use super::super::EnableReport;
use super::super::journal::{Journal, JournalError, Resource, Value};
use super::super::platform::{PacState, Platform, PlatformError, is_admin_auth_error};
use super::MSG_ADMIN_AUTH_REQUIRED;
use super::apply::note_changed;
use super::planner::plan_physical_pac;

pub(super) fn is_safe_pac_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"));
    let Some(rest) = rest else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    url.chars().all(|c| {
        c.is_ascii_graphic()
            && !matches!(
                c,
                '\'' | '"' | '\\' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '(' | ')' | '{' | '}'
            )
    })
}

fn validate_service_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err("Некорректное имя сетевой службы macOS.".to_string());
    }
    Ok(())
}

/// Strictly wraps an arbitrary argument for `/bin/sh` using POSIX single quoting.
pub(super) fn posix_single_quote(arg: &str) -> Result<String, String> {
    if arg.contains('\0') || arg.contains('\n') || arg.contains('\r') {
        return Err("Недопустимый управляющий символ в аргументе команды.".to_string());
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Ok(out)
}

/// Escapes `s` as a double-quoted AppleScript string literal (rejecting control breaks).
pub(super) fn applescript_string_literal(s: &str) -> Result<String, String> {
    if s.chars().any(char::is_control) {
        return Err("Недопустимый управляющий символ в скрипте AppleScript.".to_string());
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

pub(super) fn build_privileged_networksetup_script(
    p: &dyn Platform,
    items: &[(Resource, Value)],
) -> Result<String, String> {
    let current_services = p
        .list_services()
        .map_err(|_| "Не удалось получить список сетевых служб.".to_string())?;
    let mut cmds: Vec<String> = Vec::new();
    for (res, val) in items {
        let svc = match res {
            Resource::Pac { service } | Resource::Chain { service } => service,
            _ => {
                return Err("Неподдерживаемый тип ресурса для привилегированной настройки.".into());
            }
        };
        let resolved_name = current_services
            .iter()
            .find(|s| s.key() == svc.key())
            .map(|s| s.name.as_str())
            .unwrap_or(svc.name.as_str());
        validate_service_name(resolved_name)?;
        let q_name = posix_single_quote(resolved_name)?;
        match (res, val) {
            (Resource::Pac { .. }, Value::Pac(pac)) => {
                if pac.enabled == Some(false) {
                    cmds.push(format!(
                        "/usr/sbin/networksetup -setautoproxystate {q_name} off"
                    ));
                }
                match pac.url.as_deref() {
                    Some("") => {
                        cmds.push(format!(
                            "/usr/sbin/networksetup -setautoproxyurl {q_name} ''"
                        ));
                    }
                    Some(url) => {
                        if !is_safe_pac_url(url) {
                            return Err("Небезопасный адрес PAC-конфигурации.".to_string());
                        }
                        let q_url = posix_single_quote(url)?;
                        cmds.push(format!(
                            "/usr/sbin/networksetup -setautoproxyurl {q_name} {q_url}"
                        ));
                    }
                    None => {}
                }
                if pac.enabled == Some(true) {
                    cmds.push(format!(
                        "/usr/sbin/networksetup -setautoproxystate {q_name} on"
                    ));
                }
            }
            (Resource::Chain { .. }, Value::Chain(chain)) => {
                if let Some(on) = chain.http.enabled {
                    let flag = if on { "on" } else { "off" };
                    cmds.push(format!(
                        "/usr/sbin/networksetup -setwebproxystate {q_name} {flag}"
                    ));
                }
                if let Some(on) = chain.https.enabled {
                    let flag = if on { "on" } else { "off" };
                    cmds.push(format!(
                        "/usr/sbin/networksetup -setsecurewebproxystate {q_name} {flag}"
                    ));
                }
            }
            _ => {
                return Err("Несовпадение ресурса и значения при настройке прокси.".into());
            }
        }
    }
    Ok(cmds.join(" && "))
}

pub(super) fn build_osascript_arg(shell_script: &str) -> Result<String, String> {
    Ok(format!(
        "do shell script {} with administrator privileges",
        applescript_string_literal(shell_script)?
    ))
}

fn run_privileged_osascript(shell_script: &str) -> Result<(), JournalError> {
    if shell_script.is_empty() {
        return Ok(());
    }
    if !super::super::os_effects_enabled() {
        return Ok(());
    }
    let osa_arg = build_osascript_arg(shell_script)
        .map_err(|_| JournalError::Platform(PlatformError::Failed("osascript")))?;
    let out = super::super::silent_command("osascript")
        .args(["-e", &osa_arg])
        .output()
        .map_err(|_| JournalError::Platform(PlatformError::Failed("osascript")))?;
    if out.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let err_trimmed = stderr.trim();
    crate::diagnostics::record(
        "sysproxy:osascript",
        &format!(
            "osascript failed (code={:?}): stderr={} stdout={}",
            out.status.code(),
            err_trimmed,
            stdout.trim()
        ),
    );
    if is_admin_auth_error(&stdout, &stderr) {
        Err(JournalError::Platform(PlatformError::AdminAuthRequired(
            "osascript",
        )))
    } else {
        Err(JournalError::Platform(PlatformError::Failed("osascript")))
    }
}

/// Applies PAC (and disables chained upstream explicit proxies) in one elevated `osascript`
/// session, recording every baseline and applied state in the ownership journal.
pub(crate) fn enable_pac_privileged(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    enable_pac_privileged_with(j, p, pac_url, run_privileged_osascript)
}

pub(super) fn enable_pac_privileged_with<F>(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    exec_shell: F,
) -> Result<EnableReport, String>
where
    F: FnOnce(&str) -> Result<(), JournalError>,
{
    if !is_safe_pac_url(pac_url) {
        return Err("Небезопасный адрес PAC-конфигурации.".to_string());
    }
    let planned = plan_physical_pac(p, pac_url, None)?;
    if planned.plans.is_empty() {
        return Ok(EnableReport {
            skipped_vpn: planned.vpn_untouched,
            os_pac_deferred: planned.os_pac_deferred,
            ..EnableReport::default()
        });
    }
    let want_pac = Value::Pac(PacState {
        url: Some(pac_url.to_string()),
        enabled: Some(true),
    });

    // Record existing bypass lists in the journal before turning off upstream explicit proxies.
    // Since each value equals what the OS already holds, `RealPlatform::set_proxy_bypass_domains`
    // performs no OS write, avoiding a separate unprivileged authorization failure.
    let mut batch: Vec<(Resource, Value)> = Vec::new();
    for plan in &planned.plans {
        batch.push((
            Resource::Pac {
                service: plan.svc.clone(),
            },
            want_pac.clone(),
        ));
        if let Some(u) = &plan.upstream {
            let bypass_res = Resource::Bypass {
                service: plan.svc.clone(),
            };
            match p.get_proxy_bypass_domains(&plan.svc) {
                Ok(list) => {
                    if let Err(e) = j.apply(p, &bypass_res, Value::Bypass(list)) {
                        eprintln!("Застава: {} не записан: {e}", bypass_res.id());
                    }
                }
                Err(_) => eprintln!("Застава: {} не прочитан", bypass_res.id()),
            }
            batch.push((
                Resource::Chain {
                    service: plan.svc.clone(),
                },
                Value::Chain(u.chain_off.clone()),
            ));
        }
    }

    let outcomes = j
        .apply_batch(p, batch, |items| {
            let script = build_privileged_networksetup_script(p, items)
                .map_err(|_| JournalError::Platform(PlatformError::Failed("osascript")))?;
            exec_shell(&script)
        })
        .map_err(|e| match e {
            JournalError::Platform(PlatformError::AdminAuthRequired(_)) => {
                MSG_ADMIN_AUTH_REQUIRED.to_string()
            }
            other => format!("Не удалось включить защиту с правами администратора: {other}"),
        })?;

    let mut report = EnableReport {
        skipped_vpn: planned.vpn_untouched,
        os_pac_deferred: planned.os_pac_deferred,
        ..EnableReport::default()
    };
    for (res, outcome) in outcomes {
        note_changed(outcome, &mut report.changed);
        if let Resource::Pac { service } = res {
            report.configured.push(service.name);
        }
    }
    Ok(report)
}
