use super::catalog::get_known_app_info;
use super::cli_scanners::{check_app_installed_in, cli_fact};
use super::ide_scanners::{
    AntigravityKind, antigravity_app_fact, antigravity_kind, ide_folders, ide_verdict,
    jetbrains_fact,
};
use super::types::{
    AppFact, ConfigFacts, CoverageEnv, CoverageStatus, KNOWN_IDS, Os, PacSource, SystemProbe,
    Verdict, pac_url_for, steps, steps_of,
};
use crate::state::CliMode;
use crate::sysproxy::browser_policies::detect_browser_pac_status_with;
use crate::sysproxy::platform::{Platform, PlatformError, ServiceKind, classify_services};
use std::collections::HashMap;
use std::net::SocketAddr;

pub(super) fn identify_by_user_agent(ua: &str) -> Option<&'static str> {
    let ua_lower = ua.to_lowercase();
    if ua_lower.starts_with("curl/") {
        return Some("curl");
    }
    if ua_lower.contains("claude-code") || ua_lower.contains("claude_code") {
        return Some("claude-code");
    }
    if ua_lower.contains("python-requests") || ua_lower.contains("aiohttp") {
        return Some("python");
    }
    if ua_lower.contains("node-fetch") || ua_lower.contains("undici") {
        return Some("node");
    }
    None
}

pub(super) fn compute_config_facts(
    env: &CoverageEnv<'_>,
    gateway: Option<SocketAddr>,
    cli_mode: CliMode,
    os: Os,
    probe: &dyn SystemProbe,
) -> ConfigFacts {
    let pac_url = gateway.map(pac_url_for);
    let browser_pac = detect_browser_pac_status_with(
        env.files,
        os,
        probe,
        pac_url.as_deref(),
        env.policy_store,
        env.platform,
    );
    let browser_pac_policy_active = !browser_pac.browsers_pac_active.is_empty();

    let mut facts = ConfigFacts {
        gateway,
        apps: HashMap::new(),
        system_proxy_effective: None,
        vpn_connected: Vec::new(),
        browser_pac_policy_active,
        browsers_needing_restart: browser_pac.browsers_needing_restart.clone(),
        browsers_pac_active: browser_pac.browsers_pac_active.clone(),
    };

    // One PAC read serves browsers and desktop apps.
    let pac_verdict = match pac_url.as_deref() {
        Some(u) => read_os_pac(env.platform, env.pac_source, u),
        None => Verdict::Unknown,
    };

    let mut temp_dns_active = false;
    if env.pac_source == PacSource::Services {
        let (vpn_names, temp_dns) = detect_macos_vpn_state(env.platform);
        facts.vpn_connected = vpn_names;
        temp_dns_active = temp_dns;
        facts.system_proxy_effective = gateway.and_then(|g| read_effective_pac(env.platform, g));
    }

    for id in KNOWN_IDS {
        let Some(info) = get_known_app_info(id) else {
            continue;
        };
        let installed = match env.files {
            Some(ctx) => check_app_installed_in(id, ctx),
            None => matches!(id, "browsers" | "curl"),
        };
        if !installed {
            facts.apps.insert(
                id,
                AppFact {
                    installed: false,
                    status: CoverageStatus::NotInstalled,
                    manual_steps: Vec::new(),
                    detail: "Не установлено".to_string(),
                    watch_bypass: false,
                },
            );
            continue;
        }

        // Antigravity 2.x has no editor `User/settings.json`: the settings model does not apply.
        let desktop_antigravity = id == "antigravity"
            && env
                .files
                .and_then(antigravity_kind)
                .is_some_and(|k| k != AntigravityKind::Editor);

        let (status, manual_steps, detail) = match info.category {
            "browser" | "desktop" => {
                if info.category == "browser" && browser_pac_policy_active {
                    let detail = if !facts.browsers_needing_restart.is_empty() {
                        format!(
                            "PAC активен ({}); нужен перезапуск: {}",
                            facts.browsers_pac_active.join(", "),
                            facts.browsers_needing_restart.join(", ")
                        )
                    } else if facts.system_proxy_effective == Some(false)
                        || pac_verdict != Verdict::Configured
                    {
                        if os == Os::Windows {
                            "Политики браузеров направляют трафик в Заставу поверх VPN".to_string()
                        } else {
                            "Настройки браузеров (Preferences) направляют трафик в Заставу поверх VPN"
                                .to_string()
                        }
                    } else {
                        "Настройки браузеров и системный PAC направляют трафик в Заставу, ждём первый запрос"
                            .to_string()
                    };
                    (CoverageStatus::Configured, Vec::new(), detail)
                } else if info.category == "browser"
                    && !facts.browsers_needing_restart.is_empty()
                    && (facts.system_proxy_effective == Some(false)
                        || pac_verdict != Verdict::Configured)
                {
                    (
                        CoverageStatus::Off,
                        steps_of(&[steps::ENABLE_PROTECTION]),
                        format!(
                            "Требуется перезапуск браузеров: {}",
                            facts.browsers_needing_restart.join(", ")
                        ),
                    )
                } else {
                    match pac_verdict {
                        Verdict::Configured => (
                            CoverageStatus::Configured,
                            Vec::new(),
                            "Системный PAC указывает на Заставу, ждём первый запрос".to_string(),
                        ),
                        Verdict::Off if env.sysproxy_enabled && temp_dns_active => (
                            CoverageStatus::Off,
                            steps_of(&[steps::SET_PAC_URL]),
                            "Системный PAC отложен: активный VPN (utun) держит временные DNS — приложения без своих настроек прокси идут мимо Заставы".to_string(),
                        ),
                        Verdict::Off => (
                            CoverageStatus::Off,
                            steps_of(&[steps::ENABLE_PROTECTION]),
                            "Системный PAC не указывает на Заставу".to_string(),
                        ),
                        Verdict::Unknown => (
                            CoverageStatus::Unknown,
                            steps_of(&[steps::ENABLE_PROTECTION, steps::SET_PAC_URL]),
                            "Не удалось прочитать системный PAC".to_string(),
                        ),
                    }
                }
            }
            "ide" if desktop_antigravity && id == "antigravity" => antigravity_app_fact(
                env.sysproxy_enabled,
                facts.system_proxy_effective,
                pac_verdict,
            ),
            "ide" if id == "jetbrains" => {
                jetbrains_fact(env.files, gateway, env.jetbrains_xml_confirmed)
            }
            "ide" => {
                let verdict = match (env.files, gateway) {
                    (Some(ctx), Some(g)) => ide_verdict(ctx, ide_folders(id), g.port()),
                    _ => Verdict::Unknown,
                };
                match verdict {
                    Verdict::Configured => (
                        CoverageStatus::Configured,
                        Vec::new(),
                        "В settings.json http.proxy указывает на Заставу".to_string(),
                    ),
                    Verdict::Off => (
                        CoverageStatus::Off,
                        steps_of(&[steps::ENABLE_PROTECTION, steps::SET_HTTP_PROXY]),
                        "В settings.json нет http.proxy с портом Заставы".to_string(),
                    ),
                    Verdict::Unknown => (
                        CoverageStatus::Unknown,
                        steps_of(&[steps::SET_HTTP_PROXY]),
                        "Не удалось прочитать settings.json".to_string(),
                    ),
                }
            }
            "cli" => cli_fact(id, env, gateway, cli_mode),
            _ => (
                CoverageStatus::Unknown,
                Vec::new(),
                "Не удалось проверить".to_string(),
            ),
        };

        facts.apps.insert(
            id,
            AppFact {
                installed: true,
                status,
                manual_steps,
                detail,
                watch_bypass: id == "antigravity" && desktop_antigravity,
            },
        );
    }
    facts
}

pub(super) fn same_pac(a: &str, b: &str) -> bool {
    a.trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim().trim_end_matches('/'))
}

/// Names of enabled connected VPN services on macOS plus whether temporary VPN DNS is active
/// (e.g. an `utun` daemon such as AmneziaVPN not listed by `scutil --nc list`). Read-only.
fn detect_macos_vpn_state(platform: &dyn Platform) -> (Vec<String>, bool) {
    let temp_dns = matches!(platform.temp_dns_overrides(), Ok(true));
    let mut names: Vec<String> = match platform.list_services() {
        Ok(services) => {
            let enabled: Vec<_> = services.into_iter().filter(|s| s.enabled).collect();
            classify_services(platform, &enabled)
                .into_iter()
                .filter(|(_, k)| *k == ServiceKind::Vpn { connected: true })
                .map(|(s, _)| s.name)
                .collect()
        }
        Err(_) => Vec::new(),
    };
    if names.is_empty() && temp_dns {
        names.push("активный туннель (временные DNS)".to_string());
    }
    (names, temp_dns)
}

/// `scutil --proxy` against our PAC: the proxy the system really applies, which follows the
/// primary service (so a VPN that took over shows up here although Wi-Fi carries our PAC).
/// `None` when it cannot be read.
fn read_effective_pac(platform: &dyn Platform, gateway: SocketAddr) -> Option<bool> {
    let eff = platform.effective_proxy().ok()?;
    Some(
        eff.pac_enabled == Some(true)
            && eff
                .pac_url
                .as_deref()
                .is_some_and(|u| same_pac(u, &pac_url_for(gateway))),
    )
}

/// Reads the PAC the OS hands out and compares it with ours. A failed read is `Unknown`,
/// never `Configured`.
fn read_os_pac(platform: &dyn Platform, source: PacSource, ours: &str) -> Verdict {
    match source {
        PacSource::Inet => match platform.get_inet("AutoConfigURL") {
            Ok(Some(v)) if same_pac(&v.data, ours) => Verdict::Configured,
            Ok(_) => Verdict::Off,
            Err(_) => Verdict::Unknown,
        },
        PacSource::Services => {
            let services = match platform.list_services() {
                Ok(s) => s,
                Err(_) => return Verdict::Unknown,
            };
            let mut readable = 0usize;
            let mut failed = 0usize;
            let enabled: Vec<_> = services.into_iter().filter(|s| s.enabled).collect();
            // A PAC in a VPN service is not Zastava's (it never writes there): not a verdict.
            for (svc, kind) in classify_services(platform, &enabled) {
                if !kind.is_physical() {
                    continue;
                }
                let svc = &svc;
                match platform.get_pac(svc) {
                    Ok(st) => {
                        readable += 1;
                        if st.enabled == Some(true)
                            && st.url.as_deref().is_some_and(|u| same_pac(u, ours))
                        {
                            return Verdict::Configured;
                        }
                    }
                    Err(PlatformError::NotFound(_)) => {}
                    Err(_) => failed += 1,
                }
            }
            if failed > 0 || readable == 0 {
                Verdict::Unknown
            } else {
                Verdict::Off
            }
        }
    }
}
