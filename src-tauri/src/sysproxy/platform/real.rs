//! `RealPlatform` implementation and OS command / dry-run gates.

use super::{
    ChainState, EffectiveProxy, PResult, PacState, Platform, PlatformError, RegKind, RegValue,
    ServiceId, VpnConnection,
    diagnostics::{clear_last_os_error, set_last_os_error},
    dns,
    macos::{
        BYPASS_EMPTY_ARG, clear_pac_url, is_admin_auth_error, parse_autoproxy,
        parse_bypass_domains, parse_nc_list, parse_scutil_proxy, parse_service_order,
        parse_webproxy,
    },
    windows::{
        ENV_SUBKEY, INET_SUBKEY, registry_delete, registry_get, registry_names, registry_set_sz,
        registry_set_value,
    },
};
use std::path::Path;

/// Checks the process-wide OS dry-run switch at the entry of every real call.
/// Returns `Err(DryRun)` (and counts the blocked call) when OS effects are off.
pub(super) fn dry_run_gate(what: &str) -> PResult<()> {
    if crate::sysproxy::os_effects_enabled() {
        Ok(())
    } else {
        crate::sysproxy::note_dry_run_blocked(what);
        Err(PlatformError::DryRun)
    }
}

/// Like [`dry_run_gate`] for writes: dry-run is a counted no-op that reports success.
pub(super) fn write_gate(what: &str) -> PResult<bool> {
    match dry_run_gate(what) {
        Ok(()) => Ok(true),
        Err(PlatformError::DryRun) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Runs a program through [`crate::sysproxy::silent_command`], capturing exit status, stdout and stderr.
pub(super) fn run_detailed(
    program: &'static str,
    args: &[&str],
    op: &'static str,
) -> PResult<(bool, Option<i32>, String, String)> {
    let out = crate::sysproxy::silent_command(program)
        .args(args)
        .output()
        .map_err(|e| {
            crate::diagnostics::record(
                "sysproxy",
                &format!("{op}: failed to spawn {program}: {}", e.kind()),
            );
            PlatformError::Failed(op)
        })?;
    Ok((
        out.status.success(),
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Runs a program through [`crate::sysproxy::silent_command`], capturing stdout and stderr.
fn run(program: &'static str, args: &[&str], op: &'static str) -> PResult<(bool, String, String)> {
    let (ok, _code, stdout, stderr) = run_detailed(program, args, op)?;
    Ok((ok, stdout, stderr))
}

/// Runs `program` and returns stdout on success, or logs non-empty stderr/stdout to diagnostics
/// and maps macOS authorization failures to [`PlatformError::AdminAuthRequired`].
pub(super) fn run_stdout(program: &'static str, args: &[&str], op: &'static str) -> PResult<String> {
    match run_detailed(program, args, op)? {
        (true, _, stdout, _) => {
            clear_last_os_error();
            Ok(stdout)
        }
        (false, code, stdout, stderr) => {
            let err_trimmed = stderr.trim();
            let out_trimmed = stdout.trim();
            let subcmd = args.first().copied().unwrap_or("");
            let summary = format!(
                "{op}: {program} {subcmd} failed (code={code:?}) stderr={err_trimmed} stdout={out_trimmed}"
            );
            crate::diagnostics::record("sysproxy", &summary);
            set_last_os_error(Some(summary));
            if is_admin_auth_error(&stdout, &stderr) {
                Err(PlatformError::AdminAuthRequired(op))
            } else {
                Err(PlatformError::Failed(op))
            }
        }
    }
}

pub(super) fn run_ok(program: &'static str, args: &[&str], op: &'static str) -> PResult<()> {
    run_stdout(program, args, op).map(|_| ())
}

/// The production implementation. Used only from non-test code in `sysproxy`.
pub struct RealPlatform;

impl RealPlatform {
    fn require_macos(op: &'static str) -> PResult<()> {
        if cfg!(target_os = "macos") {
            Ok(())
        } else {
            Err(PlatformError::Unsupported(op))
        }
    }
    fn require_windows(op: &'static str) -> PResult<()> {
        if cfg!(target_os = "windows") {
            Ok(())
        } else {
            Err(PlatformError::Unsupported(op))
        }
    }

    /// Resolves the *current* display name of a service by its stable key (handles renames).
    fn current_name(&self, svc: &ServiceId, op: &'static str) -> PResult<String> {
        self.list_services()?
            .into_iter()
            .find(|s| s.key() == svc.key())
            .map(|s| s.name)
            .ok_or(PlatformError::NotFound(op))
    }
}

impl Platform for RealPlatform {
    fn list_services(&self) -> PResult<Vec<ServiceId>> {
        Self::require_macos("list_services")?;
        dry_run_gate("networksetup:listnetworkserviceorder")?;
        let text = run_stdout(
            "networksetup",
            &["-listnetworkserviceorder"],
            "list_services",
        )?;
        Ok(parse_service_order(&text))
    }

    fn get_pac(&self, svc: &ServiceId) -> PResult<PacState> {
        Self::require_macos("get_pac")?;
        dry_run_gate("networksetup:getautoproxyurl")?;
        let name = self.current_name(svc, "get_pac")?;
        let text = run_stdout("networksetup", &["-getautoproxyurl", &name], "get_pac")?;
        Ok(parse_autoproxy(&text))
    }

    fn set_pac(&self, svc: &ServiceId, pac: &PacState) -> PResult<()> {
        Self::require_macos("set_pac")?;
        if !write_gate("networksetup:setautoproxy")? {
            return Ok(());
        }
        let name = self.current_name(svc, "set_pac")?;
        let set_state = |on: bool| {
            run_ok(
                "networksetup",
                &["-setautoproxystate", &name, if on { "on" } else { "off" }],
                "set_pac",
            )
        };
        // Switching on: the URL first, then the flag. Switching off: the flag first, so the
        // service never holds an enabled PAC without an address.
        if pac.enabled == Some(false) {
            set_state(false)?;
        }
        match pac.url.as_deref() {
            Some("") => clear_pac_url(&name)?,
            Some(url) => run_ok("networksetup", &["-setautoproxyurl", &name, url], "set_pac")?,
            None => {}
        }
        if pac.enabled == Some(true) {
            set_state(true)?;
        }
        Ok(())
    }

    fn get_chain(&self, svc: &ServiceId) -> PResult<ChainState> {
        Self::require_macos("get_chain")?;
        dry_run_gate("networksetup:getwebproxy")?;
        let name = self.current_name(svc, "get_chain")?;
        let web = run_stdout("networksetup", &["-getwebproxy", &name], "get_chain")?;
        let sec = run_stdout("networksetup", &["-getsecurewebproxy", &name], "get_chain")?;
        Ok(ChainState {
            http: parse_webproxy(&web),
            https: parse_webproxy(&sec),
        })
    }

    fn set_chain(&self, svc: &ServiceId, chain: &ChainState) -> PResult<()> {
        Self::require_macos("set_chain")?;
        if !write_gate("networksetup:setwebproxy")? {
            return Ok(());
        }
        let name = self.current_name(svc, "set_chain")?;
        for (ep, set, get, state) in [
            (
                &chain.http,
                "-setwebproxy",
                "-getwebproxy",
                "-setwebproxystate",
            ),
            (
                &chain.https,
                "-setsecurewebproxy",
                "-getsecurewebproxy",
                "-setsecurewebproxystate",
            ),
        ] {
            if let (Some(host), Some(port)) = (&ep.server, ep.port) {
                // `-setwebproxy` also switches the proxy on and resets its authentication, so it
                // runs only when the address really differs from what the service holds now.
                let (ok, text, _) = run("networksetup", &[get, &name], "set_chain")?;
                let same = ok && {
                    let cur = parse_webproxy(&text);
                    cur.server.as_deref() == Some(host.as_str()) && cur.port == Some(port)
                };
                if !same {
                    run_ok(
                        "networksetup",
                        &[set, &name, host, &port.to_string()],
                        "set_chain",
                    )?;
                }
            }
            if let Some(on) = ep.enabled {
                run_ok(
                    "networksetup",
                    &[state, &name, if on { "on" } else { "off" }],
                    "set_chain",
                )?;
            }
        }
        Ok(())
    }

    fn get_proxy_bypass_domains(&self, svc: &ServiceId) -> PResult<Vec<String>> {
        Self::require_macos("get_proxy_bypass_domains")?;
        dry_run_gate("networksetup:getproxybypassdomains")?;
        let name = self.current_name(svc, "get_proxy_bypass_domains")?;
        let text = run_stdout(
            "networksetup",
            &["-getproxybypassdomains", &name],
            "get_proxy_bypass_domains",
        )?;
        Ok(parse_bypass_domains(&text))
    }

    fn set_proxy_bypass_domains(&self, svc: &ServiceId, domains: &[String]) -> PResult<()> {
        Self::require_macos("set_proxy_bypass_domains")?;
        if !write_gate("networksetup:setproxybypassdomains")? {
            return Ok(());
        }
        if self.get_proxy_bypass_domains(svc)? == domains {
            return Ok(()); // already as wanted: no call
        }
        let name = self.current_name(svc, "set_proxy_bypass_domains")?;
        let mut args: Vec<&str> = vec!["-setproxybypassdomains", &name];
        if domains.is_empty() {
            args.push(BYPASS_EMPTY_ARG);
        } else {
            args.extend(domains.iter().map(String::as_str));
        }
        run_ok("networksetup", &args, "set_proxy_bypass_domains")
    }

    fn vpn_connections(&self) -> PResult<Vec<VpnConnection>> {
        Self::require_macos("vpn_connections")?;
        dry_run_gate("scutil:nc-list")?;
        let text = run_stdout("scutil", &["--nc", "list"], "vpn_connections")?;
        Ok(parse_nc_list(&text))
    }

    fn effective_proxy(&self) -> PResult<EffectiveProxy> {
        Self::require_macos("effective_proxy")?;
        dry_run_gate("scutil:proxy")?;
        let text = run_stdout("scutil", &["--proxy"], "effective_proxy")?;
        Ok(parse_scutil_proxy(&text))
    }

    fn temp_dns_overrides(&self) -> PResult<bool> {
        dns::temp_dns_overrides(self)
    }

    fn get_user_env(&self, key: &str) -> PResult<Option<String>> {
        dry_run_gate("user_env:get")?;
        if cfg!(target_os = "macos") {
            let text = run_stdout("launchctl", &["getenv", key], "get_user_env")?;
            // launchctl prints nothing for an unset variable; "set to empty" is indistinguishable.
            let v = text.trim_end_matches('\n');
            Ok(if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            })
        } else if cfg!(target_os = "windows") {
            match registry_get(ENV_SUBKEY, key, "get_user_env")? {
                None => Ok(None),
                Some(RegValue {
                    kind: RegKind::Sz,
                    data,
                }) => Ok(Some(data)),
                // Expand/DWORD values cannot be restored byte-exact through this API.
                Some(_) => Err(PlatformError::Unsupported("get_user_env")),
            }
        } else {
            Err(PlatformError::Unsupported("get_user_env"))
        }
    }

    fn set_user_env(&self, key: &str, value: &str) -> PResult<()> {
        if !write_gate("user_env:set")? {
            return Ok(());
        }
        if cfg!(target_os = "macos") {
            run_ok("launchctl", &["setenv", key, value], "set_user_env")
        } else if cfg!(target_os = "windows") {
            registry_set_sz(ENV_SUBKEY, key, value, "set_user_env")
        } else {
            Err(PlatformError::Unsupported("set_user_env"))
        }
    }

    fn unset_user_env(&self, key: &str) -> PResult<()> {
        if !write_gate("user_env:unset")? {
            return Ok(());
        }
        if cfg!(target_os = "macos") {
            run_ok("launchctl", &["unsetenv", key], "unset_user_env")
        } else if cfg!(target_os = "windows") {
            if self.get_user_env(key)?.is_none() {
                return Ok(());
            }
            registry_delete(ENV_SUBKEY, key, "unset_user_env")
        } else {
            Err(PlatformError::Unsupported("unset_user_env"))
        }
    }

    fn list_user_env_names(&self) -> PResult<Vec<String>> {
        Self::require_windows("list_user_env_names")?;
        dry_run_gate("reg:query-env")?;
        registry_names(ENV_SUBKEY, "list_user_env_names")
    }

    fn get_inet(&self, name: &str) -> PResult<Option<RegValue>> {
        Self::require_windows("get_inet")?;
        dry_run_gate("reg:query")?;
        registry_get(INET_SUBKEY, name, "get_inet")
    }

    fn set_inet(&self, name: &str, value: &RegValue) -> PResult<()> {
        Self::require_windows("set_inet")?;
        if !write_gate("reg:add")? {
            return Ok(());
        }
        registry_set_value(INET_SUBKEY, name, value, "set_inet")
    }

    fn delete_inet(&self, name: &str) -> PResult<()> {
        Self::require_windows("delete_inet")?;
        if !write_gate("reg:delete")? {
            return Ok(());
        }
        if self.get_inet(name)?.is_none() {
            return Ok(());
        }
        registry_delete(INET_SUBKEY, name, "delete_inet")
    }

    fn notify_inet_refresh(&self) -> PResult<()> {
        Self::require_windows("notify_inet_refresh")?;
        if !write_gate("InternetSetOptionW")? {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            super::windows::ffi::inet_refresh();
        }
        Ok(())
    }

    fn broadcast_env_change(&self) -> PResult<()> {
        Self::require_windows("broadcast_env_change")?;
        if !write_gate("SendMessageTimeoutW")? {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            super::windows::ffi::env_broadcast();
        }
        Ok(())
    }

    fn exclude_from_backup(&self, path: &Path) -> PResult<()> {
        if !cfg!(target_os = "macos") {
            return Ok(());
        }
        if !write_gate("tmutil:addexclusion")? {
            return Ok(());
        }
        let p = path.to_string_lossy();
        run_ok("tmutil", &["addexclusion", &p], "exclude_from_backup")
    }
}
