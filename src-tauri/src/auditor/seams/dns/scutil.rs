//! macOS `scutil --dns` nameserver parser and runner.

#[cfg(any(target_os = "macos", test))]
use std::net::IpAddr;

#[cfg(any(target_os = "macos", test))]
use super::is_usable_nameserver;

/// Parses active reachable DNS nameservers from macOS `scutil --dns` output.
/// Global default resolvers (before `DNS configuration (for scoped queries)` and without a `domain :` filter)
/// come first; scoped default resolvers come second as fallback.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_scutil_dns_nameservers(output: &str) -> Vec<IpAddr> {
    let mut global_ips = Vec::new();
    let mut scoped_ips = Vec::new();
    let mut in_scoped_section = false;

    let mut cur_ips: Vec<IpAddr> = Vec::new();
    let mut has_domain = false;
    let mut not_reachable = false;
    let mut in_block = false;

    let flush = |in_block: bool,
                 has_domain: bool,
                 not_reachable: bool,
                 in_scoped: bool,
                 cur_ips: &mut Vec<IpAddr>,
                 global_ips: &mut Vec<IpAddr>,
                 scoped_ips: &mut Vec<IpAddr>| {
        if in_block && !has_domain && !not_reachable {
            let target = if in_scoped { scoped_ips } else { global_ips };
            for ip in cur_ips.drain(..) {
                if is_usable_nameserver(&ip) && !target.contains(&ip) {
                    target.push(ip);
                }
            }
        } else {
            cur_ips.clear();
        }
    };

    for raw in output.lines() {
        let line = raw.trim();
        if line.starts_with("DNS configuration (for scoped queries)") {
            flush(
                in_block,
                has_domain,
                not_reachable,
                in_scoped_section,
                &mut cur_ips,
                &mut global_ips,
                &mut scoped_ips,
            );
            in_block = false;
            has_domain = false;
            not_reachable = false;
            in_scoped_section = true;
            continue;
        }
        if line.starts_with("resolver #") {
            flush(
                in_block,
                has_domain,
                not_reachable,
                in_scoped_section,
                &mut cur_ips,
                &mut global_ips,
                &mut scoped_ips,
            );
            in_block = true;
            has_domain = false;
            not_reachable = false;
            continue;
        }
        if !in_block {
            continue;
        }
        if line.starts_with("domain") && line.contains(':') {
            has_domain = true;
        } else if line.starts_with("reach") && line.contains("Not Reachable") {
            not_reachable = true;
        } else if line.starts_with("nameserver[")
            && let Some((_, val)) = line.split_once(':')
            && let Ok(ip) = val.trim().parse::<IpAddr>()
        {
            cur_ips.push(ip);
        }
    }
    flush(
        in_block,
        has_domain,
        not_reachable,
        in_scoped_section,
        &mut cur_ips,
        &mut global_ips,
        &mut scoped_ips,
    );

    // Never mix scoped per-interface LAN resolvers with an active global VPN resolver:
    // racing them concurrently could make a local router answer before the VPN DNS.
    if !global_ips.is_empty() {
        global_ips
    } else {
        scoped_ips
    }
}

#[cfg(target_os = "macos")]
pub(super) async fn macos_scutil_nameservers() -> Vec<IpAddr> {
    tokio::task::spawn_blocking(|| {
        let out = crate::sysproxy::silent_command("scutil")
            .arg("--dns")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(parse_scutil_dns_nameservers(&String::from_utf8_lossy(
            &out.stdout,
        )))
    })
    .await
    .ok()
    .flatten()
    .unwrap_or_default()
}
