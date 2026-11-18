//! macOS `scutil` / `networksetup` DNS override parsing and inspection.

use super::{
    PResult, Platform, PlatformError, ServiceId,
    macos::classify_service,
    real::{dry_run_gate, run_stdout},
};

/// Parsed `scutil` dictionary of `Setup:/Network/Service/<id>/DNS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDict {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
    /// An unrecognised key other than `ServerAddresses` / `SearchDomains` / benign metadata was present.
    pub unknown_fields: bool,
}

fn is_benign_scutil_dns_key(key: &str) -> bool {
    matches!(
        key,
        "DomainName" | "ConfirmedServiceID" | "InterfaceName" | "SupplementalMatchDomains"
    ) || key.starts_with('_')
}

/// Parses `scutil` `show` output. Key order inside the dictionary does not matter.
/// Tolerates benign metadata keys (`DomainName`, `ConfirmedServiceID`, `InterfaceName`,
/// `SupplementalMatchDomains`, and `_`-prefixed keys).
pub fn parse_scutil_dns(output: &str) -> DnsDict {
    let mut d = DnsDict {
        servers: vec![],
        search_domains: vec![],
        unknown_fields: false,
    };
    let mut current: Option<&'static str> = None;
    let mut sub_depth: usize = 0;
    for line in output.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with("<dictionary>") {
            continue;
        }
        if t == "}" {
            if sub_depth > 0 {
                sub_depth -= 1;
                if sub_depth == 0 {
                    current = None;
                }
            }
            continue;
        }
        if sub_depth > 0 {
            if t.ends_with('{') {
                sub_depth += 1;
                continue;
            }
            if sub_depth == 1
                && let Some((k, v)) = t.split_once(" : ")
            {
                let k = k.trim();
                let v = v.trim();
                if k.chars().all(|c| c.is_ascii_digit()) {
                    match current {
                        Some("servers") => d.servers.push(v.to_string()),
                        Some("domains") => d.search_domains.push(v.to_string()),
                        Some("ignored") | Some("unknown") => {}
                        _ => d.unknown_fields = true,
                    }
                } else if !matches!(current, Some("ignored") | Some("unknown")) {
                    d.unknown_fields = true;
                }
            }
            continue;
        }
        if let Some((k, v)) = t.split_once(" : ") {
            let k = k.trim();
            let v = v.trim();
            if v.starts_with("<array>") && v.ends_with('{') {
                current = match k {
                    "ServerAddresses" => Some("servers"),
                    "SearchDomains" => Some("domains"),
                    _ if is_benign_scutil_dns_key(k) => Some("ignored"),
                    _ => {
                        d.unknown_fields = true;
                        Some("unknown")
                    }
                };
                sub_depth = 1;
            } else if is_benign_scutil_dns_key(k) {
                if v.ends_with('{') {
                    current = Some("ignored");
                    sub_depth = 1;
                }
            } else {
                d.unknown_fields = true;
                if v.ends_with('{') {
                    current = Some("unknown");
                    sub_depth = 1;
                }
            }
        }
    }
    d
}

/// `networksetup -getdnsservers` -> addresses (empty when none are set).
pub fn parse_getdnsservers(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("There aren't any DNS Servers"))
        .map(str::to_string)
        .collect()
}

/// `networksetup -getsearchdomains` -> domains (empty when none are set).
pub fn parse_getsearchdomains(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("There aren't any Search Domains"))
        .map(str::to_string)
        .collect()
}

/// Service IDs from `scutil`'s `list State:/Network/Service/[^/]+/IPv[46]` that currently carry an
/// active IPv4 or IPv6 state in `SCDynamicStore`. Disconnected or unplugged adapters without live IP
/// state do not appear here even if stale `Setup:/Network/Service/*/DNS` entries remain.
pub fn extract_active_service_ids(listing: &str) -> std::collections::HashSet<String> {
    listing
        .lines()
        .filter_map(|line| {
            let key = line.split(" = ").nth(1)?.trim();
            let rest = key.strip_prefix("State:/Network/Service/")?;
            let (id, proto) = rest.split_once('/')?;
            (matches!(proto, "IPv4" | "IPv6") && !id.is_empty()).then(|| id.to_string())
        })
        .collect()
}

/// One `Setup:/Network/Service/<id>/DNS` entry paired with its `UserDefinedName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupDnsEntry {
    pub service_id: String,
    pub user_defined_name: Option<String>,
    pub dns: DnsDict,
}

fn eval_physical_temp_dns_override<F>(
    physical_services: &[ServiceId],
    entries: &[SetupDnsEntry],
    active_service_ids: Option<&std::collections::HashSet<String>>,
    mut read_saved_dns: F,
) -> PResult<bool>
where
    F: FnMut(&str) -> PResult<(Vec<String>, Vec<String>)>,
{
    if physical_services.is_empty() {
        return Ok(false);
    }
    for entry in entries {
        let Some(name) = entry.user_defined_name.as_deref() else {
            continue;
        };
        if !physical_services.iter().any(|s| s.name == name) {
            continue;
        }
        if let Some(active_ids) = active_service_ids
            && !active_ids.contains(&entry.service_id)
        {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!(
                    "temp_dns ignored inactive service={name} (id={}): no State:/.../IPv4|IPv6",
                    entry.service_id
                ),
            );
            continue;
        }
        if entry.dns.unknown_fields {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!(
                    "temp_dns triggered by service={name}: unknown fields in Setup:/Network/Service/*/DNS"
                ),
            );
            return Ok(true);
        }
        let (mut saved_servers, mut saved_domains) = read_saved_dns(name)?;
        let mut live_servers = entry.dns.servers.clone();
        live_servers.sort();
        saved_servers.sort();
        if live_servers != saved_servers {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!(
                    "temp_dns triggered by service={name}: live_servers({}) != saved_servers({})",
                    live_servers.len(),
                    saved_servers.len()
                ),
            );
            return Ok(true);
        }
        let mut live_domains = entry.dns.search_domains.clone();
        live_domains.sort();
        saved_domains.sort();
        if live_domains != saved_domains {
            crate::diagnostics::record(
                "sysproxy:dns",
                &format!(
                    "temp_dns triggered by service={name}: live_domains({}) != saved_domains({})",
                    live_domains.len(),
                    saved_domains.len()
                ),
            );
            return Ok(true);
        }
    }
    Ok(false)
}

/// Pure evaluation of temporary DNS overrides, scoped strictly to `physical_services` (services
/// Zastava actually modifies). Synthetic/VPN service IDs not matching an enabled physical service
/// are ignored.
pub fn has_physical_temp_dns_override<F>(
    physical_services: &[ServiceId],
    entries: &[SetupDnsEntry],
    read_saved_dns: F,
) -> PResult<bool>
where
    F: FnMut(&str) -> PResult<(Vec<String>, Vec<String>)>,
{
    eval_physical_temp_dns_override(physical_services, entries, None, read_saved_dns)
}

/// Same check as [`has_physical_temp_dns_override`], ignoring physical services that have no live
/// `State:/Network/Service/<id>/IPv4|IPv6` entry (e.g. unplugged or inactive secondary adapters
/// carrying stale `Setup:/.../DNS` records).
pub fn has_physical_temp_dns_override_active<F>(
    physical_services: &[ServiceId],
    entries: &[SetupDnsEntry],
    active_service_ids: &std::collections::HashSet<String>,
    read_saved_dns: F,
) -> PResult<bool>
where
    F: FnMut(&str) -> PResult<(Vec<String>, Vec<String>)>,
{
    eval_physical_temp_dns_override(
        physical_services,
        entries,
        Some(active_service_ids),
        read_saved_dns,
    )
}

/// macOS `temp_dns_overrides` implementation using `scutil` and `networksetup`.
pub(super) fn temp_dns_overrides(platform: &dyn Platform) -> PResult<bool> {
    use std::io::Write;
    use std::process::Stdio;
    if !cfg!(target_os = "macos") {
        return Err(PlatformError::Unsupported("temp_dns_overrides"));
    }
    dry_run_gate("scutil:dns")?;
    // Read-only scutil session over stdin.
    let scutil = |script: &str| -> PResult<String> {
        let mut child = crate::sysproxy::silent_command("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| PlatformError::Failed("temp_dns_overrides"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|_| PlatformError::Failed("temp_dns_overrides"))?;
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let services = platform.list_services()?;
    let nc = platform.vpn_connections()?;
    let physical: Vec<ServiceId> = services
        .into_iter()
        .filter(|s| s.enabled && classify_service(s, Some(&nc)).is_physical())
        .collect();
    if physical.is_empty() {
        return Ok(false);
    }
    let listing = scutil("list Setup:/Network/Service/[^/]+/DNS\nquit\n")?;
    let mut entries = Vec::new();
    for line in listing.lines() {
        // "  subKey [0] = Setup:/Network/Service/<ID>/DNS"
        let Some(key) = line.split(" = ").nth(1).map(str::trim) else {
            continue;
        };
        let Some(id) = key
            .strip_prefix("Setup:/Network/Service/")
            .and_then(|r| r.strip_suffix("/DNS"))
        else {
            continue;
        };
        let dns = parse_scutil_dns(&scutil(&format!("show {key}\nquit\n"))?);
        let svc_dump = scutil(&format!("show Setup:/Network/Service/{id}\nquit\n"))?;
        let user_defined_name = svc_dump.lines().find_map(|l| {
            l.trim()
                .strip_prefix("UserDefinedName : ")
                .map(|v| v.trim().to_string())
        });
        entries.push(SetupDnsEntry {
            service_id: id.to_string(),
            user_defined_name,
            dns,
        });
    }
    if entries.is_empty() {
        return Ok(false);
    }
    let state_listing = scutil("list State:/Network/Service/[^/]+/IPv[46]\nquit\n")?;
    let active_ids = extract_active_service_ids(&state_listing);
    has_physical_temp_dns_override_active(&physical, &entries, &active_ids, |name| {
        let saved_dns = run_stdout(
            "networksetup",
            &["-getdnsservers", name],
            "temp_dns_overrides",
        )?;
        let saved_search = run_stdout(
            "networksetup",
            &["-getsearchdomains", name],
            "temp_dns_overrides",
        )?;
        Ok((
            parse_getdnsservers(&saved_dns),
            parse_getsearchdomains(&saved_search),
        ))
    })
}
