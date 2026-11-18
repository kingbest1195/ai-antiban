use super::types::{Os, RealProbe, SystemProbe};

/// Asynchronously resolves process name owning `peer_port`.
pub async fn lookup_process_name_by_port(port: u16) -> Option<String> {
    tokio::task::spawn_blocking(move || lookup_process_name_by_port_sync(port))
        .await
        .ok()
        .flatten()
}

/// Synchronous OS-level process resolution for an established TCP port.
pub fn lookup_process_name_by_port_sync(port: u16) -> Option<String> {
    lookup_process_with(&RealProbe, Os::current(), port, std::process::id())
}

/// Resolves the process that owns `port` using `probe` (`lsof` on macOS, `netstat` + `tasklist`
/// on Windows, `ss` on Linux). `my_pid` (the gateway itself) is never returned.
pub fn lookup_process_with(
    probe: &dyn SystemProbe,
    os: Os,
    port: u16,
    my_pid: u32,
) -> Option<String> {
    match os {
        Os::Macos => {
            let filter = format!("-iTCP:{port}");
            let text = probe.run("lsof", &["-nP", "+c", "0", "-Fpcn", &filter])?;
            parse_lsof_owner(&text, my_pid)
        }
        Os::Windows => {
            let text = probe.run("netstat", &["-ano", "-p", "tcp"])?;
            let pid = parse_netstat_pid(&text, port, my_pid)?;
            let filter = format!("PID eq {pid}");
            let tasks = probe.run("tasklist", &["/FI", &filter, "/FO", "CSV", "/NH"])?;
            parse_tasklist_name(&tasks)
        }
        Os::Linux => {
            let text = probe.run("ss", &["-t", "-p", "-H"])?;
            parse_ss_owner(&text, port, my_pid)
        }
    }
}

fn unescape_lsof(s: &str) -> String {
    s.replace("\\x20", " ")
}

/// `lsof -Fpcn` output -> first command that is not the gateway itself.
pub fn parse_lsof_owner(text: &str, my_pid: u32) -> Option<String> {
    let mut current_pid: Option<u32> = None;
    let mut current_cmd: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('p') {
            current_pid = rest.trim().parse::<u32>().ok();
            current_cmd = None;
        } else if let Some(rest) = line.strip_prefix('c') {
            current_cmd = Some(unescape_lsof(rest.trim()));
        } else if line.starts_with('n')
            && let Some(cmd) = &current_cmd
        {
            let own =
                cmd.eq_ignore_ascii_case("zastava") || cmd.eq_ignore_ascii_case("zastava_lib");
            if current_pid != Some(my_pid) && !own && !cmd.is_empty() {
                return Some(cmd.clone());
            }
        }
    }
    None
}

/// Port of `host:port` / `[::1]:port`.
fn addr_port(addr: &str) -> Option<u16> {
    addr.rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
}

/// `netstat -ano -p tcp` -> PID of the process on `port`. The port must match exactly
/// (8899 is not 18899 / 88990); the gateway's own rows and PID 0 are skipped.
pub fn parse_netstat_pid(text: &str, port: u16, my_pid: u32) -> Option<u32> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 || !parts[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        let local = addr_port(parts[1]);
        let remote = addr_port(parts[2]);
        if local != Some(port) && remote != Some(port) {
            continue;
        }
        if let Ok(pid) = parts[parts.len() - 1].parse::<u32>()
            && pid != my_pid
            && pid != 0
        {
            return Some(pid);
        }
    }
    None
}

/// `tasklist /FO CSV /NH` -> image name.
pub fn parse_tasklist_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let clean = line.trim();
        if clean.starts_with('"') {
            let name = clean.trim_start_matches('"').split('"').next()?;
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// `ss -t -p -H` -> process name of the socket on `port` (exact port, not the gateway itself).
pub fn parse_ss_owner(text: &str, port: u16, my_pid: u32) -> Option<String> {
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let (local, peer) = (addr_port(parts[3]), addr_port(parts[4]));
        if local != Some(port) && peer != Some(port) {
            continue;
        }
        let Some(after) = line.split("users:((\"").nth(1) else {
            continue;
        };
        let Some(name) = after.split('"').next() else {
            continue;
        };
        let pid = after
            .split("pid=")
            .nth(1)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|p| p.parse::<u32>().ok());
        if pid == Some(my_pid) || name.is_empty() {
            continue;
        }
        return Some(name.to_string());
    }
    None
}
