//! Replaceable sources of the checks: DNS lookups, the HTTP probe and everything that reads the host.
//!
//! The audit never talks to the network or starts a process directly: it goes through these
//! traits, so a test can substitute a fake and run without network and without child processes.

use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ---------------------------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------------------------

/// Raw outcome of one name lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// The name resolved to these addresses (never empty).
    Addrs(Vec<IpAddr>),
    /// The resolver answered "no such name / no address" (NXDOMAIN or an empty answer).
    NotFound,
    /// No answer within the time limit.
    Timeout,
    /// Any other failure (resolver unreachable, SERVFAIL, socket error...).
    Failed,
}

/// Raw outcome of one TXT lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxtOutcome {
    /// The name has these TXT records (one string per record, character-strings joined).
    Records(Vec<String>),
    /// The resolver answered "no such name / no TXT record".
    NotFound,
    /// No answer within the time limit.
    Timeout,
    /// Any other failure (no resolver configured, SERVFAIL, socket error...).
    Failed,
    /// This source cannot do TXT lookups on this system.
    Unsupported,
}

/// Resolves a host name to addresses.
pub trait DnsLookup: Send + Sync {
    fn lookup<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome>;

    /// TXT records of `host` (asked from the resolver configured in the OS).
    fn lookup_txt<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        let _ = (host, limit);
        Box::pin(async { TxtOutcome::Unsupported })
    }
}

/// The operating system resolver (`getaddrinfo`).
pub struct SystemDns;

impl DnsLookup for SystemDns {
    fn lookup<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            match tokio::time::timeout(limit, tokio::net::lookup_host((host, 80u16))).await {
                Err(_) => LookupOutcome::Timeout,
                Ok(Ok(addrs)) => {
                    let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    if ips.is_empty() {
                        LookupOutcome::NotFound
                    } else {
                        LookupOutcome::Addrs(ips)
                    }
                }
                Ok(Err(e)) if is_name_not_found(&e) => LookupOutcome::NotFound,
                Ok(Err(_)) => LookupOutcome::Failed,
            }
        })
    }

    fn lookup_txt<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        Box::pin(async move {
            tokio::time::timeout(limit, system_txt_lookup(host, limit))
                .await
                .unwrap_or(TxtOutcome::Timeout)
        })
    }
}

/// One TXT query through the resolvers of the OS configuration (scutil / registry / resolv.conf),
/// without cache and without search domains: a fresh answer of the very resolver in use.
async fn system_txt_lookup(host: &str, limit: Duration) -> TxtOutcome {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::ResolveHosts;
    use hickory_resolver::net::{DnsError, NetError};
    use hickory_resolver::proto::rr::{RData, RecordType};

    let Ok(mut builder) = TokioResolver::builder_tokio() else {
        // The OS gave no resolver list (offline, empty configuration).
        return TxtOutcome::Failed;
    };
    {
        let opts = builder.options_mut();
        opts.cache_size = 0;
        opts.attempts = 1;
        opts.timeout = limit;
        opts.use_hosts_file = ResolveHosts::Never;
    }
    let Ok(resolver) = builder.build() else {
        return TxtOutcome::Failed;
    };
    // The trailing dot makes the name absolute (no search-domain suffixes are tried).
    let name = format!("{}.", host.trim_end_matches('.'));
    match resolver.lookup(name, RecordType::TXT).await {
        Ok(lookup) => {
            let records: Vec<String> = lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(txt) => Some(
                        txt.txt_data
                            .iter()
                            .map(|part| String::from_utf8_lossy(part).into_owned())
                            .collect::<String>(),
                    ),
                    _ => None,
                })
                .collect();
            if records.is_empty() {
                TxtOutcome::NotFound
            } else {
                TxtOutcome::Records(records)
            }
        }
        Err(NetError::Timeout) => TxtOutcome::Timeout,
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) => TxtOutcome::NotFound,
        Err(_) => TxtOutcome::Failed,
    }
}

/// `getaddrinfo` reports NXDOMAIN and a broken resolver through the same error type; only the
/// well-known "name does not exist" wordings (and the Windows codes) count as `NotFound`, every
/// other error stays `Failed` (never read as "not listed").
fn is_name_not_found(e: &std::io::Error) -> bool {
    // WSAHOST_NOT_FOUND / WSANO_DATA.
    if matches!(e.raw_os_error(), Some(11001 | 11004)) {
        return true;
    }
    let text = e.to_string().to_lowercase();
    [
        "not known",
        "no address associated",
        "does not resolve",
        "no such host",
        "nodename nor servname",
    ]
    .iter()
    .any(|m| text.contains(m))
}

// ---------------------------------------------------------------------------------------------
// HTTP probe
// ---------------------------------------------------------------------------------------------

/// Raw outcome of one HTTP GET probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProbeOutcome {
    Response {
        status: u16,
        body: String,
    },
    Timeout,
    /// The connection could not be established (no route, refused, TLS failure...).
    ConnectFailed,
    /// The connection worked, but the body could not be read.
    ReadFailed,
    /// The HTTP client could not be built.
    ClientError,
}

/// Performs a plain GET from the host's own network stack (used for the IPv6 leak probe).
pub trait IpProbe: Send + Sync {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome>;
}

/// `reqwest` without any proxy: the probe must show what the OS network stack does, not what an
/// `HTTPS_PROXY` of this process would do.
pub struct ReqwestProbe;

impl IpProbe for ReqwestProbe {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            let Ok(client) = reqwest::Client::builder().timeout(limit).no_proxy().build() else {
                return HttpProbeOutcome::ClientError;
            };
            let resp = match client.get(url).send().await {
                Ok(r) => r,
                Err(e) if e.is_timeout() => return HttpProbeOutcome::Timeout,
                Err(_) => return HttpProbeOutcome::ConnectFailed,
            };
            let status = resp.status().as_u16();
            match resp.text().await {
                Ok(body) => HttpProbeOutcome::Response { status, body },
                Err(e) if e.is_timeout() => HttpProbeOutcome::Timeout,
                Err(_) => HttpProbeOutcome::ReadFailed,
            }
        })
    }
}

// ---------------------------------------------------------------------------------------------
// UDP exchange
// ---------------------------------------------------------------------------------------------

/// Raw outcome of one UDP request/response exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpOutcome {
    /// The first datagram of the server that the `accept` filter let through.
    Reply(Vec<u8>),
    /// Nothing acceptable arrived within the time limit.
    Timeout,
    /// The server name did not resolve or the socket failed (no route, send error...).
    Failed,
}

/// One datagram out, one acceptable datagram back (used for the STUN binding request).
pub trait UdpProbe: Send + Sync {
    /// Sends `request` to `server` (`host:port`) from the host's own network stack and waits up to
    /// `limit` for a datagram of that server for which `accept` is true; any other datagram
    /// (garbage, a stray or forged answer) is skipped.
    fn exchange<'a>(
        &'a self,
        server: &'a str,
        request: &'a [u8],
        accept: &'a (dyn Fn(&[u8]) -> bool + Send + Sync),
        limit: Duration,
    ) -> BoxFuture<'a, UdpOutcome>;
}

/// A real `tokio` UDP socket bound to `0.0.0.0:0` (IPv4).
pub struct TokioUdp;

impl UdpProbe for TokioUdp {
    fn exchange<'a>(
        &'a self,
        server: &'a str,
        request: &'a [u8],
        accept: &'a (dyn Fn(&[u8]) -> bool + Send + Sync),
        limit: Duration,
    ) -> BoxFuture<'a, UdpOutcome> {
        Box::pin(async move {
            let work = async {
                let Ok(mut addrs) = tokio::net::lookup_host(server).await else {
                    return UdpOutcome::Failed;
                };
                let Some(target) = addrs.find(|a| a.is_ipv4()) else {
                    return UdpOutcome::Failed;
                };
                let Ok(sock) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
                    return UdpOutcome::Failed;
                };
                if sock.send_to(request, target).await.is_err() {
                    return UdpOutcome::Failed;
                }
                let mut buf = [0u8; 1500];
                loop {
                    match sock.recv_from(&mut buf).await {
                        // Only the queried server counts: a datagram from anywhere else is noise.
                        Ok((n, from)) if from == target && accept(&buf[..n]) => {
                            return UdpOutcome::Reply(buf[..n].to_vec());
                        }
                        Ok(_) => {}
                        // Windows reports an ICMP "port unreachable" of an earlier datagram as a
                        // reset on the next read: not an answer, keep waiting for the limit.
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                        Err(_) => return UdpOutcome::Failed,
                    }
                }
            };
            tokio::time::timeout(limit, work)
                .await
                .unwrap_or(UdpOutcome::Timeout)
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Host information
// ---------------------------------------------------------------------------------------------

/// Why a host setting could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemReadError {
    /// This operating system has no such source.
    Unsupported,
    /// The source exists, but reading it failed (command missing, non-zero exit, empty output).
    Failed,
}

/// Everything the checks read from the host.
pub trait SystemInfo: Send + Sync {
    /// Whether the host has a global IPv6 address and a route for it. `None`: could not tell.
    fn has_global_ipv6(&self) -> Option<bool>;
    /// IANA name of the system time zone.
    fn system_timezone(&self) -> Result<String, String>;
    /// Current UTC offset of the host (seconds east).
    fn local_utc_offset_secs(&self) -> Option<i32>;
    /// Current UTC offset of an IANA zone (seconds east); `None` when it cannot be computed here.
    fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32>;
    /// Environment variable of this process.
    fn env_var(&self, name: &str) -> Option<String>;
    /// User locale tags from the OS settings (macOS `AppleLocale`/`AppleLanguages`, Windows
    /// regional settings).
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError>;
    /// Text of the OS DNS configuration (`scutil --dns` / `ipconfig /all`).
    fn dns_listing(&self) -> Result<String, SystemReadError>;
    /// Output of `reg query` of the location consent value (Windows only).
    fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError>;
    /// Whether the CLI/IDE protection of Zastava is applied on this machine.
    fn cli_protection_active(&self) -> bool;
}

/// The real host.
pub struct RealSystem;

/// `2000::/3`: addresses that are routed on the Internet.
pub fn is_global_unicast_v6(addr: &Ipv6Addr) -> bool {
    (addr.octets()[0] & 0xe0) == 0x20
}

/// `"+0100"` / `"-0330"` (the output of `date +%z`) to seconds east of UTC.
pub fn parse_utc_offset(text: &str) -> Option<i32> {
    let t = text.trim();
    let (sign, digits) = match t.as_bytes().first()? {
        b'+' => (1, &t[1..]),
        b'-' => (-1, &t[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits[2..].parse().ok()?;
    if hours > 14 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Values of a `defaults read` output: `ru_RU` or `(\n    "ru-RU",\n    "en-RU"\n)`.
pub fn parse_defaults_values(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| {
            l.trim()
                .trim_matches(|c: char| matches!(c, '(' | ')' | ',' | '"' | ' '))
        })
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// A zone name taken from a remote service is checked before it is used on a command line.
#[cfg_attr(not(unix), allow(dead_code))]
fn is_plain_zone_name(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && !zone.starts_with('/')
        && !zone.contains("..")
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'+'))
}

impl SystemInfo for RealSystem {
    fn has_global_ipv6(&self) -> Option<bool> {
        use std::io::ErrorKind::{
            AddrNotAvailable, HostUnreachable, NetworkUnreachable, Unsupported,
        };
        // A connected UDP socket sends nothing: the kernel only picks the route and the source
        // address, so no global IPv6 route means no global source address.
        let sock = match UdpSocket::bind("[::]:0") {
            Ok(s) => s,
            Err(e) if matches!(e.kind(), AddrNotAvailable | Unsupported) => return Some(false),
            Err(_) => return None,
        };
        match sock.connect("[2606:4700:4700::1111]:53") {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    NetworkUnreachable | HostUnreachable | AddrNotAvailable | Unsupported
                ) =>
            {
                return Some(false);
            }
            Err(_) => return None,
        }
        match sock.local_addr().ok()?.ip() {
            IpAddr::V6(v6) => Some(is_global_unicast_v6(&v6)),
            IpAddr::V4(_) => None,
        }
    }

    fn system_timezone(&self) -> Result<String, String> {
        iana_time_zone::get_timezone().map_err(|e| e.to_string())
    }

    fn local_utc_offset_secs(&self) -> Option<i32> {
        Some(chrono::Local::now().offset().local_minus_utc())
    }

    #[cfg(unix)]
    fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32> {
        if !is_plain_zone_name(zone) {
            return None;
        }
        // An unknown zone name makes `date` print UTC without any error: look the zone up first.
        let known = [
            "/usr/share/zoneinfo",
            "/var/db/timezone/zoneinfo",
            "/usr/lib/zoneinfo",
        ]
        .iter()
        .any(|root| std::path::Path::new(root).join(zone).is_file());
        if !known {
            return None;
        }
        let out = crate::sysproxy::silent_command("/bin/date")
            .arg("+%z")
            .env("TZ", zone)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_utc_offset(&String::from_utf8_lossy(&out.stdout))
    }

    #[cfg(not(unix))]
    fn zone_utc_offset_secs(&self, _zone: &str) -> Option<i32> {
        // No time zone database on this OS: the offset of an IANA name cannot be computed.
        None
    }

    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    #[cfg(target_os = "macos")]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        let mut found = Vec::new();
        for key in ["AppleLocale", "AppleLanguages"] {
            let out = crate::sysproxy::silent_command("/usr/bin/defaults")
                .args(["read", "-g", key])
                .output()
                .ok()
                .filter(|o| o.status.success());
            if let Some(out) = out {
                found.extend(parse_defaults_values(&String::from_utf8_lossy(&out.stdout)));
            }
        }
        if found.is_empty() {
            Err(SystemReadError::Failed)
        } else {
            Ok(found)
        }
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        let mut found = Vec::new();
        for (key, value) in [
            (r"HKCU\Control Panel\International", "LocaleName"),
            (
                r"HKCU\Control Panel\International\User Profile",
                "Languages",
            ),
        ] {
            let out = crate::sysproxy::silent_command("reg")
                .args(["query", key, "/v", value])
                .output()
                .ok()
                .filter(|o| o.status.success());
            if let Some(out) = out {
                found.extend(parse_reg_string_values(&String::from_utf8_lossy(
                    &out.stdout,
                )));
            }
        }
        if found.is_empty() {
            Err(SystemReadError::Failed)
        } else {
            Ok(found)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    #[cfg(target_os = "macos")]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        run_for_text(crate::sysproxy::silent_command("scutil").arg("--dns"))
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        run_for_text(crate::sysproxy::silent_command("ipconfig").arg("/all"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError> {
        let key = if machine_wide {
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        } else {
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"
        };
        run_for_text(crate::sysproxy::silent_command("reg").args(["query", key, "/v", "Value"]))
    }

    #[cfg(not(target_os = "windows"))]
    fn location_consent(&self, _machine_wide: bool) -> Result<String, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    fn cli_protection_active(&self) -> bool {
        crate::sysproxy::is_cli_protection_enabled()
    }
}

/// Stdout of a finished command; a spawn error, a non-zero exit or an empty output is `Failed`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_for_text(cmd: &mut std::process::Command) -> Result<String, SystemReadError> {
    match cmd.output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            if text.trim().is_empty() {
                Err(SystemReadError::Failed)
            } else {
                Ok(text)
            }
        }
        _ => Err(SystemReadError::Failed),
    }
}

/// Values of `reg query` lines: `    LocaleName    REG_SZ    ru-RU` and
/// `    Languages    REG_MULTI_SZ    ru-RU\0en-US`.
#[cfg(any(test, target_os = "windows"))]
pub fn parse_reg_string_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(idx) = line.find("REG_") else {
            continue;
        };
        let after = &line[idx..];
        let mut parts = after.splitn(2, char::is_whitespace);
        let _kind = parts.next();
        let value = parts.next().unwrap_or("").trim();
        for item in value.split("\\0") {
            let item = item.trim();
            if !item.is_empty() {
                out.push(item.to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Bundle
// ---------------------------------------------------------------------------------------------

/// The sources an [`Auditor`](super::Auditor) works with.
#[derive(Clone)]
pub struct AuditEnv {
    pub dns: Arc<dyn DnsLookup>,
    pub probe: Arc<dyn IpProbe>,
    pub udp: Arc<dyn UdpProbe>,
    pub system: Arc<dyn SystemInfo>,
}

impl AuditEnv {
    /// DNS, HTTP and host of the machine the application runs on.
    pub fn real() -> Self {
        Self {
            dns: Arc::new(SystemDns),
            probe: Arc::new(ReqwestProbe),
            udp: Arc::new(TokioUdp),
            system: Arc::new(RealSystem),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fakes for tests (no network, no processes)
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
pub mod fakes {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers by host name; an unlisted host gets `default`. `panic_on` makes a lookup panic.
    pub struct FakeDns {
        pub answers: Mutex<HashMap<String, LookupOutcome>>,
        /// TXT answers by host name; an unlisted host gets `TxtOutcome::Timeout`.
        pub txt_answers: Mutex<HashMap<String, TxtOutcome>>,
        pub default: LookupOutcome,
        pub panic_on: Option<String>,
        pub calls: AtomicUsize,
    }

    impl FakeDns {
        pub fn new(default: LookupOutcome) -> Self {
            Self {
                answers: Mutex::default(),
                txt_answers: Mutex::default(),
                default,
                panic_on: None,
                calls: AtomicUsize::new(0),
            }
        }
        pub fn with(self, host: &str, outcome: LookupOutcome) -> Self {
            self.answers
                .lock()
                .unwrap()
                .insert(host.to_string(), outcome);
            self
        }
        pub fn with_txt(self, host: &str, outcome: TxtOutcome) -> Self {
            self.txt_answers
                .lock()
                .unwrap()
                .insert(host.to_string(), outcome);
            self
        }
        pub fn panicking_on(mut self, host_part: &str) -> Self {
            self.panic_on = Some(host_part.to_string());
            self
        }
    }

    pub fn addr(ip: &str) -> LookupOutcome {
        LookupOutcome::Addrs(vec![ip.parse().unwrap()])
    }

    impl DnsLookup for FakeDns {
        fn lookup<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, LookupOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(p) = &self.panic_on {
                if host.contains(p.as_str()) {
                    panic!("fake resolver panic");
                }
            }
            let out = self
                .answers
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .unwrap_or_else(|| self.default.clone());
            Box::pin(async move { out })
        }

        fn lookup_txt<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, TxtOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = self
                .txt_answers
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .unwrap_or(TxtOutcome::Timeout);
            Box::pin(async move { out })
        }
    }

    /// The same outcome for every URL, except the ones with a registered part of the URL; counts
    /// the calls.
    pub struct FakeProbe {
        pub outcome: HttpProbeOutcome,
        pub routes: Vec<(String, HttpProbeOutcome)>,
        pub calls: AtomicUsize,
    }

    impl FakeProbe {
        pub fn new(outcome: HttpProbeOutcome) -> Self {
            Self {
                outcome,
                routes: Vec::new(),
                calls: AtomicUsize::new(0),
            }
        }
        /// URLs that contain `url_part` get `outcome` instead of the default one.
        pub fn with_route(mut self, url_part: &str, outcome: HttpProbeOutcome) -> Self {
            self.routes.push((url_part.to_string(), outcome));
            self
        }
        pub fn body(status: u16, body: &str) -> Self {
            Self::new(HttpProbeOutcome::Response {
                status,
                body: body.to_string(),
            })
        }
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl IpProbe for FakeProbe {
        fn get<'a>(&'a self, url: &'a str, _limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = self
                .routes
                .iter()
                .find(|(part, _)| url.contains(part.as_str()))
                .map(|(_, o)| o.clone())
                .unwrap_or_else(|| self.outcome.clone());
            Box::pin(async move { out })
        }
    }

    /// Builds the datagrams a fake server sends back for a request.
    pub type UdpResponder = Box<dyn Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync>;

    /// A UDP "network": per server a responder that gets the request and returns the datagrams
    /// that arrive (in order). A server without a responder stays silent (`Timeout`); the `accept`
    /// filter is applied exactly as the real socket does.
    #[derive(Default)]
    pub struct FakeUdp {
        pub servers: Mutex<HashMap<String, UdpResponder>>,
        pub failing: Mutex<Vec<String>>,
        pub calls: AtomicUsize,
    }

    impl FakeUdp {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with_server(
            self,
            server: &str,
            responder: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync + 'static,
        ) -> Self {
            self.servers
                .lock()
                .unwrap()
                .insert(server.to_string(), Box::new(responder));
            self
        }
        /// The server name does not resolve / the socket fails.
        pub fn failing_server(self, server: &str) -> Self {
            self.failing.lock().unwrap().push(server.to_string());
            self
        }
        pub fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl UdpProbe for FakeUdp {
        fn exchange<'a>(
            &'a self,
            server: &'a str,
            request: &'a [u8],
            accept: &'a (dyn Fn(&[u8]) -> bool + Send + Sync),
            _limit: Duration,
        ) -> BoxFuture<'a, UdpOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let out = if self.failing.lock().unwrap().iter().any(|s| s == server) {
                UdpOutcome::Failed
            } else {
                let datagrams = self
                    .servers
                    .lock()
                    .unwrap()
                    .get(server)
                    .map(|f| f(request))
                    .unwrap_or_default();
                datagrams
                    .into_iter()
                    .find(|d| accept(d))
                    .map_or(UdpOutcome::Timeout, UdpOutcome::Reply)
            };
            Box::pin(async move { out })
        }
    }

    /// A host with every field set explicitly. `FakeSystem::offline()` fails every read.
    #[derive(Clone)]
    pub struct FakeSystem {
        pub global_ipv6: Option<bool>,
        pub timezone: Result<String, String>,
        pub local_offset: Option<i32>,
        pub zone_offsets: HashMap<String, i32>,
        pub env: HashMap<String, String>,
        pub os_locales: Result<Vec<String>, SystemReadError>,
        pub dns_listing: Result<String, SystemReadError>,
        pub consent_machine: Result<String, SystemReadError>,
        pub consent_user: Result<String, SystemReadError>,
        pub cli_protection: bool,
    }

    impl FakeSystem {
        /// A quiet, working host: NL time zone, English locale, plain DNS, no IPv6, macOS-like
        /// (no location setting).
        pub fn healthy() -> Self {
            Self {
                global_ipv6: Some(false),
                timezone: Ok("Europe/Amsterdam".into()),
                local_offset: Some(3600),
                zone_offsets: HashMap::from([
                    ("Europe/Amsterdam".to_string(), 3600),
                    ("Europe/Berlin".to_string(), 3600),
                ]),
                env: HashMap::from([("LANG".to_string(), "en_US.UTF-8".to_string())]),
                os_locales: Ok(vec!["en_US".into()]),
                dns_listing: Ok("resolver #1\n  nameserver[0] : 1.1.1.1\n".into()),
                consent_machine: Err(SystemReadError::Unsupported),
                consent_user: Err(SystemReadError::Unsupported),
                cli_protection: false,
            }
        }

        /// Every read fails or returns nothing.
        pub fn offline() -> Self {
            Self {
                global_ipv6: None,
                timezone: Err("no tz".into()),
                local_offset: None,
                zone_offsets: HashMap::new(),
                env: HashMap::new(),
                os_locales: Err(SystemReadError::Failed),
                dns_listing: Err(SystemReadError::Failed),
                consent_machine: Err(SystemReadError::Unsupported),
                consent_user: Err(SystemReadError::Unsupported),
                cli_protection: false,
            }
        }
    }

    impl SystemInfo for FakeSystem {
        fn has_global_ipv6(&self) -> Option<bool> {
            self.global_ipv6
        }
        fn system_timezone(&self) -> Result<String, String> {
            self.timezone.clone()
        }
        fn local_utc_offset_secs(&self) -> Option<i32> {
            self.local_offset
        }
        fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32> {
            self.zone_offsets.get(zone).copied()
        }
        fn env_var(&self, name: &str) -> Option<String> {
            self.env.get(name).cloned()
        }
        fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
            self.os_locales.clone()
        }
        fn dns_listing(&self) -> Result<String, SystemReadError> {
            self.dns_listing.clone()
        }
        fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError> {
            if machine_wide {
                self.consent_machine.clone()
            } else {
                self.consent_user.clone()
            }
        }
        fn cli_protection_active(&self) -> bool {
            self.cli_protection
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_unicast_is_2000_slash_3() {
        let g: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_global_unicast_v6(&g));
        assert!(!is_global_unicast_v6(&ula));
        assert!(!is_global_unicast_v6(&ll));
        assert!(!is_global_unicast_v6(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn utc_offset_parsing() {
        assert_eq!(parse_utc_offset("+0100\n"), Some(3600));
        assert_eq!(parse_utc_offset("-0330"), Some(-12600));
        assert_eq!(parse_utc_offset("+0000"), Some(0));
        assert_eq!(parse_utc_offset("CET"), None);
        assert_eq!(parse_utc_offset("+01"), None);
        assert_eq!(parse_utc_offset("+9900"), None);
    }

    #[test]
    fn defaults_output_parsing() {
        assert_eq!(parse_defaults_values("ru_RU\n"), vec!["ru_RU"]);
        assert_eq!(
            parse_defaults_values("(\n    \"ru-RU\",\n    \"en-RU\"\n)\n"),
            vec!["ru-RU", "en-RU"]
        );
        assert!(parse_defaults_values("\n").is_empty());
    }

    #[test]
    fn reg_output_parsing() {
        let one = "\nHKEY_CURRENT_USER\\Control Panel\\International\n    LocaleName    REG_SZ    ru-RU\n";
        assert_eq!(parse_reg_string_values(one), vec!["ru-RU"]);
        let many = "    Languages    REG_MULTI_SZ    ru-RU\\0en-US\n";
        assert_eq!(parse_reg_string_values(many), vec!["ru-RU", "en-US"]);
    }

    #[test]
    fn zone_names_from_remote_services_are_validated() {
        assert!(is_plain_zone_name("Europe/Amsterdam"));
        assert!(is_plain_zone_name("America/Port-au-Prince"));
        assert!(is_plain_zone_name("Etc/GMT+3"));
        assert!(!is_plain_zone_name(""));
        assert!(!is_plain_zone_name("/etc/passwd"));
        assert!(!is_plain_zone_name("../../etc/passwd"));
        assert!(!is_plain_zone_name("Europe/Amsterdam; rm -rf"));
    }

    #[test]
    fn not_found_is_told_apart_from_a_broken_resolver() {
        use std::io::{Error, ErrorKind};
        let nx = Error::new(
            ErrorKind::Other,
            "failed to lookup address information: nodename nor servname provided, or not known",
        );
        assert!(is_name_not_found(&nx));
        let glibc = Error::new(ErrorKind::Other, "Name or service not known");
        assert!(is_name_not_found(&glibc));
        let broken = Error::new(
            ErrorKind::Other,
            "failed to lookup address information: Temporary failure in name resolution",
        );
        assert!(!is_name_not_found(&broken));
    }

    // The real probe against a loopback listener only (no traffic leaves this machine).
    async fn loopback(response: Option<&'static str>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    match response {
                        Some(r) => {
                            let _ = sock.write_all(r.as_bytes()).await;
                            let _ = sock.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(30)).await,
                    }
                });
            }
        });
        format!("http://{addr}/cdn-cgi/trace")
    }

    #[tokio::test]
    async fn reqwest_probe_tells_timeout_from_refused_from_a_response() {
        let silent = loopback(None).await;
        assert_eq!(
            ReqwestProbe.get(&silent, Duration::from_millis(50)).await,
            HttpProbeOutcome::Timeout
        );
        let ok = loopback(Some("HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nloc=NL")).await;
        assert_eq!(
            ReqwestProbe.get(&ok, Duration::from_secs(2)).await,
            HttpProbeOutcome::Response {
                status: 200,
                body: "loc=NL".into()
            }
        );
        // A port nobody listens on.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/", l.local_addr().unwrap())
        };
        let refused = ReqwestProbe.get(&closed, Duration::from_secs(2)).await;
        if cfg!(windows) {
            // Windows retries a refused loopback connect for about two seconds, so the short
            // limit can expire first; either way the probe reports a failure, never a response.
            assert!(
                matches!(refused, HttpProbeOutcome::ConnectFailed | HttpProbeOutcome::Timeout),
                "{refused:?}"
            );
        } else {
            assert_eq!(refused, HttpProbeOutcome::ConnectFailed);
        }
    }
}
