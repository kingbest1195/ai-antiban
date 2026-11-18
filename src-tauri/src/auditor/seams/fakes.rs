use super::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Answers by host name; an unlisted host gets `default`. `panic_on` makes a lookup panic.
pub struct FakeDns {
    pub answers: Mutex<HashMap<String, LookupOutcome>>,
    /// TXT answers by host name; an unlisted host gets `TxtOutcome::Timeout`.
    pub txt_answers: Mutex<HashMap<String, TxtOutcome>>,
    /// PTR answers by IP address; an unlisted IP gets `None`.
    pub ptr_answers: Mutex<HashMap<IpAddr, String>>,
    pub default: LookupOutcome,
    pub panic_on: Option<String>,
    pub calls: AtomicUsize,
}

impl FakeDns {
    pub fn new(default: LookupOutcome) -> Self {
        Self {
            answers: Mutex::default(),
            txt_answers: Mutex::default(),
            ptr_answers: Mutex::default(),
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
    pub fn with_ptr(self, ip: IpAddr, ptr: impl Into<String>) -> Self {
        self.ptr_answers.lock().unwrap().insert(ip, ptr.into());
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
        if let Some(p) = &self.panic_on
            && host.contains(p.as_str())
        {
            panic!("fake resolver panic");
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

    fn reverse_ptr<'a>(&'a self, ip: IpAddr) -> BoxFuture<'a, Option<String>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let out = self.ptr_answers.lock().unwrap().get(&ip).cloned();
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
    pub sync_ai_tz: bool,
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
            sync_ai_tz: false,
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
            sync_ai_tz: false,
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
    fn sync_ai_tz_active(&self) -> bool {
        self.sync_ai_tz
    }
}
