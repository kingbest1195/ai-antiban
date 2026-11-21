use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use zastava_lib::auditor::Auditor;
use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::probes::whoami::{AKAMAI_HOST, GOOGLE_TXT_HOST};
use zastava_lib::auditor::seams::fakes::{FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{
    AuditEnv, BoxFuture, DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome, TxtOutcome,
};
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::transit::invalidate_all_dns_caches;
use zastava_lib::proxy::{ProxyServer, Transit};
use zastava_lib::routing::net::clear_entry_dns_cache;
use zastava_lib::sysproxy::{force_os_dry_run, set_chained_proxy, test_support};

pub use crate::mock_entry::{EntryMode, MockZastavaEntry, serve_synthetic_echo_or_http};

pub fn lock_global_state_sync() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub struct GlobalStateGuard<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl Drop for GlobalStateGuard<'_> {
    fn drop(&mut self) {
        set_chained_proxy(None);
        test_support::reset_sysproxy_state_for_test();
        clear_entry_dns_cache();
        invalidate_all_dns_caches();
    }
}

pub async fn acquire_global_state() -> GlobalStateGuard<'static> {
    force_os_dry_run();
    let guard = lock_global_state_sync().lock().await;
    set_chained_proxy(None);
    test_support::reset_sysproxy_state_for_test();
    clear_entry_dns_cache();
    invalidate_all_dns_caches();
    GlobalStateGuard { _guard: guard }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ChainedMode {
    HttpConnect,
    Socks5,
    Blackhole,
}

#[derive(Default)]
pub struct ChainedCounters {
    pub total_connections: AtomicUsize,
    pub http_connect_count: AtomicUsize,
    pub http_plain_count: AtomicUsize,
    pub socks5_domain_connect_count: AtomicUsize,
    pub raw_http_on_socks_port: AtomicUsize,
    pub last_target: Mutex<Option<String>>,
    routes: Mutex<HashMap<String, SocketAddr>>,
    default_target: Mutex<Option<SocketAddr>>,
}

impl ChainedCounters {
    pub fn add_route(&self, host: &str, addr: SocketAddr) {
        self.routes
            .lock()
            .unwrap()
            .insert(host.to_ascii_lowercase(), addr);
    }

    pub fn set_default_target(&self, addr: SocketAddr) {
        *self.default_target.lock().unwrap() = Some(addr);
    }

    fn resolve_target(&self, host: &str, port: u16) -> Option<SocketAddr> {
        let key_with_port = format!("{}:{port}", host.to_ascii_lowercase());
        let key_host = host.to_ascii_lowercase();
        let routes = self.routes.lock().unwrap();
        routes
            .get(&key_with_port)
            .or_else(|| routes.get(&key_host))
            .copied()
            .or_else(|| *self.default_target.lock().unwrap())
    }
}

pub struct MockChainedProxy {
    pub addr: SocketAddr,
    pub counters: Arc<ChainedCounters>,
    task: JoinHandle<()>,
}

impl Drop for MockChainedProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockChainedProxy {
    pub async fn spawn(mode: ChainedMode, default_target: Option<SocketAddr>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counters = Arc::new(ChainedCounters::default());
        if let Some(t) = default_target {
            counters.set_default_target(t);
        }
        let c = Arc::clone(&counters);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let c = Arc::clone(&c);
                tokio::spawn(async move {
                    let _ = handle_chained_conn(stream, mode, c).await;
                });
            }
        });
        Self {
            addr,
            counters,
            task,
        }
    }

    pub fn http_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn socks5_url(&self) -> String {
        format!("socks5://{}", self.addr)
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

async fn handle_chained_conn(
    mut client: TcpStream,
    mode: ChainedMode,
    c: Arc<ChainedCounters>,
) -> std::io::Result<()> {
    c.total_connections.fetch_add(1, Ordering::SeqCst);
    if mode == ChainedMode::Blackhole {
        tokio::time::sleep(Duration::from_secs(30)).await;
        return Ok(());
    }

    let mut first = [0u8; 4096];
    let n = client.read(&mut first).await?;
    if n == 0 {
        return Ok(());
    }

    if mode == ChainedMode::Socks5 {
        if first[0] != 0x05 {
            c.raw_http_on_socks_port.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        client.write_all(&[0x05, 0x00]).await?;
        let mut hdr = [0u8; 4];
        client.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 || hdr[1] != 0x01 {
            return Ok(());
        }
        let host = match hdr[3] {
            0x03 => {
                let mut len = [0u8; 1];
                client.read_exact(&mut len).await?;
                let mut hb = vec![0u8; len[0] as usize];
                client.read_exact(&mut hb).await?;
                c.socks5_domain_connect_count.fetch_add(1, Ordering::SeqCst);
                String::from_utf8_lossy(&hb).to_string()
            }
            0x01 => {
                let mut ip = [0u8; 4];
                client.read_exact(&mut ip).await?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            _ => return Ok(()),
        };
        let mut pb = [0u8; 2];
        client.read_exact(&mut pb).await?;
        let port = u16::from_be_bytes(pb);
        *c.last_target.lock().unwrap() = Some(format!("{host}:{port}"));

        let Some(target_addr) = c.resolve_target(&host, port) else {
            client
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        };
        let Ok(mut upstream) = TcpStream::connect(target_addr).await else {
            client
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Ok(());
        };
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return Ok(());
    }

    // HttpConnect mode
    let req = String::from_utf8_lossy(&first[..n]);
    let mut parts = req.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    if method.eq_ignore_ascii_case("CONNECT") {
        c.http_connect_count.fetch_add(1, Ordering::SeqCst);
        let (host, port) = target
            .rsplit_once(':')
            .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
            .unwrap_or((target.to_string(), 443));
        *c.last_target.lock().unwrap() = Some(format!("{host}:{port}"));
        let Some(target_addr) = c.resolve_target(&host, port) else {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        };
        let Ok(mut upstream) = TcpStream::connect(target_addr).await else {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        };
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return Ok(());
    }

    c.http_plain_count.fetch_add(1, Ordering::SeqCst);
    let url_parsed = url::Url::parse(target).ok();
    let host = url_parsed
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("unknown")
        .to_string();
    let port = url_parsed
        .as_ref()
        .and_then(|u| u.port_or_known_default())
        .unwrap_or(80);
    *c.last_target.lock().unwrap() = Some(format!("{host}:{port}"));
    if let Some(target_addr) = c.resolve_target(&host, port)
        && let Ok(mut upstream) = TcpStream::connect(target_addr).await
    {
        upstream.write_all(&first[..n]).await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    } else {
        client
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            .await?;
    }
    Ok(())
}

pub struct MockEchoTarget {
    pub addr: SocketAddr,
    pub connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for MockEchoTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockEchoTarget {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = serve_synthetic_echo_or_http(stream).await;
                });
            }
        });
        Self {
            addr,
            connections,
            task,
        }
    }
}

pub fn dead_local_port() -> u16 {
    let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_l.local_addr().unwrap().port()
}

pub fn clean_de_telemetry() -> NetworkTelemetry {
    NetworkTelemetry {
        ip: "185.100.10.2".to_string(),
        country_code: "DE".to_string(),
        hostname: Some("clean-exit.example.net".to_string()),
        asn: Some(24940),
        org: Some("Hetzner Online GmbH".to_string()),
        isp: Some("Hetzner Online GmbH".to_string()),
        timezone: Some("Europe/Berlin".to_string()),
        resolved_at: current_timestamp(),
    }
}

pub struct RuIspKeyProbe {
    pub ipv6_loc: &'static str,
    pub block_doh_and_tor: bool,
    pub stun_ip: &'static str,
    pub stun_cc: &'static str,
}

impl IpProbe for RuIspKeyProbe {
    fn get<'a>(&'a self, url: &'a str, _limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            if url.contains("[2606:4700:4700::1111]") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: format!("fl=1\nip=2a00:1370::1\nloc={}\n", self.ipv6_loc),
                };
            }
            if self.block_doh_and_tor
                && (url.contains("dns.google")
                    || url.contains("1.1.1.1/dns-query")
                    || url.contains("torbulkexitlist"))
            {
                return HttpProbeOutcome::Timeout;
            }
            if url.contains("ipwho.is") && url.contains(self.stun_ip) {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: json!({
                        "success": true,
                        "ip": self.stun_ip,
                        "country_code": self.stun_cc,
                    })
                    .to_string(),
                };
            }
            if url.contains("ipwho.is") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: json!({
                        "success": true,
                        "ip": "185.100.10.2",
                        "country_code": "DE",
                        "connection": { "asn": 24940, "org": "Hetzner Online GmbH", "isp": "Hetzner Online GmbH" },
                        "timezone": { "id": "Europe/Berlin" },
                    })
                    .to_string(),
                };
            }
            if url.contains("/cdn-cgi/trace") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: "fl=1\nip=185.100.10.2\nloc=DE\ncolo=FRA\n".to_string(),
                };
            }
            if url.contains("torbulkexitlist") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: "198.51.100.1\n".to_string(),
                };
            }
            HttpProbeOutcome::Timeout
        })
    }
}

pub struct OfflineDns {
    pub block_dnsbl: bool,
    pub resolver_ip: &'static str,
}

impl DnsLookup for OfflineDns {
    fn lookup<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            if host == AKAMAI_HOST {
                let ip: IpAddr = self.resolver_ip.parse().unwrap();
                return LookupOutcome::Addrs(vec![ip]);
            }
            if self.block_dnsbl {
                LookupOutcome::Timeout
            } else {
                LookupOutcome::NotFound
            }
        })
    }

    fn lookup_uncached<'a>(
        &'a self,
        host: &'a str,
        limit: Duration,
    ) -> BoxFuture<'a, LookupOutcome> {
        self.lookup(host, limit)
    }

    fn lookup_txt<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        Box::pin(async move {
            if host == GOOGLE_TXT_HOST {
                return TxtOutcome::Records(vec![format!("\"{}\"", self.resolver_ip)]);
            }
            TxtOutcome::NotFound
        })
    }
}

pub fn build_offline_auditor(
    probe: Arc<dyn IpProbe>,
    dns: Arc<dyn DnsLookup>,
    udp: FakeUdp,
) -> Auditor {
    let env = AuditEnv {
        dns,
        probe,
        udp: Arc::new(udp),
        system: Arc::new(FakeSystem {
            global_ipv6: Some(true),
            timezone: Ok("Europe/Berlin".to_string()),
            ..FakeSystem::healthy()
        }),
    };
    Auditor::with_env(env).unwrap()
}

pub fn build_offline_transit(target_addr: SocketAddr, resolve_calls: Arc<AtomicUsize>) -> Transit {
    Transit::with_backends(
        Arc::new(move |_host| {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(vec!["185.100.10.2".parse::<IpAddr>().unwrap()]) })
        }),
        Arc::new(move |_addr| Box::pin(async move { TcpStream::connect(target_addr).await })),
        Arc::new(std::time::Instant::now),
    )
}

pub async fn start_proxy_server(
    auditor: Auditor,
    state: zastava_lib::state::AppState,
    upstream_redirect: Option<SocketAddr>,
    transit: Option<Transit>,
) -> (Arc<ProxyServer>, JoinHandle<()>) {
    let hq = Arc::new(HoldQueue::new());
    let mut srv = ProxyServer::bind_ephemeral(auditor, state, hq, upstream_redirect)
        .await
        .unwrap();
    if let Some(t) = transit {
        srv = srv.with_transit(t);
    }
    let srv = Arc::new(srv);
    let cloned = Arc::clone(&srv);
    let task = tokio::spawn(async move {
        cloned.run().await;
    });
    (srv, task)
}

pub async fn send_connect_and_echo(
    proxy_addr: SocketAddr,
    target: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(proxy_addr)
        .await
        .map_err(|e| format!("connect proxy: {e}"))?;
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write connect: {e}"))?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut b))
            .await
            .map_err(|_| "connect header timeout".to_string())?
            .map_err(|e| format!("read header: {e}"))?;
        if n == 0 {
            return Err(String::from_utf8_lossy(&head).to_string());
        }
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_str = String::from_utf8_lossy(&head).to_string();
    if !head_str.starts_with("HTTP/1.1 200") {
        let mut rest = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_millis(300), stream.read_to_end(&mut rest)).await;
        head.extend_from_slice(&rest);
        return Err(String::from_utf8_lossy(&head).to_string());
    }
    if !payload.is_empty() {
        stream.write_all(payload).await.map_err(|e| e.to_string())?;
        let mut echo = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut echo))
            .await
            .map_err(|_| "echo timeout".to_string())?
            .map_err(|e| format!("echo read: {e}"))?;
        return Ok(echo);
    }
    Ok(head)
}

pub async fn send_http_get(proxy_addr: SocketAddr, raw_request: &str) -> String {
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream.write_all(raw_request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).to_string()
}

pub fn stun_binding_success_packet(ip: std::net::Ipv4Addr, port: u16, tx_id: &[u8; 12]) -> Vec<u8> {
    let magic: u32 = 0x2112_A442;
    let mut pkt = Vec::with_capacity(32);
    pkt.extend_from_slice(&0x0101u16.to_be_bytes());
    pkt.extend_from_slice(&12u16.to_be_bytes());
    pkt.extend_from_slice(&magic.to_be_bytes());
    pkt.extend_from_slice(tx_id);
    // XOR-MAPPED-ADDRESS (0x0020)
    pkt.extend_from_slice(&0x0020u16.to_be_bytes());
    pkt.extend_from_slice(&8u16.to_be_bytes());
    pkt.push(0x00);
    pkt.push(0x01); // IPv4
    pkt.extend_from_slice(&(port ^ 0x2112).to_be_bytes());
    let xip = u32::from(ip) ^ magic;
    pkt.extend_from_slice(&xip.to_be_bytes());
    pkt
}
