use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use zastava_lib::auditor::network::{NetworkTelemetry, current_timestamp};
use zastava_lib::auditor::probes::whoami::{AKAMAI_HOST, GOOGLE_TXT_HOST};
use zastava_lib::auditor::seams::fakes::{FakeSystem, FakeUdp};
use zastava_lib::auditor::seams::{
    AuditEnv, BoxFuture, DnsLookup, HttpProbeOutcome, IpProbe, LookupOutcome, TxtOutcome,
};
use zastava_lib::auditor::{Auditor, ProviderId};
use zastava_lib::proxy::guard::{ProbeFn, ResolveFn};
use zastava_lib::proxy::hold_queue::HoldQueue;
use zastava_lib::proxy::{Gate, NetworkGuard, ProxyServer};
use zastava_lib::state::{AppState, InterceptionBehavior};
use zastava_lib::sysproxy::force_os_dry_run;

#[derive(Clone)]
pub(crate) struct ExitState {
    pub(crate) ip: String,
    pub(crate) country: String,
    pub(crate) asn: u32,
    pub(crate) org: String,
    pub(crate) timezone: String,
}

impl ExitState {
    pub(crate) fn clean_de() -> Self {
        Self {
            ip: "185.100.10.2".into(),
            country: "DE".into(),
            asn: 24940,
            org: "Hetzner Online GmbH".into(),
            timezone: "Europe/Berlin".into(),
        }
    }

    pub(crate) fn blocked_ru() -> Self {
        Self {
            ip: "95.165.10.22".into(),
            country: "RU".into(),
            asn: 8359,
            org: "MTS PJSC".into(),
            timezone: "Europe/Moscow".into(),
        }
    }

    pub(crate) fn telemetry(&self) -> NetworkTelemetry {
        NetworkTelemetry {
            ip: self.ip.clone(),
            country_code: self.country.clone(),
            hostname: Some("exit.example.net".into()),
            asn: Some(self.asn),
            org: Some(self.org.clone()),
            isp: Some(self.org.clone()),
            timezone: Some(self.timezone.clone()),
            resolved_at: current_timestamp(),
        }
    }
}

struct DynamicProbe {
    exit: Arc<RwLock<ExitState>>,
}

impl IpProbe for DynamicProbe {
    fn get<'a>(&'a self, url: &'a str, _limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            let ex = self.exit.read().await.clone();
            if url.contains("ipwho.is") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: json!({
                        "success": true,
                        "ip": ex.ip,
                        "country_code": ex.country,
                        "connection": { "asn": ex.asn, "org": ex.org, "isp": ex.org },
                        "timezone": { "id": ex.timezone },
                    })
                    .to_string(),
                };
            }
            if url.contains("[2606:") {
                return HttpProbeOutcome::Timeout;
            }
            if url.contains("/cdn-cgi/trace") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: format!("fl=1\nip={}\nloc={}\ncolo=FRA\n", ex.ip, ex.country),
                };
            }
            if url.contains("torbulkexitlist") {
                return HttpProbeOutcome::Response {
                    status: 200,
                    body: "198.51.100.1\n198.51.100.2\n".into(),
                };
            }
            HttpProbeOutcome::Timeout
        })
    }
}

struct DynamicDns {
    exit: Arc<RwLock<ExitState>>,
}

impl DnsLookup for DynamicDns {
    fn lookup<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        Box::pin(async move {
            if host == AKAMAI_HOST {
                let ip: IpAddr = self.exit.read().await.ip.parse().unwrap();
                return LookupOutcome::Addrs(vec![ip]);
            }
            if host.starts_with("2.0.0.127.") {
                return LookupOutcome::Addrs(vec!["127.0.0.2".parse().unwrap()]);
            }
            LookupOutcome::NotFound
        })
    }

    fn lookup_uncached<'a>(&'a self, host: &'a str, limit: Duration) -> BoxFuture<'a, LookupOutcome> {
        self.lookup(host, limit)
    }

    fn lookup_txt<'a>(&'a self, host: &'a str, _limit: Duration) -> BoxFuture<'a, TxtOutcome> {
        Box::pin(async move {
            if host == GOOGLE_TXT_HOST {
                let ip = self.exit.read().await.ip.clone();
                return TxtOutcome::Records(vec![format!("\"{ip}\"")]);
            }
            TxtOutcome::NotFound
        })
    }
}

/// Minimal SOCKS5 (no auth) echo upstream that echoes plain streams and closes immediately on TLS ClientHello (0x16).
pub(crate) async fn spawn_socks_echo() -> (u16, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let tunnels = Arc::new(AtomicU64::new(0));
    let tunnels_bg = Arc::clone(&tunnels);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let t = Arc::clone(&tunnels_bg);
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                if s.read_exact(&mut g).await.is_err() {
                    return;
                }
                let _ = s.write_all(&[0x05, 0x00]).await;
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                if head[3] == 0x03 {
                    let mut len = [0u8; 1];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; len[0] as usize + 2];
                    if s.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                } else {
                    let mut rest = [0u8; 6];
                    if s.read_exact(&mut rest).await.is_err() {
                        return;
                    }
                }
                let _ = s
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                let mut buf = [0u8; 256];
                let Ok(n) = s.read(&mut buf).await else { return };
                if n == 0 || buf[0] == 0x16 {
                    // Immediate close on TLS probe (non-echo audit probe).
                    return;
                }
                t.fetch_add(1, Ordering::SeqCst);
                let _ = s.write_all(&buf[..n]).await;
                while let Ok(k) = s.read(&mut buf).await {
                    if k == 0 || s.write_all(&buf[..k]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (port, tunnels)
}

pub(crate) async fn spawn_direct_echo_sink() -> (SocketAddr, Arc<AtomicU64>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let hits_bg = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            hits_bg.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, hits)
}

pub(crate) async fn start_gateway(
    initial_exit: ExitState,
) -> (
    AppState,
    Arc<ProxyServer>,
    Arc<NetworkGuard>,
    Arc<RwLock<ExitState>>,
    Arc<AtomicU64>,
    Auditor,
) {
    force_os_dry_run();
    let exit = Arc::new(RwLock::new(initial_exit));
    let env = AuditEnv {
        dns: Arc::new(DynamicDns { exit: Arc::clone(&exit) }),
        probe: Arc::new(DynamicProbe { exit: Arc::clone(&exit) }),
        udp: Arc::new(FakeUdp::new()),
        system: Arc::new(FakeSystem { global_ipv6: Some(true), ..FakeSystem::healthy() }),
    };
    let auditor = Auditor::with_env(env).unwrap();
    let state = AppState::new_in_memory();
    state
        .set_interception_behavior(InterceptionBehavior::AutoLockSilent)
        .await
        .unwrap();
    let hold_queue = Arc::new(HoldQueue::new());
    let (direct_sink, direct_hits) = spawn_direct_echo_sink().await;
    let server = Arc::new(
        ProxyServer::bind_ephemeral(auditor.clone(), state.clone(), Arc::clone(&hold_queue), Some(direct_sink))
            .await
            .unwrap(),
    );
    let guard = Arc::clone(&server.guard);
    let probe_exit = Arc::clone(&exit);
    let probe: ProbeFn = Arc::new(move || {
        let e = Arc::clone(&probe_exit);
        Box::pin(async move { Some(e.read().await.ip.clone()) })
    });
    let res_exit = Arc::clone(&exit);
    let resolve: ResolveFn = Arc::new(move || {
        let e = Arc::clone(&res_exit);
        Box::pin(async move { Ok(e.read().await.telemetry()) })
    });
    guard.start_with_test_env(auditor.clone(), state.clone(), hold_queue, Some(probe), Some(resolve));
    let srv_bg = Arc::clone(&server);
    tokio::spawn(async move { srv_bg.run().await });
    (state, server, guard, exit, direct_hits, auditor)
}

pub(crate) async fn wait_for_gate(guard: &NetworkGuard, provider: ProviderId, expected: Gate) {
    for _ in 0..200 {
        if guard.gate_for(provider) == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(guard.gate_for(provider), expected, "timed out waiting for {provider:?} gate");
}

pub(crate) async fn connect_and_echo(addr: SocketAddr, host: &str, msg: &[u8]) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut hdr = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut hdr))
        .await
        .expect("gateway response timeout")
        .unwrap();
    let resp = String::from_utf8_lossy(&hdr[..n]).to_string();
    if !resp.starts_with("HTTP/1.1 200") {
        return (resp, Vec::new());
    }
    s.write_all(msg).await.unwrap();
    let mut echo = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut echo))
        .await
        .expect("echo timeout")
        .unwrap();
    (resp, echo)
}

pub(crate) fn route_telemetry(ip: &str, cc: &str) -> NetworkTelemetry {
    NetworkTelemetry {
        ip: ip.into(),
        country_code: cc.into(),
        hostname: Some("k1.proxy.example".into()),
        asn: Some(24940),
        org: Some("Zastava Remote ISP".into()),
        isp: Some("Zastava Remote ISP".into()),
        timezone: Some("Europe/Amsterdam".into()),
        resolved_at: current_timestamp(),
    }
}
