//! Egress through a route's entry nodes: SOCKS5, HTTP CONNECT and HTTP CONNECT over TLS (`https`).

mod chained;
mod entry_connect;
pub(crate) mod handshakes;

pub use chained::{
    ChainedError, connect_chained_tcp, connect_via_chained_proxy, is_socks5_chained,
};
use entry_connect::connect_entry_with;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use crate::routing::{Route, parse_route_key};
use crate::state::UpstreamProxyConfig;

/// Parses a key or proxy URL into the legacy single-proxy view (first entry).
/// See [`crate::routing::key`] for the accepted formats and validation rules.
pub fn parse_upstream_key(input: &str) -> Result<UpstreamProxyConfig, String> {
    let route = parse_route_key(input, crate::auditor::network::current_timestamp())?;
    route
        .to_legacy(true)
        .ok_or_else(|| "Key has no entry nodes".to_string())
}

/// Stream to the target through an entry node (or a direct TCP connection).
pub enum UpstreamStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
    Prefixed {
        prefix: std::io::Cursor<Vec<u8>>,
        inner: Box<UpstreamStream>,
    },
}

impl UpstreamStream {
    pub(crate) fn with_prefix(self, prefix: Vec<u8>) -> Self {
        if prefix.is_empty() {
            self
        } else {
            Self::Prefixed {
                prefix: std::io::Cursor::new(prefix),
                inner: Box::new(self),
            }
        }
    }
}

impl AsyncRead for UpstreamStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            UpstreamStream::Prefixed { prefix, inner } => {
                let pos = prefix.position() as usize;
                let data = prefix.get_ref();
                if pos < data.len() {
                    let avail = &data[pos..];
                    let to_copy = avail.len().min(buf.remaining());
                    buf.put_slice(&avail[..to_copy]);
                    prefix.set_position((pos + to_copy) as u64);
                    return Poll::Ready(Ok(()));
                }
                Pin::new(inner.as_mut()).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for UpstreamStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            UpstreamStream::Prefixed { inner, .. } => Pin::new(inner.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            UpstreamStream::Prefixed { inner, .. } => Pin::new(inner.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UpstreamStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            UpstreamStream::Prefixed { inner, .. } => Pin::new(inner.as_mut()).poll_shutdown(cx),
        }
    }
}

fn build_tls_config(roots: RootCertStore) -> io::Result<ClientConfig> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("TLS setup failed: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Production TLS config: Mozilla roots (webpki-roots, same as reqwest), full verification.
/// There is intentionally no way to inject roots or disable verification on this path.
pub(crate) fn production_tls_config() -> io::Result<Arc<ClientConfig>> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    if let Some(c) = CFG.get() {
        return Ok(Arc::clone(c));
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = Arc::new(build_tls_config(roots)?);
    Ok(Arc::clone(CFG.get_or_init(|| cfg)))
}

const ROUTE_ENTRY_STAGGER: Duration = Duration::from_millis(500);

async fn connect_via_route_inner(
    route: &Route,
    target_host: &str,
    target_port: u16,
    per_entry_timeout: Duration,
    tls: &Arc<ClientConfig>,
    gateway_port: u16,
    chained_proxy: Option<&str>,
) -> io::Result<UpstreamStream> {
    if route.entries.is_empty() {
        crate::diagnostics::record(
            "proxy:route",
            &format!(
                "route={} phase=connect err=route has no entry nodes",
                route.id
            ),
        );
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "route has no entry nodes",
        ));
    }
    let allow_local = route.allows_local_entries();
    let mut errors: Vec<Option<String>> = vec![None; route.entries.len()];
    let mut last_kind = io::ErrorKind::Other;

    if route.entries.len() == 1 {
        let entry = &route.entries[0];
        match connect_entry_with(
            entry,
            target_host,
            target_port,
            per_entry_timeout,
            tls,
            allow_local,
            gateway_port,
            chained_proxy,
        )
        .await
        {
            Ok(s) => return Ok(s),
            Err(e) => {
                last_kind = e.kind();
                errors[0] = Some(format!(
                    "entry #1 {} {}: {e}",
                    entry.proto.as_str(),
                    entry.endpoint()
                ));
            }
        }
    } else {
        let mut set: JoinSet<(usize, io::Result<UpstreamStream>)> = JoinSet::new();
        let mut next_idx = 0usize;
        let spawn_entry = |set: &mut JoinSet<(usize, io::Result<UpstreamStream>)>, idx: usize| {
            let entry = route.entries[idx].clone();
            let host = target_host.to_string();
            let tls = Arc::clone(tls);
            let cp = chained_proxy.map(str::to_string);
            set.spawn(async move {
                let res = connect_entry_with(
                    &entry,
                    &host,
                    target_port,
                    per_entry_timeout,
                    &tls,
                    allow_local,
                    gateway_port,
                    cp.as_deref(),
                )
                .await;
                (idx, res)
            });
        };

        spawn_entry(&mut set, next_idx);
        next_idx += 1;

        loop {
            let has_more = next_idx < route.entries.len();
            tokio::select! {
                joined = set.join_next(), if !set.is_empty() => {
                    match joined {
                        Some(Ok((_idx, Ok(stream)))) => return Ok(stream),
                        Some(Ok((idx, Err(e)))) => {
                            last_kind = e.kind();
                            let entry = &route.entries[idx];
                            errors[idx] = Some(format!(
                                "entry #{} {} {}: {e}",
                                idx + 1,
                                entry.proto.as_str(),
                                entry.endpoint()
                            ));
                        }
                        Some(Err(join_err)) => {
                            last_kind = io::ErrorKind::Other;
                            let _ = join_err;
                        }
                        None => {}
                    }
                    if next_idx < route.entries.len() {
                        spawn_entry(&mut set, next_idx);
                        next_idx += 1;
                    } else if set.is_empty() {
                        break;
                    }
                }
                _ = tokio::time::sleep(ROUTE_ENTRY_STAGGER), if has_more => {
                    spawn_entry(&mut set, next_idx);
                    next_idx += 1;
                }
            }
        }
    }

    let joined_errors: Vec<String> = errors.into_iter().flatten().collect();
    let summary = format!("all entry nodes failed ({})", joined_errors.join("; "));
    crate::diagnostics::record(
        "proxy:route",
        &format!(
            "route={} err={}",
            route.id,
            crate::diagnostics::sanitize_diagnostic_text(&summary)
        ),
    );
    Err(io::Error::new(last_kind, summary))
}

#[cfg(test)]
async fn connect_via_route_with(
    route: &Route,
    target_host: &str,
    target_port: u16,
    per_entry_timeout: Duration,
    tls: &Arc<ClientConfig>,
    gateway_port: u16,
) -> io::Result<UpstreamStream> {
    connect_via_route_inner(
        route,
        target_host,
        target_port,
        per_entry_timeout,
        tls,
        gateway_port,
        None,
    )
    .await
}

/// Opens a tunnel to `target_host:target_port` through the route's entries, tried in order with
/// `per_entry_timeout` each, using `chained_proxy` (if provided) as automatic fallback when a
/// direct connection to a public entry fails.
pub async fn connect_via_route_with_chained(
    route: &Route,
    target_host: &str,
    target_port: u16,
    per_entry_timeout: Duration,
    gateway_port: u16,
    chained_proxy: Option<&str>,
) -> io::Result<UpstreamStream> {
    let tls = production_tls_config()?;
    connect_via_route_inner(
        route,
        target_host,
        target_port,
        per_entry_timeout,
        &tls,
        gateway_port,
        chained_proxy,
    )
    .await
}

/// Opens a tunnel to `target_host:target_port` through the route's entries, tried in order with
/// `per_entry_timeout` each. Fails only when every entry failed. `gateway_port` is the port of the
/// local gateway (0 = unknown): an entry pointing back at it is refused (loop).
pub async fn connect_via_route(
    route: &Route,
    target_host: &str,
    target_port: u16,
    per_entry_timeout: Duration,
    gateway_port: u16,
) -> io::Result<UpstreamStream> {
    let chained = crate::sysproxy::get_chained_proxy();
    connect_via_route_with_chained(
        route,
        target_host,
        target_port,
        per_entry_timeout,
        gateway_port,
        chained.as_deref(),
    )
    .await
}

/// Legacy entry point: connects through a single v1.3.x upstream config.
pub async fn connect_via_upstream(
    cfg: &UpstreamProxyConfig,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> io::Result<UpstreamStream> {
    let route = Route::from_legacy(cfg, 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported upstream proxy protocol: {}", cfg.protocol),
        )
    })?;
    connect_via_route(&route, target_host, target_port, timeout, 0).await
}

#[cfg(test)]
#[path = "../upstream_tests.rs"]
mod tests;
