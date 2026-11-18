use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::diagnostics::sanitize_diagnostic_text;
use crate::routing::net::resolve_entry_checked;
use crate::routing::{Entry, EntryProto};

use super::UpstreamStream;
use super::chained::{
    ChainedError, connect_entry_tcp_via_chained, is_chained_eligible_for_entry,
    should_try_chained_for_entry,
};
use super::handshakes::{http_connect_handshake, socks5_handshake, tcp_connect_addrs};

#[derive(Clone, Copy)]
enum RoutePhase {
    Dns,
    TcpDirect,
    TcpChained,
    Tls,
    Connect,
}

impl RoutePhase {
    fn as_str(self) -> &'static str {
        match self {
            RoutePhase::Dns => "dns",
            RoutePhase::TcpDirect => "tcp_direct",
            RoutePhase::TcpChained => "tcp_chained",
            RoutePhase::Tls => "tls",
            RoutePhase::Connect => "connect",
        }
    }
}

struct PhaseError {
    phase: RoutePhase,
    err: io::Error,
}

impl PhaseError {
    fn new(phase: RoutePhase, err: io::Error) -> Self {
        Self { phase, err }
    }
}

async fn handshake_on_tcp(
    mut tcp: TcpStream,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
    tls: &Arc<ClientConfig>,
) -> Result<UpstreamStream, PhaseError> {
    match entry.proto {
        EntryProto::Socks5 => {
            socks5_handshake(&mut tcp, entry, target_host, target_port)
                .await
                .map_err(|e| PhaseError::new(RoutePhase::Connect, e))?;
            Ok(UpstreamStream::Plain(tcp))
        }
        EntryProto::Http => {
            http_connect_handshake(&mut tcp, entry, target_host, target_port)
                .await
                .map_err(|e| PhaseError::new(RoutePhase::Connect, e))?;
            Ok(UpstreamStream::Plain(tcp))
        }
        EntryProto::Https => {
            let server_name =
                ServerName::try_from(entry.tls_server_name().to_string()).map_err(|_| {
                    PhaseError::new(
                        RoutePhase::Tls,
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"),
                    )
                })?;
            let mut tls_stream = TlsConnector::from(Arc::clone(tls))
                .connect(server_name, tcp)
                .await
                .map_err(|e| {
                    PhaseError::new(
                        RoutePhase::Tls,
                        io::Error::new(e.kind(), format!("TLS handshake failed: {e}")),
                    )
                })?;
            http_connect_handshake(&mut tls_stream, entry, target_host, target_port)
                .await
                .map_err(|e| PhaseError::new(RoutePhase::Connect, e))?;
            Ok(UpstreamStream::Tls(Box::new(tls_stream)))
        }
    }
}

fn record_route_phase(phase: RoutePhase, entry: &Entry, note: &str) {
    let clean = sanitize_diagnostic_text(note);
    crate::diagnostics::record(
        "proxy:route",
        &format!(
            "phase={} proto={} endpoint={} {clean}",
            phase.as_str(),
            entry.proto.as_str(),
            entry.endpoint()
        ),
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_entry_with(
    entry: &Entry,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
    tls: &Arc<ClientConfig>,
    allow_local: bool,
    gateway_port: u16,
    chained_proxy: Option<&str>,
) -> io::Result<UpstreamStream> {
    let started = tokio::time::Instant::now();
    let mut resolved_addrs: Option<Vec<SocketAddr>> = None;

    let direct_res: Result<UpstreamStream, PhaseError> = async {
        let dns_rem = timeout.saturating_sub(started.elapsed());
        let addrs = match tokio::time::timeout(
            dns_rem,
            resolve_entry_checked(entry, allow_local, gateway_port),
        )
        .await
        {
            Ok(Ok(addrs)) => addrs,
            Ok(Err(e)) => return Err(PhaseError::new(RoutePhase::Dns, e)),
            Err(_) => {
                return Err(PhaseError::new(
                    RoutePhase::Dns,
                    io::Error::new(io::ErrorKind::TimedOut, "entry DNS lookup timed out"),
                ));
            }
        };
        resolved_addrs = Some(addrs.clone());

        let rem = timeout.saturating_sub(started.elapsed());
        if rem.is_zero() {
            return Err(PhaseError::new(
                RoutePhase::TcpDirect,
                io::Error::new(io::ErrorKind::TimedOut, "entry connect budget exhausted"),
            ));
        }

        let can_chain = chained_proxy
            .is_some_and(|cp| is_chained_eligible_for_entry(entry, Some(&addrs), gateway_port, cp));
        let direct_budget = if can_chain {
            ((rem * 55) / 100).min(Duration::from_secs(5)).max(rem / 2)
        } else {
            rem
        };

        let direct_io = tokio::time::timeout(direct_budget, async {
            let tcp = tcp_connect_addrs(addrs, direct_budget)
                .await
                .map_err(|e| PhaseError::new(RoutePhase::TcpDirect, e))?;
            handshake_on_tcp(tcp, entry, target_host, target_port, tls).await
        })
        .await;

        match direct_io {
            Ok(res) => res,
            Err(_) => Err(PhaseError::new(
                RoutePhase::TcpDirect,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} direct entry connection timed out", entry.proto.as_str()),
                ),
            )),
        }
    }
    .await;

    let (direct_phase, direct_err) = match direct_res {
        Ok(stream) => return Ok(stream),
        Err(pe) => {
            record_route_phase(pe.phase, entry, &format!("err={}", pe.err));
            (pe.phase, pe.err)
        }
    };

    let allow_on_phase = matches!(direct_phase, RoutePhase::TcpDirect | RoutePhase::Tls)
        || (matches!(direct_phase, RoutePhase::Dns | RoutePhase::Connect)
            && direct_err.kind() != io::ErrorKind::PermissionDenied);

    let Some(cp) = chained_proxy.filter(|cp| {
        should_try_chained_for_entry(
            entry,
            resolved_addrs.as_deref(),
            gateway_port,
            cp,
            allow_on_phase,
        )
    }) else {
        return Err(direct_err);
    };

    let rem = timeout.saturating_sub(started.elapsed());
    if rem.is_zero() {
        let err = io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "{} entry connection timed out before chained fallback",
                entry.proto.as_str()
            ),
        );
        record_route_phase(RoutePhase::TcpChained, entry, &format!("err={err}"));
        return Err(err);
    }

    let chained_res: Result<UpstreamStream, PhaseError> =
        match tokio::time::timeout(rem, async {
            let tcp = connect_entry_tcp_via_chained(cp, entry, rem, gateway_port)
                .await
                .map_err(|ce| match ce {
                    ChainedError::Unreachable(e) => PhaseError::new(RoutePhase::TcpChained, e),
                    ChainedError::Refused { status } => PhaseError::new(
                        RoutePhase::TcpChained,
                        io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("chained proxy refused entry tunnel (status {status})"),
                        ),
                    ),
                })?;
            handshake_on_tcp(tcp, entry, target_host, target_port, tls).await
        })
        .await
        {
            Ok(res) => res,
            Err(_) => Err(PhaseError::new(
                RoutePhase::TcpChained,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} chained entry connection timed out", entry.proto.as_str()),
                ),
            )),
        };

    match chained_res {
        Ok(stream) => {
            record_route_phase(RoutePhase::TcpChained, entry, "status=recovered_via_chained");
            Ok(stream)
        }
        Err(pe) => {
            record_route_phase(pe.phase, entry, &format!("err={}", pe.err));
            Err(pe.err)
        }
    }
}
