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
            let leftover = http_connect_handshake(&mut tcp, entry, target_host, target_port)
                .await
                .map_err(|e| PhaseError::new(RoutePhase::Connect, e))?;
            Ok(UpstreamStream::Plain(tcp).with_prefix(leftover))
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
            let leftover = http_connect_handshake(&mut tls_stream, entry, target_host, target_port)
                .await
                .map_err(|e| PhaseError::new(RoutePhase::Connect, e))?;
            Ok(UpstreamStream::Tls(Box::new(tls_stream)).with_prefix(leftover))
        }
    }
}

fn record_route_phase(route_id: &str, phase: RoutePhase, entry: &Entry, note: &str) {
    let clean = sanitize_diagnostic_text(note);
    let status_tag = if note.starts_with("status=") {
        "ok"
    } else {
        "err"
    };
    let key = format!(
        "phase:{route_id}:{}:{}:{}",
        phase.as_str(),
        entry.endpoint(),
        status_tag
    );
    super::record_route_diag_throttled(
        &key,
        &format!(
            "route={route_id} phase={} proto={} endpoint={} {clean}",
            phase.as_str(),
            entry.proto.as_str(),
            entry.endpoint()
        ),
    );
}

const HEDGED_DIRECT_HEADSTART: Duration = Duration::from_millis(750);

#[allow(clippy::too_many_arguments)]
async fn connect_chained_attempt(
    cp: &str,
    entry: &Entry,
    target_host: &str,
    target_port: u16,
    budget: Duration,
    tls: &Arc<ClientConfig>,
    gateway_port: u16,
) -> Result<UpstreamStream, PhaseError> {
    match tokio::time::timeout(budget, async {
        let tcp = connect_entry_tcp_via_chained(cp, entry, budget, gateway_port)
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
                format!(
                    "{} chained entry connection timed out",
                    entry.proto.as_str()
                ),
            ),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn connect_entry_with(
    route_id: &str,
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

    let dns_rem = timeout.saturating_sub(started.elapsed());
    let dns_res = tokio::time::timeout(
        dns_rem,
        resolve_entry_checked(entry, allow_local, gateway_port),
    )
    .await;

    let direct_res: Result<UpstreamStream, PhaseError> = match dns_res {
        Ok(Ok(addrs)) => {
            resolved_addrs = Some(addrs.clone());
            let rem = timeout.saturating_sub(started.elapsed());
            if rem.is_zero() {
                Err(PhaseError::new(
                    RoutePhase::TcpDirect,
                    io::Error::new(io::ErrorKind::TimedOut, "entry connect budget exhausted"),
                ))
            } else if let Some(cp) = chained_proxy
                .filter(|cp| is_chained_eligible_for_entry(entry, Some(&addrs), gateway_port, cp))
            {
                let has_fake_ip = addrs
                    .iter()
                    .any(|a| crate::core::net_safety::is_tun_fake_ip(&a.ip()));
                let mut direct_fut = Box::pin(async {
                    match tokio::time::timeout(rem, async {
                        let tcp = super::handshakes::tcp_connect_addrs_with_v4_priority(
                            addrs,
                            rem,
                            has_fake_ip,
                        )
                        .await
                        .map_err(|e| PhaseError::new(RoutePhase::TcpDirect, e))?;
                        handshake_on_tcp(tcp, entry, target_host, target_port, tls).await
                    })
                    .await
                    {
                        Ok(res) => res,
                        Err(_) => Err(PhaseError::new(
                            RoutePhase::TcpDirect,
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "{} direct entry connection timed out",
                                    entry.proto.as_str()
                                ),
                            ),
                        )),
                    }
                });

                let headstart = if has_fake_ip {
                    Duration::ZERO
                } else {
                    HEDGED_DIRECT_HEADSTART.min(rem)
                };
                match tokio::time::timeout(headstart, &mut direct_fut).await {
                    Ok(Ok(stream)) => return Ok(stream),
                    Ok(Err(pe)) => Err(pe),
                    Err(_) => {
                        let chain_rem = timeout.saturating_sub(started.elapsed());
                        let mut chained_fut = Box::pin(connect_chained_attempt(
                            cp,
                            entry,
                            target_host,
                            target_port,
                            chain_rem,
                            tls,
                            gateway_port,
                        ));
                        tokio::select! {
                            d = &mut direct_fut => match d {
                                Ok(stream) => return Ok(stream),
                                Err(pe) => {
                                    record_route_phase(route_id, pe.phase, entry, &format!("err={}", pe.err));
                                    return match chained_fut.await {
                                        Ok(stream) => {
                                            record_route_phase(route_id, RoutePhase::TcpChained, entry, "status=recovered_via_chained");
                                            Ok(stream)
                                        }
                                        Err(cpe) => {
                                            record_route_phase(route_id, cpe.phase, entry, &format!("err={}", cpe.err));
                                            Err(cpe.err)
                                        }
                                    };
                                }
                            },
                            c = &mut chained_fut => match c {
                                Ok(stream) => {
                                    record_route_phase(route_id, RoutePhase::TcpChained, entry, "status=recovered_via_chained");
                                    return Ok(stream);
                                }
                                Err(cpe) => {
                                    record_route_phase(route_id, cpe.phase, entry, &format!("err={}", cpe.err));
                                    return direct_fut.await.map_err(|pe| {
                                        record_route_phase(route_id, pe.phase, entry, &format!("err={}", pe.err));
                                        pe.err
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                match tokio::time::timeout(rem, async {
                    let tcp = tcp_connect_addrs(addrs, rem)
                        .await
                        .map_err(|e| PhaseError::new(RoutePhase::TcpDirect, e))?;
                    handshake_on_tcp(tcp, entry, target_host, target_port, tls).await
                })
                .await
                {
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
        }
        Ok(Err(e)) => Err(PhaseError::new(RoutePhase::Dns, e)),
        Err(_) => Err(PhaseError::new(
            RoutePhase::Dns,
            io::Error::new(io::ErrorKind::TimedOut, "entry DNS lookup timed out"),
        )),
    };

    let (direct_phase, direct_err) = match direct_res {
        Ok(stream) => return Ok(stream),
        Err(pe) => {
            record_route_phase(route_id, pe.phase, entry, &format!("err={}", pe.err));
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
        record_route_phase(
            route_id,
            RoutePhase::TcpChained,
            entry,
            &format!("err={err}"),
        );
        return Err(err);
    }

    match connect_chained_attempt(cp, entry, target_host, target_port, rem, tls, gateway_port).await
    {
        Ok(stream) => {
            record_route_phase(
                route_id,
                RoutePhase::TcpChained,
                entry,
                "status=recovered_via_chained",
            );
            Ok(stream)
        }
        Err(pe) => {
            record_route_phase(route_id, pe.phase, entry, &format!("err={}", pe.err));
            Err(pe.err)
        }
    }
}
