//! UDP datagram probe trait and tokio UDP socket implementation (STUN).

use std::time::Duration;

use super::BoxFuture;

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
