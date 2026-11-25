//! Bidirectional tunnel relay, TLS backpressure flushing, and half-close drain handling.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::guard::{Gate, NetworkGuard, gate_closed, shutdown_aborted};
use crate::proxy::route_watch::RouteWatch;
use crate::proxy::upstream::UpstreamStream;

use super::TunnelPolicy;

const PENDING_GATE_GRACE_MS: u64 = 2500;
const RELAY_BUF_SIZE: usize = 64 * 1024;

/// Bidirectional relay that obeys the network guard. Direct tunnels (`FollowGate`): while the gate
/// is closed no byte is forwarded, allowing a brief `Gate::Pending` grace (up to 2500ms) while
/// immediately breaking on `Gate::Blocked`, `manual_killswitch`, or explicit `abort_rx`.
/// Routed tunnels (`KillSwitchOnly`) are only stopped by the manual kill-switch or shutdown.
/// Both end as soon as the routing of their provider changes (`watch`).
pub(super) async fn pump(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    guard: &Arc<NetworkGuard>,
    policy: TunnelPolicy,
    provider: Option<ProviderId>,
    watch: Option<RouteWatch>,
) -> Result<(), std::io::Error> {
    pump_with_drain(
        client,
        target,
        guard,
        policy,
        provider,
        watch,
        super::HALF_CLOSE_DRAIN_TIMEOUT,
    )
    .await
}

pub(super) async fn pump_with_drain(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    guard: &Arc<NetworkGuard>,
    policy: TunnelPolicy,
    provider: Option<ProviderId>,
    watch: Option<RouteWatch>,
    half_close_drain_timeout: Duration,
) -> Result<(), std::io::Error> {
    let relay = relay(
        client,
        target,
        guard,
        policy,
        provider,
        half_close_drain_timeout,
    );
    match watch {
        Some(mut w) => {
            tokio::select! {
                res = relay => res,
                _ = w.stale() => Err(tunnel_route_changed()),
            }
        }
        None => relay.await,
    }
}

async fn relay(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    guard: &Arc<NetworkGuard>,
    policy: TunnelPolicy,
    provider: Option<ProviderId>,
    half_close_drain_timeout: Duration,
) -> Result<(), std::io::Error> {
    // Never send TLS close_notify on outer HTTPS entry tunnel when client half-closes write side.
    let mut state = RelayState::new(!target.is_tls(), half_close_drain_timeout);
    match policy {
        TunnelPolicy::FollowGate => {
            relay_follow_gate(client, target, &mut state, guard, provider).await
        }
        TunnelPolicy::KillSwitchOnly => {
            relay_killswitch_only(client, target, &mut state, guard).await
        }
    }
}

fn tunnel_route_changed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "tunnel aborted: the routing of this service changed",
    )
}

pub(super) fn tunnel_stalled() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "tunnel aborted: network route changed or closed",
    )
}

enum CopyPoll {
    Pending,
    Finished,
    GatePending,
}

enum RelayStep {
    Finished,
    GatePending,
}

struct HalfRelay {
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
    read_done: bool,
    need_flush: bool,
    done: bool,
    shutdown_on_eof: bool,
}

impl HalfRelay {
    fn new(shutdown_on_eof: bool) -> Self {
        Self {
            buf: vec![0u8; RELAY_BUF_SIZE],
            pos: 0,
            cap: 0,
            read_done: false,
            need_flush: false,
            done: false,
            shutdown_on_eof,
        }
    }

    fn poll_copy<R, W, F>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
        made_progress: &mut bool,
        mut can_write: F,
    ) -> Result<CopyPoll, std::io::Error>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
        F: FnMut() -> Result<bool, std::io::Error>,
    {
        if self.done {
            return Ok(CopyPoll::Finished);
        }
        loop {
            if self.pos < self.cap {
                if !can_write()? {
                    return Ok(CopyPoll::GatePending);
                }
                while self.pos < self.cap {
                    match Pin::new(&mut *writer).poll_write(cx, &self.buf[self.pos..self.cap]) {
                        Poll::Ready(Ok(0)) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "write zero byte into tunnel writer",
                            ));
                        }
                        Poll::Ready(Ok(i)) => {
                            self.pos += i;
                            self.need_flush = true;
                            *made_progress = true;
                        }
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Pending => return Ok(CopyPoll::Pending),
                    }
                }
            }

            if self.need_flush {
                match Pin::new(&mut *writer).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        self.need_flush = false;
                    }
                    Poll::Ready(Err(e)) => return Err(e),
                    Poll::Pending => return Ok(CopyPoll::Pending),
                }
            }

            if self.read_done {
                if self.shutdown_on_eof {
                    match Pin::new(&mut *writer).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Err(e),
                        Poll::Pending => return Ok(CopyPoll::Pending),
                    }
                }
                self.done = true;
                return Ok(CopyPoll::Finished);
            }

            let mut read_buf = ReadBuf::new(&mut self.buf);
            match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        self.read_done = true;
                    } else {
                        self.pos = 0;
                        self.cap = n;
                        *made_progress = true;
                    }
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => {
                    if self.need_flush {
                        match Pin::new(&mut *writer).poll_flush(cx) {
                            Poll::Ready(Ok(())) => {
                                self.need_flush = false;
                            }
                            Poll::Ready(Err(e)) => return Err(e),
                            Poll::Pending => return Ok(CopyPoll::Pending),
                        }
                    }
                    return Ok(CopyPoll::Pending);
                }
            }
        }
    }
}

struct RelayState {
    c2t: HalfRelay,
    t2c: HalfRelay,
    half_closed: bool,
    drain_timeout: Duration,
    drain_sleep: Pin<Box<tokio::time::Sleep>>,
}

impl RelayState {
    fn new(shutdown_upstream_on_eof: bool, drain_timeout: Duration) -> Self {
        Self {
            c2t: HalfRelay::new(shutdown_upstream_on_eof),
            t2c: HalfRelay::new(true),
            half_closed: false,
            drain_timeout,
            drain_sleep: Box::pin(tokio::time::sleep(drain_timeout)),
        }
    }
}

async fn poll_bidirectional<F>(
    state: &mut RelayState,
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    mut can_write: F,
) -> Result<RelayStep, std::io::Error>
where
    F: FnMut() -> Result<bool, std::io::Error>,
{
    poll_fn(|cx| {
        let mut c2t_progress = false;
        let mut t2c_progress = false;

        let c2t_res = state
            .c2t
            .poll_copy(cx, client, target, &mut c2t_progress, &mut can_write)?;
        if matches!(c2t_res, CopyPoll::GatePending) {
            return Poll::Ready(Ok(RelayStep::GatePending));
        }
        let t2c_res = state
            .t2c
            .poll_copy(cx, target, client, &mut t2c_progress, &mut can_write)?;
        if matches!(t2c_res, CopyPoll::GatePending) {
            return Poll::Ready(Ok(RelayStep::GatePending));
        }

        if state.c2t.done && state.t2c.done {
            return Poll::Ready(Ok(RelayStep::Finished));
        }

        if state.c2t.done ^ state.t2c.done {
            let active_progressed = if state.c2t.done {
                t2c_progress
            } else {
                c2t_progress
            };
            if !state.half_closed || active_progressed {
                state.half_closed = true;
                state
                    .drain_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + state.drain_timeout);
            }
            if state.drain_sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(RelayStep::Finished));
            }
        }

        Poll::Pending
    })
    .await
}

async fn wait_pending_grace(
    rx: &mut watch::Receiver<Gate>,
    abort_rx: &mut watch::Receiver<u64>,
    kill_rx: &mut watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let wait_fut = async {
        loop {
            if *kill_rx.borrow_and_update() || abort_rx.has_changed().unwrap_or(false) {
                return Err(tunnel_stalled());
            }
            match *rx.borrow_and_update() {
                Gate::Open => return Ok(()),
                Gate::Blocked => return Err(tunnel_stalled()),
                Gate::Pending => {}
            }
            tokio::select! {
                res = rx.changed() => {
                    if res.is_err() {
                        return Err(tunnel_stalled());
                    }
                }
                _ = abort_rx.changed() => return Err(tunnel_stalled()),
                changed = kill_rx.changed() => {
                    if changed.is_err() || *kill_rx.borrow_and_update() {
                        return Err(tunnel_stalled());
                    }
                }
            }
        }
    };
    match tokio::time::timeout(Duration::from_millis(PENDING_GATE_GRACE_MS), wait_fut).await {
        Ok(res) => res,
        Err(_) => Err(tunnel_stalled()),
    }
}

async fn relay_follow_gate(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    state: &mut RelayState,
    guard: &Arc<NetworkGuard>,
    provider: Option<ProviderId>,
) -> Result<(), std::io::Error> {
    let mut rx = match provider {
        Some(p) => guard.subscribe_for(p),
        None => guard.subscribe(),
    };
    let mut abort_rx = guard.subscribe_tunnel_abort();
    let abort_check_rx = abort_rx.clone();
    let mut kill_rx = guard.subscribe_killswitch();

    loop {
        if *kill_rx.borrow_and_update()
            || guard.is_manual_killswitch()
            || abort_rx.has_changed().unwrap_or(false)
        {
            return Err(tunnel_stalled());
        }
        let gate = match provider {
            Some(p) => guard.gate_for(p),
            None => guard.gate(),
        };
        let rx_gate = *rx.borrow_and_update();
        if gate == Gate::Blocked || rx_gate == Gate::Blocked {
            return Err(tunnel_stalled());
        }
        if gate == Gate::Pending || rx_gate == Gate::Pending {
            wait_pending_grace(&mut rx, &mut abort_rx, &mut kill_rx).await?;
        }

        let step = tokio::select! {
            res = poll_bidirectional(state, client, target, || {
                let current_gate = match provider {
                    Some(p) => guard.gate_for(p),
                    None => guard.gate(),
                };
                if current_gate == Gate::Blocked
                    || guard.is_manual_killswitch()
                    || abort_check_rx.has_changed().unwrap_or(false)
                {
                    return Err(tunnel_stalled());
                }
                Ok(current_gate == Gate::Open)
            }) => Some(res?),
            _ = gate_closed(&mut rx) => {
                wait_pending_grace(&mut rx, &mut abort_rx, &mut kill_rx).await?;
                None
            }
            _ = abort_rx.changed() => return Err(tunnel_stalled()),
            changed = kill_rx.changed() => {
                if changed.is_err() || *kill_rx.borrow_and_update() {
                    return Err(tunnel_stalled());
                }
                None
            }
        };

        match step {
            Some(RelayStep::Finished) => return Ok(()),
            Some(RelayStep::GatePending) => {
                wait_pending_grace(&mut rx, &mut abort_rx, &mut kill_rx).await?;
            }
            None => {}
        }
    }
}

async fn relay_killswitch_only(
    client: &mut TcpStream,
    target: &mut UpstreamStream,
    state: &mut RelayState,
    guard: &Arc<NetworkGuard>,
) -> Result<(), std::io::Error> {
    let mut kill_rx = guard.subscribe_killswitch();
    let mut shutdown_rx = guard.subscribe_shutdown_abort();
    let shutdown_check_rx = shutdown_rx.clone();

    loop {
        if *kill_rx.borrow_and_update()
            || *shutdown_rx.borrow_and_update()
            || guard.is_manual_killswitch()
        {
            return Err(tunnel_stalled());
        }

        let step = tokio::select! {
            res = poll_bidirectional(state, client, target, || {
                if guard.is_manual_killswitch() || *shutdown_check_rx.borrow() {
                    Err(tunnel_stalled())
                } else {
                    Ok(true)
                }
            }) => Some(res?),
            changed = kill_rx.changed() => {
                if changed.is_err() || *kill_rx.borrow_and_update() {
                    return Err(tunnel_stalled());
                }
                None
            }
            _ = shutdown_aborted(&mut shutdown_rx) => return Err(tunnel_stalled()),
        };

        if matches!(step, Some(RelayStep::Finished)) {
            return Ok(());
        }
    }
}
