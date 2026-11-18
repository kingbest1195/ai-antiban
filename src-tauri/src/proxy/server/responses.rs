use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

pub(super) const KILLSWITCH_MESSAGE: &str = "Сеть остановлена вручную";

/// Completes when the manual kill-switch is (or becomes) engaged. Lowering the flag later does
/// not matter: the caller has already dropped its connection.
pub(super) async fn killswitch_engaged(rx: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

pub(super) fn killswitch_stopped() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "connection stopped by the manual kill-switch",
    )
}

pub(super) fn is_absolute_http_target(target: &str) -> bool {
    target
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("http://"))
}

/// A peer that went away mid-transfer is the normal end of a transit connection, not an error.
pub(super) fn is_peer_gone(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

pub(super) async fn send_gateway_info(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\nConnection: close\r\n\r\nZastava Gateway Active\n";
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

pub(super) async fn send_status(
    client: &mut TcpStream,
    status: &str,
    reason: &str,
) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reason}",
        reason.len(),
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

pub(super) async fn send_bad_gateway(client: &mut TcpStream, reason: &str) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reason.len(),
        reason
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

pub(super) async fn send_routing_changed(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let reason =
        "Zastava routing for this service changed while the connection was being set up: retry.";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reason.len(),
        reason
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

pub(super) async fn send_canary_intercepted(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let resp = "HTTP/1.1 503 Service Unavailable\r\nX-Zastava-Status: INTERCEPTED_BY_KILLSWITCH\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

pub(super) async fn send_canary_protected(client: &mut TcpStream) -> Result<(), std::io::Error> {
    let resp = "HTTP/1.1 200 OK\r\nX-Zastava-Status: PROTECTED\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    client.write_all(resp.as_bytes()).await?;
    client.flush().await
}

pub(super) async fn send_forbidden(client: &mut TcpStream, reason: &str) -> Result<(), std::io::Error> {
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reason.len(),
        reason
    );
    client.write_all(resp.as_bytes()).await?;
    client.flush().await?;
    Ok(())
}
