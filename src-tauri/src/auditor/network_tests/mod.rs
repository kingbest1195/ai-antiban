use super::*;


pub(super) async fn spawn_http_mock(
    status: &'static str,
    content_type: &'static str,
    body: &'static str,
    delay: Duration,
) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    format!("http://127.0.0.1:{}/cdn-cgi/trace", addr.port())
}


mod client_tests;
mod probe_tests;
