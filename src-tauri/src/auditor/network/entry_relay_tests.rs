use super::*;
use crate::routing::EntryProto;

fn mk_entry(host: &str, port: u16) -> Entry {
    Entry {
        proto: EntryProto::Socks5,
        host: host.into(),
        port,
        username: None,
        password: None,
        sni: None,
    }
}

#[test]
fn same_target_normalizes_loopback_aliases() {
    assert!(same_target_as_chained(
        &mk_entry("localhost", 1080),
        "127.0.0.1",
        1080
    ));
    assert!(same_target_as_chained(
        &mk_entry("127.0.0.1", 1080),
        "localhost",
        1080
    ));
    assert!(same_target_as_chained(
        &mk_entry("::1", 1080),
        "localhost",
        1080
    ));
    assert!(!same_target_as_chained(
        &mk_entry("localhost", 1080),
        "127.0.0.1",
        1081
    ));
    assert!(!same_target_as_chained(
        &mk_entry("1.2.3.4", 1080),
        "127.0.0.1",
        1080
    ));
}

#[tokio::test]
async fn spawn_entry_relay_accepts_ip_literal_https_entry() {
    let entry = Entry {
        proto: EntryProto::Https,
        host: "1.1.1.1".into(),
        port: 443,
        username: None,
        password: None,
        sni: None,
    };
    let res = spawn_entry_relay(&entry, "http://127.0.0.1:18080", false, 0)
        .await
        .expect("relay spawn should not reject public IP literal HTTPS entry");
    assert!(res.is_some(), "§7.5: IP-literal EntryProto::Https must use entry_relay instead of skipping");
}

#[tokio::test]
async fn entry_relay_connects_through_http_chained_proxy_and_preserves_prefixed_bytes() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Mock chained HTTP CONNECT proxy that sends 200 + pipelined payload in a single TCP segment.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut req = [0u8; 512];
            let _ = s.read(&mut req).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nPIPELINED_OK")
                .await;
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
            }
        }
    });

    // Unreachable direct port forces connect_hedged to win via chained proxy.
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead);

    let entry = mk_entry("127.0.0.1", dead_port);
    let relay_addr = spawn_entry_relay(
        &entry,
        &format!("http://127.0.0.1:{}", cp_addr.port()),
        true,
        0,
    )
    .await
    .unwrap()
    .expect("relay must bind");

    let mut client = TcpStream::connect(relay_addr).await.unwrap();
    let mut head = [0u8; 12];
    client.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"PIPELINED_OK");
    client.write_all(b"PING").await.unwrap();
    let mut pong = [0u8; 4];
    client.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"PING");
}
