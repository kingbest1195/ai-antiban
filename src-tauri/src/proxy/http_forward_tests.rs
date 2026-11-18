use super::*;
use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

fn head(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn parses_absolute_get_and_rewrites_to_origin_form() {
    let raw = "GET http://Example.ORG:8080/a/b?x=1&y=%20 HTTP/1.1\r\nHost: wrong.example\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n";
    let r = parse_request(raw.as_bytes()).unwrap();
    assert_eq!((r.host.as_str(), r.port), ("example.org", 8080));
    assert_eq!(r.path, "/a/b?x=1&y=%20");
    assert_eq!(r.body, BodyKind::None);
    let out = String::from_utf8(r.build_head(RequestForm::Origin)).unwrap();
    assert!(
        out.starts_with("GET /a/b?x=1&y=%20 HTTP/1.1\r\nHost: example.org:8080\r\n"),
        "{out}"
    );
    assert!(out.contains("User-Agent: curl/8\r\n"));
    assert!(!out.contains("wrong.example"));
    assert!(out.ends_with("Connection: close\r\n\r\n"));
}

#[test]
fn default_port_is_left_out_of_host_and_path_defaults_to_slash() {
    let r = parse_request(&head("GET http://example.org HTTP/1.1\r\n\r\n")).unwrap();
    assert_eq!(r.port, 80);
    assert_eq!(r.path, "/");
    assert_eq!(r.host_header(), "example.org");
    let r = parse_request(&head("GET http://example.org?q=1 HTTP/1.1\r\n\r\n")).unwrap();
    assert_eq!(r.path, "/?q=1");
    let r = parse_request(&head("GET http://[2606:2800::1]:80/x HTTP/1.1\r\n\r\n")).unwrap();
    assert_eq!(r.host, "2606:2800::1");
    assert_eq!(r.host_header(), "[2606:2800::1]");
}

#[test]
fn userinfo_and_fragment_are_dropped_and_trailing_dot_normalized() {
    let r = parse_request(&head(
        "GET http://user:pw@Example.org./p#frag HTTP/1.1\r\n\r\n",
    ))
    .unwrap();
    assert_eq!(r.host, "example.org");
    assert_eq!(r.path, "/p");
    let out = String::from_utf8(r.build_head(RequestForm::Origin)).unwrap();
    assert!(!out.contains("pw") && !out.contains("frag"));
}

#[test]
fn hop_by_hop_headers_and_connection_tokens_are_removed() {
    let raw = "GET http://example.org/ HTTP/1.1\r\n\
Host: example.org\r\n\
Connection: keep-alive, X-Secret-Hop\r\n\
Proxy-Connection: keep-alive\r\n\
Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\
Keep-Alive: timeout=5\r\n\
TE: trailers\r\n\
Trailer: X-Foo\r\n\
Upgrade: websocket\r\n\
X-Secret-Hop: 1\r\n\
X-Keep: yes\r\n\
\r\n";
    let r = parse_request(raw.as_bytes()).unwrap();
    let out = String::from_utf8(r.build_head(RequestForm::Origin))
        .unwrap()
        .to_ascii_lowercase();
    for gone in [
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "te:",
        "trailer:",
        "upgrade",
        "x-secret-hop",
        "zm9v",
    ] {
        assert!(!out.contains(gone), "{gone} leaked: {out}");
    }
    assert!(out.contains("x-keep: yes"));
    assert_eq!(out.matches("connection:").count(), 1);
    assert!(out.contains("connection: close"));
}

#[test]
fn framing_is_determined_and_reemitted() {
    let r = parse_request(&head(
        "POST http://example.org/u HTTP/1.1\r\nContent-Length:  12 \r\n\r\n",
    ))
    .unwrap();
    assert_eq!(r.body, BodyKind::Length(12));
    assert!(
        String::from_utf8(r.build_head(RequestForm::Origin))
            .unwrap()
            .contains("Content-Length: 12\r\n")
    );

    let r = parse_request(&head(
        "POST http://example.org/u HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n",
    ))
    .unwrap();
    assert_eq!(r.body, BodyKind::Chunked);
    assert!(
        String::from_utf8(r.build_head(RequestForm::Origin))
            .unwrap()
            .contains("Transfer-Encoding: chunked\r\n")
    );

    let r = parse_request(&head(
        "POST http://example.org/u HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    ))
    .unwrap();
    assert_eq!(r.body, BodyKind::None);
}

#[test]
fn absolute_form_for_chained_proxy_keeps_the_full_uri() {
    let r = parse_request(&head("GET http://example.org:8080/p?q=1 HTTP/1.1\r\n\r\n")).unwrap();
    let out = String::from_utf8(r.build_head(RequestForm::Absolute)).unwrap();
    assert!(out.starts_with(
        "GET http://example.org:8080/p?q=1 HTTP/1.1\r\nHost: example.org:8080\r\n"
    ));
}

#[test]
fn smuggling_shapes_and_garbage_are_refused() {
    let bad = [
        "POST http://e.org/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST http://e.org/ HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
        "POST http://e.org/ HTTP/1.1\r\nContent-Length: +3\r\n\r\n",
        "POST http://e.org/ HTTP/1.1\r\nContent-Length: 3, 3\r\n\r\n",
        "GET http://e.org/ HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n",
        "GET http://e.org/ HTTP/1.1\r\nBad Name: 1\r\n\r\n",
        "GET http://e.org/ HTTP/1.1\r\nHost : e.org\r\n\r\n",
        "GET ftp://e.org/ HTTP/1.1\r\n\r\n",
        "GET /relative HTTP/1.1\r\n\r\n",
        "GET http://e.org:0/ HTTP/1.1\r\n\r\n",
        "GET http://e.org:99999/ HTTP/1.1\r\n\r\n",
        "GET http:///path HTTP/1.1\r\n\r\n",
        "GET http://::1/ HTTP/1.1\r\n\r\n",
        "GET http://e.org/ HTTP/1.1 extra\r\n\r\n",
        "CONNECT http://e.org/ HTTP/1.1\r\n\r\n",
        "GET http://e.org/ HTTP/1.1\r\nX: a\r\n",
    ];
    for raw in bad {
        assert!(parse_request(raw.as_bytes()).is_err(), "accepted: {raw:?}");
    }
    assert!(matches!(
        parse_request(&head("GET http://e.org/ HTTP/2.0\r\n\r\n")),
        Err(HeadError::Unsupported(_))
    ));
    assert!(matches!(
        parse_request(&head(
            "POST http://e.org/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        )),
        Err(HeadError::Unsupported(_))
    ));
}

#[test]
fn head_end_is_found() {
    assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
    assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
}

#[test]
fn authority_splitting() {
    assert_eq!(split_authority("a.b"), Some(("a.b".into(), None)));
    assert_eq!(split_authority("a.b:81"), Some(("a.b".into(), Some(81))));
    assert_eq!(
        split_authority("[::1]:8899"),
        Some(("::1".into(), Some(8899)))
    );
    assert_eq!(split_authority("u@A.B."), Some(("a.b".into(), None)));
    assert_eq!(split_authority(""), None);
    assert_eq!(split_authority("a b"), None);
}

#[test]
fn chunked_tracker_finds_the_end_and_ignores_what_follows() {
    let msg = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: v\r\n\r\nGET /next";
    let mut t = ChunkedTracker::new();
    let end = t.feed(msg).unwrap().unwrap();
    assert_eq!(&msg[end..], b"GET /next");
    assert!(t.is_done());
}

#[test]
fn chunked_tracker_works_byte_by_byte() {
    let msg = b"A\r\n0123456789\r\n1\r\nx\r\n0\r\n\r\n";
    let mut t = ChunkedTracker::new();
    for (i, b) in msg.iter().enumerate() {
        let r = t.feed(std::slice::from_ref(b)).unwrap();
        if i + 1 == msg.len() {
            assert_eq!(r, Some(1));
        } else {
            assert_eq!(r, None, "ended early at {i}");
        }
    }
}

#[test]
fn chunked_tracker_rejects_broken_framing() {
    for bad in [
        &b"zz\r\n"[..],
        b"\r\n",
        b"3\r\nabcXX",
        b"fffffffffffffffff\r\n",
    ] {
        assert!(ChunkedTracker::new().feed(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn content_length_body_is_copied_exactly_with_prefix() {
    let (mut client_side, mut test_client) = tokio::io::duplex(1024);
    let (mut up_a, mut up_b) = tokio::io::duplex(1024);
    let kind = BodyKind::Length(10);
    let task = tokio::spawn(async move {
        relay_request_body(&kind, b"01234", &mut client_side, &mut up_a).await
    });
    test_client.write_all(b"56789EXTRA").await.unwrap();
    task.await.unwrap().unwrap();
    let mut got = vec![0u8; 10];
    up_b.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"0123456789");
}

#[tokio::test]
async fn content_length_body_fails_when_the_client_disappears() {
    let (mut client_side, test_client) = tokio::io::duplex(64);
    let (mut up_a, _up_b) = tokio::io::duplex(64);
    drop(test_client);
    let err = relay_request_body(&BodyKind::Length(5), b"ab", &mut client_side, &mut up_a)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn chunked_body_is_copied_raw_up_to_the_last_chunk() {
    let (mut client_side, mut test_client) = tokio::io::duplex(1024);
    let (mut up_a, mut up_b) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        relay_request_body(&BodyKind::Chunked, b"3\r\nab", &mut client_side, &mut up_a).await
    });
    test_client
        .write_all(b"c\r\n0\r\n\r\nLEFTOVER")
        .await
        .unwrap();
    task.await.unwrap().unwrap();
    let mut got = vec![0u8; 13];
    up_b.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"3\r\nabc\r\n0\r\n\r\n");
}

#[tokio::test(start_paused = true)]
async fn silent_exchange_times_out_but_activity_extends_the_deadline() {
    let idle = Duration::from_secs(60);
    // Upstream never answers and never closes.
    let (mut client_side, _test_client) = tokio::io::duplex(1024);
    let (mut up_side, _test_up) = tokio::io::duplex(1024);
    let started = Instant::now();
    let err = relay_exchange(&mut client_side, &mut up_side, &BodyKind::None, b"", idle)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= idle && started.elapsed() < idle + Duration::from_secs(1));

    // A byte every 40 s keeps it alive past 60 s; then the upstream goes quiet.
    let (mut client_side, mut test_client) = tokio::io::duplex(1024);
    let (mut up_side, mut test_up) = tokio::io::duplex(1024);
    let feeder = tokio::spawn(async move {
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(40)).await;
            test_up.write_all(b"x").await.unwrap();
        }
        std::future::pending::<()>().await;
    });
    let started = Instant::now();
    let err = relay_exchange(&mut client_side, &mut up_side, &BodyKind::None, b"", idle)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(
        started.elapsed() >= Duration::from_secs(180),
        "{:?}",
        started.elapsed()
    );
    let mut got = [0u8; 3];
    test_client.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"xxx");
    feeder.abort();
}
