use super::testing::*;
use super::*;
use crate::auditor::geo_matrix::CheckStatus;
use crate::auditor::seams::fakes::FakeUdp;

/// Transaction id of the sample response of RFC 5769 section 2.2.
const RFC_TXID: TransactionId = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

/// `XOR-MAPPED-ADDRESS` of the same sample: 192.0.2.1, port 32853.
const RFC_XOR_ATTR: [u8; 12] = [
    0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
];

#[test]
fn binding_request_is_the_20_byte_rfc_5389_header() {
    let txid = [7u8; 12];
    let req = build_binding_request(&txid);
    assert_eq!(req.len(), 20);
    assert_eq!(&req[0..4], &[0x00, 0x01, 0x00, 0x00]);
    assert_eq!(&req[4..8], &[0x21, 0x12, 0xa4, 0x42]);
    assert_eq!(&req[8..20], &txid);
}

#[test]
fn transaction_ids_are_random() {
    assert_ne!(new_transaction_id(), new_transaction_id());
}

#[test]
fn rfc_5769_xor_mapped_address_is_decoded() {
    let msg = response(&RFC_TXID, &RFC_XOR_ATTR);
    assert_eq!(
        parse_binding_response(&msg, &RFC_TXID),
        Some(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn attributes_before_the_address_are_skipped_with_their_padding() {
    // SOFTWARE "test vector" (11 bytes, padded to 12) as in the RFC 5769 sample.
    let mut attrs = vec![0x80, 0x22, 0x00, 0x0b];
    attrs.extend_from_slice(b"test vector ");
    attrs.extend_from_slice(&RFC_XOR_ATTR);
    let msg = response(&RFC_TXID, &attrs);
    assert_eq!(
        parse_binding_response(&msg, &RFC_TXID),
        Some(Ipv4Addr::new(192, 0, 2, 1))
    );
}

#[test]
fn plain_mapped_address_is_the_fallback_and_xor_wins() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    let only_mapped = response(&RFC_TXID, &mapped_attr(ip, 4000));
    assert_eq!(parse_binding_response(&only_mapped, &RFC_TXID), Some(ip));
    // Both present (the plain one first): the XOR one is the answer.
    let mut both = mapped_attr(Ipv4Addr::new(10, 9, 9, 9), 1);
    both.extend_from_slice(&xor_attr(ip, 4000));
    assert_eq!(
        parse_binding_response(&response(&RFC_TXID, &both), &RFC_TXID),
        Some(ip)
    );
}

#[test]
fn answers_that_are_not_for_this_request_are_rejected() {
    let good = response(&RFC_TXID, &RFC_XOR_ATTR);
    // Another transaction id.
    assert_eq!(parse_binding_response(&good, &[1u8; 12]), None);
    // Binding Error Response (0x0111), wrong cookie, truncated, empty, noise.
    let mut error = good.clone();
    error[0..2].copy_from_slice(&[0x01, 0x11]);
    assert_eq!(parse_binding_response(&error, &RFC_TXID), None);
    let mut cookie = good.clone();
    cookie[4] = 0x00;
    assert_eq!(parse_binding_response(&cookie, &RFC_TXID), None);
    assert_eq!(
        parse_binding_response(&good[..good.len() - 2], &RFC_TXID),
        None
    );
    assert_eq!(parse_binding_response(&[], &RFC_TXID), None);
    assert_eq!(
        parse_binding_response(b"HTTP/1.1 200 OK\r\n\r\n", &RFC_TXID),
        None
    );
    // Length that is not a multiple of four.
    let mut odd = good.clone();
    odd[3] = 0x0b;
    assert_eq!(parse_binding_response(&odd, &RFC_TXID), None);
    // An attribute that claims more bytes than the message has.
    let mut long_attr = response(&RFC_TXID, &RFC_XOR_ATTR);
    long_attr[HEADER_LEN + 3] = 0x40;
    assert_eq!(parse_binding_response(&long_attr, &RFC_TXID), None);
    // A response without any address attribute.
    assert_eq!(
        parse_binding_response(&response(&RFC_TXID, &[]), &RFC_TXID),
        None
    );
    // IPv6 only: not an IPv4 answer.
    let mut v6 = vec![0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0x00, 0x00];
    v6.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        parse_binding_response(&response(&RFC_TXID, &v6), &RFC_TXID),
        None
    );
}

fn both(ip: Ipv4Addr) -> FakeUdp {
    FakeUdp::new()
        .with_server(SERVERS[0].addr, echoing(ip))
        .with_server(SERVERS[1].addr, echoing(ip))
}

async fn check(udp: &FakeUdp, exit: &str) -> CheckResult {
    evaluate_udp_stun(&probe_servers(udp, STUN_TIMEOUT).await, exit)
}

#[tokio::test]
async fn same_address_as_the_http_exit_is_ok() {
    let udp = both(Ipv4Addr::new(203, 0, 113, 9));
    let r = check(&udp, "203.0.113.9").await;
    assert_eq!(r.status, CheckStatus::Ok);
    assert_eq!(r.code, "UDP_STUN_MATCH");
    assert_eq!(r.measured_via.as_deref(), Some("stun:cloudflare+google"));
    assert_eq!(udp.calls(), 2);
}

#[tokio::test]
async fn another_address_than_the_http_exit_is_a_warning() {
    let udp = both(Ipv4Addr::new(198, 51, 100, 77));
    let r = check(&udp, "203.0.113.9").await;
    assert_eq!(r.status, CheckStatus::Warning);
    assert_eq!(r.code, "UDP_STUN_MISMATCH");
    assert!(r.message.contains("198.51.100.77") && r.message.contains("203.0.113.9"));
    assert!(
        r.message.contains("возможно"),
        "only a verifiable fact, hedged: {}",
        r.message
    );
    assert_eq!(r.measured_via.as_deref(), Some("stun:cloudflare+google"));
}

#[tokio::test]
async fn a_foreign_transaction_id_is_ignored_and_the_real_answer_still_counts() {
    let ip = Ipv4Addr::new(203, 0, 113, 9);
    // The first datagram is a forged answer (other transaction id, other address), then noise,
    // then the genuine one.
    let udp = FakeUdp::new().with_server(SERVERS[0].addr, move |req: &[u8]| {
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&req[8..20]);
        vec![
            response(&[9u8; 12], &xor_attr(Ipv4Addr::new(6, 6, 6, 6), 1)),
            b"garbage".to_vec(),
            response(&txid, &xor_attr(ip, 5000)),
        ]
    });
    let r = evaluate_udp_stun(&probe_servers(&udp, STUN_TIMEOUT).await, "203.0.113.9");
    assert_eq!(r.status, CheckStatus::Ok);
    // Only the server that really answered is named as the source.
    assert_eq!(r.measured_via.as_deref(), Some("stun:cloudflare"));
}

#[tokio::test]
async fn only_forged_or_garbage_answers_means_no_answer() {
    let udp = FakeUdp::new()
        .with_server(SERVERS[0].addr, |_: &[u8]| {
            vec![response(
                &[9u8; 12],
                &xor_attr(Ipv4Addr::new(6, 6, 6, 6), 1),
            )]
        })
        .with_server(SERVERS[1].addr, |_: &[u8]| vec![b"\x00\x01".to_vec()]);
    let r = check(&udp, "203.0.113.9").await;
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::Timeout))
    );
}

#[tokio::test]
async fn both_servers_silent_is_unknown_timeout_not_a_leak() {
    let r = check(&FakeUdp::new(), "203.0.113.9").await;
    assert_eq!(r.status, CheckStatus::Unknown);
    assert_eq!(r.reason, Some(UnknownReason::Timeout));
    assert_eq!(r.code, "UDP_STUN_NO_RESPONSE");
    assert!(r.measured_via.is_none());
    assert!(r.message.contains("не считается утечкой"));
}

#[tokio::test]
async fn unreachable_servers_are_a_network_error_unknown() {
    let udp = FakeUdp::new()
        .failing_server(SERVERS[0].addr)
        .failing_server(SERVERS[1].addr);
    let r = check(&udp, "203.0.113.9").await;
    assert_eq!(
        (r.status, r.reason),
        (CheckStatus::Unknown, Some(UnknownReason::NetworkError))
    );
}

#[tokio::test]
async fn one_silent_server_does_not_hide_the_answer_of_the_other() {
    let udp =
        FakeUdp::new().with_server(SERVERS[1].addr, echoing(Ipv4Addr::new(203, 0, 113, 9)));
    let ok = check(&udp, "203.0.113.9").await;
    assert_eq!(ok.status, CheckStatus::Ok);
    assert_eq!(ok.measured_via.as_deref(), Some("stun:google"));
    let leak = check(&udp, "192.0.2.5").await;
    assert_eq!(leak.status, CheckStatus::Warning);
}

#[tokio::test]
async fn two_servers_disagreeing_with_the_exit_in_any_way_is_a_warning() {
    let udp = FakeUdp::new()
        .with_server(SERVERS[0].addr, echoing(Ipv4Addr::new(203, 0, 113, 9)))
        .with_server(SERVERS[1].addr, echoing(Ipv4Addr::new(198, 51, 100, 1)));
    assert_eq!(
        check(&udp, "203.0.113.9").await.status,
        CheckStatus::Warning
    );
}

#[tokio::test]
async fn an_unusable_exit_address_cannot_be_compared() {
    let udp = both(Ipv4Addr::new(203, 0, 113, 9));
    for exit in ["", "not-an-ip"] {
        let r = check(&udp, exit).await;
        assert_eq!(
            (r.status, r.reason),
            (CheckStatus::Unknown, Some(UnknownReason::NoData)),
            "{exit:?}"
        );
        assert_eq!(r.code, "UDP_STUN_NO_EXIT_IP");
    }
    let r = check(&udp, "2001:db8::9").await;
    assert_eq!(
        (r.status, r.code.as_str()),
        (CheckStatus::Unknown, "UDP_STUN_EXIT_IPV6")
    );
}

// The real socket against a loopback "server" only: nothing leaves this machine.
#[tokio::test]
async fn real_socket_skips_noise_and_times_out_on_silence() {
    use crate::auditor::seams::TokioUdp;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        while let Ok((n, from)) = server.recv_from(&mut buf).await {
            let mut txid = [0u8; 12];
            txid.copy_from_slice(&buf[8..20]);
            assert_eq!(n, 20);
            let _ = server.send_to(b"noise", from).await;
            let _ = server
                .send_to(
                    &response(&[3u8; 12], &xor_attr(Ipv4Addr::new(6, 6, 6, 6), 1)),
                    from,
                )
                .await;
            let _ = server
                .send_to(
                    &response(&txid, &xor_attr(Ipv4Addr::new(192, 0, 2, 1), 40000)),
                    from,
                )
                .await;
        }
    });
    assert_eq!(
        query_server(&TokioUdp, &addr, Duration::from_secs(2)).await,
        ServerAnswer::Addr(Ipv4Addr::new(192, 0, 2, 1))
    );

    // A port with nobody behind it stays silent (or is refused): never an address.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap().to_string();
    let got = query_server(&TokioUdp, &silent_addr, Duration::from_millis(100)).await;
    assert_eq!(got, ServerAnswer::Timeout);
}

#[test]
fn route_via_zastava_key_allows_foreign_vpn_udp_or_blocked_udp_but_warns_on_ru() {
    let foreign_answers = [
        (
            &SERVERS[0],
            ServerAnswer::Addr(Ipv4Addr::new(145, 241, 193, 245)),
        ),
        (&SERVERS[1], ServerAnswer::Timeout),
    ];

    // Direct mode still flags HTTP (FR key) vs UDP (UK VPN) mismatch.
    let direct =
        evaluate_udp_stun_for_route(&foreign_answers, "136.244.114.42", false, Some("GB"));
    assert_eq!(direct.status, CheckStatus::Warning);
    assert_eq!(direct.code, "UDP_STUN_MISMATCH");

    // Bound Zastava key treats foreign VPN UDP as TCP-protected OK.
    let routed_ok =
        evaluate_udp_stun_for_route(&foreign_answers, "136.244.114.42", true, Some("GB"));
    assert_eq!(routed_ok.status, CheckStatus::Ok);
    assert_eq!(routed_ok.code, "UDP_KEY_TCP_PROTECTED");

    // Empty/blocked STUN under Zastava key is also OK (no UDP leak).
    let blocked_answers = [
        (&SERVERS[0], ServerAnswer::Timeout),
        (&SERVERS[1], ServerAnswer::Timeout),
    ];
    let routed_blocked =
        evaluate_udp_stun_for_route(&blocked_answers, "136.244.114.42", true, None);
    assert_eq!(routed_blocked.status, CheckStatus::Ok);
    assert_eq!(routed_blocked.code, "UDP_KEY_TCP_PROTECTED");

    // Sanctioned UDP country (e.g. RU) still produces Warning even with Zastava key.
    let ru_answers = [(&SERVERS[0], ServerAnswer::Addr(Ipv4Addr::new(5, 8, 8, 8)))];
    let routed_ru =
        evaluate_udp_stun_for_route(&ru_answers, "136.244.114.42", true, Some("RU"));
    assert_eq!(routed_ru.status, CheckStatus::Warning);
    assert_eq!(routed_ru.code, "UDP_STUN_MISMATCH");
}
