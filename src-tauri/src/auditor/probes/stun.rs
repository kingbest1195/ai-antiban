//! UDP leak probe: a STUN Binding Request (RFC 5389) tells the public address a server sees for
//! UDP traffic of this machine. When it differs from the address HTTP traffic exits with, UDP
//! takes another way out than the tunnel.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::auditor::geo_matrix::{CheckResult, GUIDE_OS_PRIVACY, UnknownReason};
use crate::auditor::seams::{UdpOutcome, UdpProbe};

/// A STUN server: short name for `measured_via`, label for texts, `host:port`.
pub struct StunServer {
    pub id: &'static str,
    pub label: &'static str,
    pub addr: &'static str,
}

pub const SERVERS: [StunServer; 2] = [
    StunServer {
        id: "cloudflare",
        label: "Cloudflare",
        addr: "stun.cloudflare.com:3478",
    },
    StunServer {
        id: "google",
        label: "Google",
        addr: "stun.l.google.com:19302",
    },
];

/// Time limit of one STUN exchange (both servers are asked in parallel).
pub const STUN_TIMEOUT: Duration = Duration::from_millis(1500);

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const HEADER_LEN: usize = 20;

pub type TransactionId = [u8; 12];

/// A fresh random transaction id.
pub fn new_transaction_id() -> TransactionId {
    let mut id = [0u8; 12];
    id.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..12]);
    id
}

/// The 20 bytes of a Binding Request: type, length 0, magic cookie, transaction id.
pub fn build_binding_request(txid: &TransactionId) -> [u8; HEADER_LEN] {
    let mut msg = [0u8; HEADER_LEN];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Bytes 2..4: message length of the attributes (none).
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(txid);
    msg
}

/// The IPv4 address a Binding Success Response reports (`XOR-MAPPED-ADDRESS`, or the legacy
/// `MAPPED-ADDRESS` when there is none). `None` for anything that is not a well-formed success
/// response to the request with this transaction id (wrong type, cookie, transaction id, length,
/// no IPv4 address): such a datagram is not an answer.
pub fn parse_binding_response(data: &[u8], txid: &TransactionId) -> Option<Ipv4Addr> {
    if data.len() < HEADER_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let body_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if msg_type != BINDING_SUCCESS
        || cookie != MAGIC_COOKIE
        || &data[8..20] != txid
        || body_len % 4 != 0
        || HEADER_LEN + body_len > data.len()
    {
        return None;
    }

    let mut mapped = None;
    let mut xor_mapped = None;
    let mut rest = &data[HEADER_LEN..HEADER_LEN + body_len];
    while rest.len() >= 4 {
        let attr_type = u16::from_be_bytes([rest[0], rest[1]]);
        let attr_len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let padded = attr_len.div_ceil(4) * 4;
        if rest.len() < 4 + attr_len {
            return None;
        }
        let value = &rest[4..4 + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => xor_mapped = ipv4_attribute(value, true),
            ATTR_MAPPED_ADDRESS => mapped = ipv4_attribute(value, false),
            _ => {}
        }
        rest = rest.get(4 + padded..).unwrap_or(&[]);
    }
    xor_mapped.or(mapped)
}

/// Value of a (XOR-)MAPPED-ADDRESS attribute: reserved byte, family (1 = IPv4), port, address.
fn ipv4_attribute(value: &[u8], xored: bool) -> Option<Ipv4Addr> {
    if value.len() < 8 || value[1] != 0x01 {
        return None;
    }
    let mut octets = [value[4], value[5], value[6], value[7]];
    if xored {
        for (o, c) in octets.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
            *o ^= c;
        }
    }
    Some(Ipv4Addr::from(octets))
}

/// What one STUN server said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAnswer {
    Addr(Ipv4Addr),
    Timeout,
    /// The server name did not resolve or the socket failed.
    Failed,
}

/// One Binding Request to `server`.
pub async fn query_server(udp: &dyn UdpProbe, server: &str, limit: Duration) -> ServerAnswer {
    let txid = new_transaction_id();
    let request = build_binding_request(&txid);
    let accept = move |datagram: &[u8]| parse_binding_response(datagram, &txid).is_some();
    match udp.exchange(server, &request, &accept, limit).await {
        UdpOutcome::Reply(datagram) => match parse_binding_response(&datagram, &txid) {
            Some(ip) => ServerAnswer::Addr(ip),
            // The filter let it through, so this does not happen; a defect is not an answer.
            None => ServerAnswer::Failed,
        },
        UdpOutcome::Timeout => ServerAnswer::Timeout,
        UdpOutcome::Failed => ServerAnswer::Failed,
    }
}

/// The answers of both servers, in the order of [`SERVERS`].
pub async fn probe_servers(
    udp: &dyn UdpProbe,
    limit: Duration,
) -> Vec<(&'static StunServer, ServerAnswer)> {
    let (a, b) = tokio::join!(
        query_server(udp, SERVERS[0].addr, limit),
        query_server(udp, SERVERS[1].addr, limit)
    );
    vec![(&SERVERS[0], a), (&SERVERS[1], b)]
}

/// Verdict of the UDP check: the public address STUN servers see for UDP against the exit address
/// of HTTP traffic. A closed UDP is not a leak: without any answer the check is `Unknown`.
pub fn evaluate_udp_stun(
    answers: &[(&'static StunServer, ServerAnswer)],
    http_exit_ip: &str,
) -> CheckResult {
    let answered: Vec<(&StunServer, Ipv4Addr)> = answers
        .iter()
        .filter_map(|(s, a)| match a {
            ServerAnswer::Addr(ip) => Some((*s, *ip)),
            _ => None,
        })
        .collect();

    if answered.is_empty() {
        let (reason, why) = if answers.iter().any(|(_, a)| *a == ServerAnswer::Timeout) {
            (
                UnknownReason::Timeout,
                format!(
                    "ни один STUN-сервер не ответил за {} с",
                    STUN_TIMEOUT.as_secs_f32()
                ),
            )
        } else {
            (
                UnknownReason::NetworkError,
                "STUN-серверы недоступны (адрес не разрешился или сокет UDP не открылся)"
                    .to_string(),
            )
        };
        return CheckResult::unknown(
            "UDP_STUN_NO_RESPONSE",
            format!(
                "Проверка UDP не выполнена: {why}. Закрытый UDP не считается утечкой, но и идёт ли UDP мимо туннеля, не проверено."
            ),
            reason,
        );
    }

    let via = format!(
        "stun:{}",
        answered
            .iter()
            .map(|(s, _)| s.id)
            .collect::<Vec<_>>()
            .join("+")
    );
    let labels = answered
        .iter()
        .map(|(s, _)| s.label)
        .collect::<Vec<_>>()
        .join(" и ");

    let exit: IpAddr = match http_exit_ip.trim().parse() {
        Ok(ip) => ip,
        Err(_) => {
            return CheckResult::unknown(
                "UDP_STUN_NO_EXIT_IP",
                "Проверка UDP не выполнена: адрес HTTP-выхода неизвестен, UDP-адрес не с чем сравнить.",
                UnknownReason::NoData,
            )
            .with_measured_via(via);
        }
    };
    let IpAddr::V4(exit_v4) = exit else {
        return CheckResult::unknown(
            "UDP_STUN_EXIT_IPV6",
            "Проверка UDP не выполнена: HTTP выходит по IPv6, а UDP-проба идёт по IPv4, адреса сравнить нельзя.",
            UnknownReason::NoData,
        )
        .with_measured_via(via);
    };

    if let Some((server, udp_ip)) = answered.iter().find(|(_, ip)| *ip != exit_v4) {
        return CheckResult::warning(
            "UDP_STUN_MISMATCH",
            format!(
                "Внешний адрес по UDP ({udp_ip}, ответ {}) отличается от адреса HTTP-выхода ({exit_v4}): UDP-трафик выходит другим путём, возможно, мимо туннеля.",
                server.label
            ),
            Some(GUIDE_OS_PRIVACY.to_string()),
        )
        .with_measured_via(via);
    }

    CheckResult::ok(
        "UDP_STUN_MATCH",
        format!(
            "Внешний адрес по UDP ({exit_v4}, ответ {labels}) совпадает с адресом HTTP-выхода: UDP-проба вышла тем же путём. Проверена только эта проба, другие UDP-приложения не проверялись."
        ),
    )
    .with_measured_via(via)
}

/// Builders of STUN datagrams for tests (also used by the audit tests of `auditor`).
#[cfg(test)]
pub mod testing {
    use super::*;

    pub fn response(txid: &TransactionId, attrs: &[u8]) -> Vec<u8> {
        let mut m = vec![0x01, 0x01];
        m.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(txid);
        m.extend_from_slice(attrs);
        m
    }

    /// Attribute bytes of an XOR-MAPPED-ADDRESS (IPv4) for `ip`.
    pub fn xor_attr(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut a = vec![0x00, 0x20, 0x00, 0x08, 0x00, 0x01];
        a.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        for (o, c) in ip.octets().iter().zip(MAGIC_COOKIE.to_be_bytes()) {
            a.push(o ^ c);
        }
        a
    }

    pub fn mapped_attr(ip: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut a = vec![0x00, 0x01, 0x00, 0x08, 0x00, 0x01];
        a.extend_from_slice(&port.to_be_bytes());
        a.extend_from_slice(&ip.octets());
        a
    }

    /// A fake server that answers with `ip` (echoing the transaction id of the request).
    pub fn echoing(ip: Ipv4Addr) -> impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + Sync + 'static {
        move |req: &[u8]| {
            let mut txid = [0u8; 12];
            txid.copy_from_slice(&req[8..20]);
            vec![response(&txid, &xor_attr(ip, 5000))]
        }
    }
}

#[cfg(test)]
mod tests {
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
}
