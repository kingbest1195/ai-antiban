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

fn extract_answered(
    answers: &[(&'static StunServer, ServerAnswer)],
) -> Vec<(&'static StunServer, Ipv4Addr)> {
    answers
        .iter()
        .filter_map(|(s, a)| match a {
            ServerAnswer::Addr(ip) => Some((*s, *ip)),
            _ => None,
        })
        .collect()
}

fn format_via_and_labels(answered: &[(&'static StunServer, Ipv4Addr)]) -> (String, String) {
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
    (via, labels)
}

/// Evaluates UDP STUN results taking route isolation into account.
///
/// When `via_zastava_key` is true, AI traffic goes over TCP through the Zastava key (and
/// browser QUIC is disabled by policy), so a non-sanctioned foreign VPN UDP exit or blocked UDP
/// returns `Ok("UDP_KEY_TCP_PROTECTED")` instead of flagging an HTTP/UDP country mismatch.
pub fn evaluate_udp_stun_for_route(
    answers: &[(&'static StunServer, ServerAnswer)],
    http_exit_ip: &str,
    via_zastava_key: bool,
    udp_ip_country: Option<&str>,
) -> CheckResult {
    if !via_zastava_key {
        return evaluate_udp_stun(answers, http_exit_ip);
    }

    let answered = extract_answered(answers);
    if answered.is_empty() {
        return CheckResult::ok(
            "UDP_KEY_TCP_PROTECTED",
            "ВПН Заставы передаёт AI-трафик по TCP, а QUIC в браузерах отключён политикой Заставы; исходящий UDP заблокирован или недоступен, утечки локального IP РФ нет.",
        );
    }

    let (via, labels) = format_via_and_labels(&answered);
    let first_ip = answered[0].1;
    let sanctioned = udp_ip_country.is_some_and(crate::sanctions::is_sanctioned_or_blocked_country);
    if sanctioned {
        let cc = udp_ip_country.unwrap_or("??");
        return CheckResult::warning(
            "UDP_STUN_MISMATCH",
            format!(
                "По UDP виден адрес {first_ip} ({cc}, ответ {labels}), хотя HTTP-трафик AI идёт через ВПН Заставы ({http_exit_ip}). Включите зарубежный VPN для системного UDP-трафика."
            ),
            None,
        )
        .with_measured_via(via);
    }

    let cc_note = udp_ip_country
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();
    CheckResult::ok(
        "UDP_KEY_TCP_PROTECTED",
        format!(
            "ВПН Заставы передаёт AI-трафик по TCP (выход {http_exit_ip}), QUIC в браузерах отключён политикой Заставы. Системный UDP идёт через VPN-туннель ({first_ip}{cc_note}, ответ {labels}) без утечки локального IP РФ."
        ),
    )
    .with_measured_via(via)
}

/// Verdict of the UDP check: the public address STUN servers see for UDP against the exit address
/// of HTTP traffic. A closed UDP is not a leak: without any answer the check is `Unknown`.
pub fn evaluate_udp_stun(
    answers: &[(&'static StunServer, ServerAnswer)],
    http_exit_ip: &str,
) -> CheckResult {
    let answered = extract_answered(answers);

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

    let (via, labels) = format_via_and_labels(&answered);

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
#[path = "stun_testing.rs"]
pub mod testing;

#[cfg(test)]
#[path = "stun_tests.rs"]
mod tests;
