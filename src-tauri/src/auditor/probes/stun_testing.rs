//! Builders of STUN datagrams for tests (also used by the audit tests of `auditor`).

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
