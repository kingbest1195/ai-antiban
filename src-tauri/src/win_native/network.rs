//! Native Win32 network adapter, DNS, and TCP owner-PID table APIs (`iphlpapi.dll`).

use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterInfo {
    pub friendly_name: String,
    pub description: String,
    pub adapter_name: String,
    pub is_up: bool,
    pub if_type: u32,
    pub ipv4_addrs: Vec<String>,
    pub ipv6_addrs: Vec<String>,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkParamsInfo {
    pub host_name: String,
    pub domain_name: String,
    pub dns_servers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOwnerRow {
    pub state: u32,
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub owning_pid: u32,
}

#[cfg(target_os = "windows")]
mod win {
    use super::{AdapterInfo, NetworkParamsInfo, TcpOwnerRow};
    use crate::win_native::{ipv4_from_win32_u32, port_from_win32_u32};
    use core::ffi::{CStr, c_void};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        FIXED_INFO_W2KSP1, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, GetExtendedTcpTable,
        GetNetworkParams, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
        IP_ADAPTER_UNICAST_ADDRESS_LH, IP_ADDR_STRING, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };
    use windows::core::{PSTR, PWSTR};

    unsafe fn pwstr_to_string(p: PWSTR) -> String {
        if p.0.is_null() {
            return String::new();
        }
        // SAFETY: Caller guarantees `p` is a valid NUL-terminated UTF-16 string from Win32 API.
        unsafe { p.to_string().unwrap_or_default() }
    }

    unsafe fn pstr_to_string(p: PSTR) -> String {
        if p.0.is_null() {
            return String::new();
        }
        // SAFETY: Caller guarantees `p` is a valid NUL-terminated ANSI string from Win32 API.
        unsafe { CStr::from_ptr(p.0.cast()) }
            .to_string_lossy()
            .into_owned()
    }

    fn c_char_buf_to_string(buf: &[i8]) -> String {
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    unsafe fn sockaddr_to_ip(sa: *const SOCKADDR, len: i32) -> Option<(bool, String)> {
        if sa.is_null() || len < core::mem::size_of::<u16>() as i32 {
            return None;
        }
        // SAFETY: `sa` has at least `size_of::<u16>()` bytes for `sa_family`.
        let family = unsafe { (*sa).sa_family };
        if family == AF_INET && len >= core::mem::size_of::<SOCKADDR_IN>() as i32 {
            // SAFETY: Length verified for `SOCKADDR_IN`.
            let sin = unsafe { &*(sa.cast::<SOCKADDR_IN>()) };
            // SAFETY: `S_addr` is a plain `u32` inside `IN_ADDR_0`.
            let raw = unsafe { sin.sin_addr.S_un.S_addr };
            return Some((false, Ipv4Addr::from(raw.to_ne_bytes()).to_string()));
        }
        if family == AF_INET6 && len >= core::mem::size_of::<SOCKADDR_IN6>() as i32 {
            // SAFETY: Length verified for `SOCKADDR_IN6`.
            let sin6 = unsafe { &*(sa.cast::<SOCKADDR_IN6>()) };
            // SAFETY: `Byte` is `[u8; 16]` inside `IN6_ADDR_0`.
            let bytes = unsafe { sin6.sin6_addr.u.Byte };
            return Some((true, Ipv6Addr::from(bytes).to_string()));
        }
        None
    }

    pub fn get_adapters_addresses() -> Result<Vec<AdapterInfo>, String> {
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            let word_count = (size as usize).div_ceil(core::mem::size_of::<u64>());
            let mut buf = vec![0u64; word_count];
            let ptr = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: `ptr` points to `size` writable bytes aligned to `u64`.
            let rc = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    Some(ptr),
                    &mut size,
                )
            };
            if rc == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if rc != ERROR_SUCCESS.0 {
                return Err(format!("GetAdaptersAddresses failed with Win32 error {rc}"));
            }
            let mut out = Vec::new();
            let mut cur = ptr as *const IP_ADAPTER_ADDRESSES_LH;
            while !cur.is_null() {
                // SAFETY: `cur` walks a valid Win32-populated linked list inside `buf`.
                let item = unsafe { &*cur };
                let mut ipv4_addrs = Vec::new();
                let mut ipv6_addrs = Vec::new();
                let mut ua: *const IP_ADAPTER_UNICAST_ADDRESS_LH =
                    item.FirstUnicastAddress.cast_const();
                while !ua.is_null() {
                    // SAFETY: Linked list node inside `buf`.
                    let u = unsafe { &*ua };
                    if let Some((is_v6, ip)) =
                        unsafe { sockaddr_to_ip(u.Address.lpSockaddr, u.Address.iSockaddrLength) }
                    {
                        if is_v6 {
                            ipv6_addrs.push(ip);
                        } else {
                            ipv4_addrs.push(ip);
                        }
                    }
                    ua = u.Next;
                }
                let mut dns_servers = Vec::new();
                let mut da: *const IP_ADAPTER_DNS_SERVER_ADDRESS_XP =
                    item.FirstDnsServerAddress.cast_const();
                while !da.is_null() {
                    // SAFETY: Linked list node inside `buf`.
                    let d = unsafe { &*da };
                    if let Some((_, ip)) =
                        unsafe { sockaddr_to_ip(d.Address.lpSockaddr, d.Address.iSockaddrLength) }
                    {
                        dns_servers.push(ip);
                    }
                    da = d.Next;
                }
                out.push(AdapterInfo {
                    friendly_name: unsafe { pwstr_to_string(item.FriendlyName) },
                    description: unsafe { pwstr_to_string(item.Description) },
                    adapter_name: unsafe { pstr_to_string(item.AdapterName) },
                    is_up: item.OperStatus.0 == IfOperStatusUp.0,
                    if_type: item.IfType,
                    ipv4_addrs,
                    ipv6_addrs,
                    dns_servers,
                });
                cur = item.Next;
            }
            return Ok(out);
        }
        Err("GetAdaptersAddresses buffer retry limit exceeded".to_string())
    }

    pub fn get_network_params() -> Result<NetworkParamsInfo, String> {
        let mut size: u32 = core::mem::size_of::<FIXED_INFO_W2KSP1>() as u32;
        for _ in 0..4 {
            let word_count = (size as usize).div_ceil(core::mem::size_of::<u64>());
            let mut buf = vec![0u64; word_count];
            let ptr = buf.as_mut_ptr().cast::<FIXED_INFO_W2KSP1>();
            // SAFETY: `ptr` points to `size` writable bytes aligned to `u64`.
            let rc = unsafe { GetNetworkParams(Some(ptr), &mut size) };
            if rc == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if rc != ERROR_SUCCESS {
                return Err(format!("GetNetworkParams failed with Win32 error {}", rc.0));
            }
            // SAFETY: `ptr` was populated by `GetNetworkParams`.
            let info = unsafe { &*ptr };
            let mut dns_servers = Vec::new();
            let mut cur: *const IP_ADDR_STRING = &raw const info.DnsServerList;
            while !cur.is_null() {
                // SAFETY: Linked list nodes reside inside `buf`.
                let node = unsafe { &*cur };
                let s = c_char_buf_to_string(&node.IpAddress.String);
                if !s.is_empty() {
                    dns_servers.push(s);
                }
                cur = node.Next;
            }
            return Ok(NetworkParamsInfo {
                host_name: c_char_buf_to_string(&info.HostName),
                domain_name: c_char_buf_to_string(&info.DomainName),
                dns_servers,
            });
        }
        Err("GetNetworkParams buffer retry limit exceeded".to_string())
    }

    pub fn get_extended_tcp_table_ipv4() -> Result<Vec<TcpOwnerRow>, String> {
        let mut size: u32 = 0;
        // SAFETY: Null pointer query fetches required table byte size.
        let rc = unsafe {
            GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER.0 && rc != ERROR_SUCCESS.0 {
            return Err(format!("GetExtendedTcpTable size query failed: {rc}"));
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        for _ in 0..4 {
            let word_count = (size as usize).div_ceil(core::mem::size_of::<u64>());
            let mut buf = vec![0u64; word_count];
            // SAFETY: `buf` is `size`+ bytes long and `u64`-aligned.
            let rc = unsafe {
                GetExtendedTcpTable(
                    Some(buf.as_mut_ptr().cast::<c_void>()),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if rc == ERROR_INSUFFICIENT_BUFFER.0 {
                continue;
            }
            if rc != ERROR_SUCCESS.0 {
                return Err(format!("GetExtendedTcpTable failed: {rc}"));
            }
            // SAFETY: `buf` starts with `MIB_TCPTABLE_OWNER_PID`.
            let table = unsafe { &*(buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>()) };
            let count = table.dwNumEntries as usize;
            // SAFETY: `GetExtendedTcpTable` wrote `dwNumEntries` rows into `table.table`.
            let rows = unsafe { core::slice::from_raw_parts(table.table.as_ptr(), count) };
            return Ok(rows
                .iter()
                .map(|r| TcpOwnerRow {
                    state: r.dwState,
                    local_ip: ipv4_from_win32_u32(r.dwLocalAddr),
                    local_port: port_from_win32_u32(r.dwLocalPort),
                    remote_ip: ipv4_from_win32_u32(r.dwRemoteAddr),
                    remote_port: port_from_win32_u32(r.dwRemotePort),
                    owning_pid: r.dwOwningPid,
                })
                .collect());
        }
        Err("GetExtendedTcpTable buffer retry limit exceeded".to_string())
    }
}

pub fn get_adapters_addresses() -> Result<Vec<AdapterInfo>, String> {
    #[cfg(target_os = "windows")]
    {
        win::get_adapters_addresses()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}

pub fn get_network_params() -> Result<NetworkParamsInfo, String> {
    #[cfg(target_os = "windows")]
    {
        win::get_network_params()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err("get_network_params is only supported on Windows".to_string())
    }
}

pub fn get_extended_tcp_table_ipv4() -> Result<Vec<TcpOwnerRow>, String> {
    #[cfg(target_os = "windows")]
    {
        win::get_extended_tcp_table_ipv4()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(Vec::new())
    }
}

pub fn find_pids_for_local_port(port: u16) -> Result<Vec<u32>, String> {
    let rows = get_extended_tcp_table_ipv4()?;
    let mut pids = Vec::new();
    for row in rows {
        if row.local_port == port && !pids.contains(&row.owning_pid) {
            pids.push(row.owning_pid);
        }
    }
    Ok(pids)
}

/// Formats native Win32 `GetNetworkParams` + `GetAdaptersAddresses` output into a line-oriented
/// DNS listing compatible with [`crate::auditor::leaks::evaluate_dns_listing`].
pub fn format_dns_listing(params: Option<&NetworkParamsInfo>, adapters: &[AdapterInfo]) -> String {
    let mut lines = Vec::new();
    if let Some(p) = params {
        if !p.domain_name.trim().is_empty() {
            lines.push(format!("Domain Name: {}", p.domain_name.trim()));
        }
        if !p.dns_servers.is_empty() {
            lines.push(format!("DNS Servers: {}", p.dns_servers.join(", ")));
        }
    }
    for a in adapters {
        if !a.is_up || a.dns_servers.is_empty() {
            continue;
        }
        let header = if a.description.trim().is_empty() {
            a.friendly_name.trim().to_string()
        } else {
            format!("{} ({})", a.friendly_name.trim(), a.description.trim())
        };
        lines.push(format!("Adapter {header}:"));
        lines.push(format!("  DNS Servers: {}", a.dns_servers.join(", ")));
    }
    lines.join("\n")
}
