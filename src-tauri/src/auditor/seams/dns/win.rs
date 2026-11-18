//! Windows `DnsQuery_W` native cache-bypassing DNS lookups.

use std::time::Duration;

pub(super) async fn windows_native_lookup<T: Send + 'static>(
    host: &str,
    limit: Duration,
    query: fn(&str) -> Option<T>,
) -> Option<T> {
    let host_fqdn = format!("{}.", host.trim_end_matches('.'));
    tokio::time::timeout(
        limit,
        tokio::task::spawn_blocking(move || query(&host_fqdn)),
    )
    .await
    .ok()
    .and_then(|res| res.ok())
    .flatten()
}

pub(super) mod win_dns {
    use super::super::{LookupOutcome, TxtOutcome};
    use core::ffi::c_void;
    use std::net::{IpAddr, Ipv4Addr};

    const DNS_TYPE_A: u16 = 0x0001;
    const DNS_TYPE_TEXT: u16 = 0x0010;
    const DNS_QUERY_BYPASS_CACHE: u32 = 0x0000_0008;
    const DNS_QUERY_TREAT_AS_FQDN: u32 = 0x0000_1000;
    const DNS_FREE_RECORD_LIST: i32 = 1;
    const DNS_ERROR_RCODE_NAME_ERROR: i32 = 9003;
    const DNS_INFO_NO_RECORDS: i32 = 9501;
    const ERROR_TIMEOUT: i32 = 1460;

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DnsAData {
        ip_address: u32,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DnsTxtDataW {
        dw_string_count: u32,
        p_string_array: [*const u16; 1],
    }

    #[repr(C)]
    union DnsRecordData {
        a: DnsAData,
        txt: DnsTxtDataW,
        _pad: [usize; 8],
    }

    #[repr(C)]
    struct DnsRecordW {
        p_next: *mut DnsRecordW,
        p_name: *const u16,
        w_type: u16,
        w_data_length: u16,
        flags: u32,
        dw_ttl: u32,
        dw_reserved: u32,
        data: DnsRecordData,
    }

    #[link(name = "dnsapi")]
    unsafe extern "system" {
        fn DnsQuery_W(
            psz_name: *const u16,
            w_type: u16,
            options: u32,
            p_extra: *mut c_void,
            pp_query_results: *mut *mut DnsRecordW,
            p_reserved: *mut c_void,
        ) -> i32;
        fn DnsRecordListFree(p_record_list: *mut c_void, free_type: i32);
    }

    unsafe fn utf16_ptr_to_string(ptr: *const u16) -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let mut len = 0usize;
        unsafe {
            while len < 4096 && *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr, len);
            Some(String::from_utf16_lossy(slice))
        }
    }

    enum QueryList {
        NotFound,
        Records(*mut DnsRecordW),
    }

    fn query_raw(host_fqdn: &str, record_type: u16) -> Option<QueryList> {
        let wide: Vec<u16> = host_fqdn
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        let mut head: *mut DnsRecordW = core::ptr::null_mut();
        let status = unsafe {
            DnsQuery_W(
                wide.as_ptr(),
                record_type,
                DNS_QUERY_BYPASS_CACHE | DNS_QUERY_TREAT_AS_FQDN,
                core::ptr::null_mut(),
                &mut head,
                core::ptr::null_mut(),
            )
        };
        if status == DNS_ERROR_RCODE_NAME_ERROR || status == DNS_INFO_NO_RECORDS {
            if !head.is_null() {
                unsafe { DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST) };
            }
            return Some(QueryList::NotFound);
        }
        if status == ERROR_TIMEOUT {
            if !head.is_null() {
                unsafe { DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST) };
            }
            return None;
        }
        if status != 0 || head.is_null() {
            if !head.is_null() {
                unsafe { DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST) };
            }
            crate::diagnostics::record(
                "auditor:dns",
                &format!("DnsQuery_W(type={record_type}) failed status={status}"),
            );
            return None;
        }
        Some(QueryList::Records(head))
    }

    pub fn query_a(host_fqdn: &str) -> Option<LookupOutcome> {
        let head = match query_raw(host_fqdn, DNS_TYPE_A)? {
            QueryList::NotFound => return Some(LookupOutcome::NotFound),
            QueryList::Records(h) => h,
        };
        let mut addrs = Vec::new();
        let mut cur: *const DnsRecordW = head;
        unsafe {
            while !cur.is_null() {
                let w_type = core::ptr::addr_of!((*cur).w_type).read();
                let next = core::ptr::addr_of!((*cur).p_next).read();
                if w_type == DNS_TYPE_A {
                    let ip_raw = core::ptr::addr_of!((*cur).data.a.ip_address).read();
                    addrs.push(IpAddr::V4(Ipv4Addr::from(ip_raw.to_ne_bytes())));
                }
                cur = next;
            }
            DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST);
        }
        if addrs.is_empty() {
            Some(LookupOutcome::NotFound)
        } else {
            Some(LookupOutcome::Addrs(addrs))
        }
    }

    pub fn query_txt(host_fqdn: &str) -> Option<TxtOutcome> {
        let head = match query_raw(host_fqdn, DNS_TYPE_TEXT)? {
            QueryList::NotFound => return Some(TxtOutcome::NotFound),
            QueryList::Records(h) => h,
        };

        let mut records = Vec::new();
        let mut cur: *const DnsRecordW = head;
        unsafe {
            while !cur.is_null() {
                // Read fields via raw pointers to avoid slice/union provenance over Windows' variable-length pStringArray.
                let w_type = core::ptr::addr_of!((*cur).w_type).read();
                let data_len = core::ptr::addr_of!((*cur).w_data_length).read() as usize;
                let next = core::ptr::addr_of!((*cur).p_next).read();
                if w_type == DNS_TYPE_TEXT {
                    let count =
                        core::ptr::addr_of!((*cur).data.txt.dw_string_count).read() as usize;
                    let header_bytes = core::mem::offset_of!(DnsTxtDataW, p_string_array);
                    let max_ptrs =
                        data_len.saturating_sub(header_bytes) / core::mem::size_of::<*const u16>();
                    let bounded_count = count.min(max_ptrs).min(64);
                    let arr_ptr =
                        core::ptr::addr_of!((*cur).data.txt.p_string_array).cast::<*const u16>();
                    let mut joined = String::new();
                    for i in 0..bounded_count {
                        if let Some(part) = utf16_ptr_to_string(*arr_ptr.add(i)) {
                            joined.push_str(&part);
                        }
                    }
                    if !joined.is_empty() {
                        records.push(joined);
                    }
                }
                cur = next;
            }
            DnsRecordListFree(head.cast(), DNS_FREE_RECORD_LIST);
        }
        if records.is_empty() {
            Some(TxtOutcome::NotFound)
        } else {
            Some(TxtOutcome::Records(records))
        }
    }
}
