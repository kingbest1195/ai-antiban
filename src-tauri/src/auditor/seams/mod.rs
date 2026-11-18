//! Replaceable sources of the checks: DNS lookups, the HTTP probe and everything that reads the host.
//!
//! The audit never talks to the network or starts a process directly: it goes through these
//! traits, so a test can substitute a fake and run without network and without child processes.

mod dns;
mod probe;
mod system;
mod udp;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(crate) use dns::is_usable_nameserver;
#[cfg(any(target_os = "macos", test))]
#[allow(unused_imports)]
pub(crate) use dns::parse_scutil_dns_nameservers;
pub use dns::{DnsLookup, LookupOutcome, SystemDns, TxtOutcome};
#[cfg(test)]
use dns::is_name_not_found;
pub use probe::{HttpProbeOutcome, IpProbe, ReqwestProbe};
#[cfg(any(test, target_os = "windows"))]
pub use system::parse_reg_string_values;
#[cfg(test)]
use system::is_plain_zone_name;
pub use system::{
    RealSystem, SystemInfo, SystemReadError, is_global_unicast_v6, parse_defaults_values,
    parse_utc_offset,
};
pub use udp::{TokioUdp, UdpOutcome, UdpProbe};

#[cfg(test)]
use std::net::Ipv6Addr;
#[cfg(test)]
use std::time::Duration;

/// The sources an [`Auditor`](super::Auditor) works with.
#[derive(Clone)]
pub struct AuditEnv {
    pub dns: Arc<dyn DnsLookup>,
    pub probe: Arc<dyn IpProbe>,
    pub udp: Arc<dyn UdpProbe>,
    pub system: Arc<dyn SystemInfo>,
}

impl AuditEnv {
    /// DNS, HTTP and host of the machine the application runs on.
    pub fn real() -> Self {
        Self {
            dns: Arc::new(SystemDns),
            probe: Arc::new(ReqwestProbe),
            udp: Arc::new(TokioUdp),
            system: Arc::new(RealSystem),
        }
    }
}

#[cfg(test)]
#[path = "../seams_tests.rs"]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub mod fakes;
