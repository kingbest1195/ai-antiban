use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::{Journal, recover_with};
use crate::sysproxy::platform::FakePlatform;
use std::path::Path;
use std::sync::Arc;


pub(super) const DIR: &str = "/data";
pub(super) const PAC: &str = "http://127.0.0.1:8899/proxy.pac";

pub(super) fn open(fs: &FakeFs) -> Journal {
    Journal::open(Arc::new(fs.clone()), Path::new(DIR)).unwrap()
}
pub(super) fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}
pub(super) fn usb() -> ServiceId {
    ServiceId::new("en5", "USB 10/100 LAN", "USB LAN")
}
pub(super) fn setup() -> (FakeFs, FakePlatform) {
    let p = FakePlatform::new();
    p.add_service(wifi());
    (FakeFs::new(), p)
}
pub(super) fn pac(url: Option<&str>, on: Option<bool>) -> PacState {
    PacState {
        url: url.map(str::to_string),
        enabled: on,
    }
}
pub(super) fn ep(on: bool, host: &str, port: u16) -> ProxyEndpoint {
    ProxyEndpoint {
        enabled: Some(on),
        server: Some(host.into()),
        port: Some(port),
        authenticated: Some(false),
    }
}
pub(super) fn recover(fs: &FakeFs, p: &FakePlatform) {
    recover_with(Arc::new(fs.clone()), p, Path::new(DIR)).unwrap();
}
pub(super) fn touched(p: &FakePlatform, svc: &ServiceId) -> bool {
    let key = svc.key();
    p.calls().iter().any(|c| c.contains(&key))
}


mod proxy_tests;
mod vpn_tests;
