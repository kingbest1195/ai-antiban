use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::Journal;
use crate::sysproxy::platform::ServiceId;
use std::path::Path;
use std::sync::Arc;


pub(super) const DIR: &str = "/data";

pub(super) fn open(fs: &FakeFs) -> Journal {
    Journal::open(Arc::new(fs.clone()), Path::new(DIR)).unwrap()
}
pub(super) fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}
pub(super) fn env_res(name: &str) -> Resource {
    Resource::UserEnv { name: name.into() }
}
pub(super) fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}


mod restore_tests;
mod migration_tests;
mod vpn_tests;
