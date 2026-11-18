use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::platform::FakePlatform;


pub(super) const DIR: &str = "/data";

pub(super) fn setup() -> (FakeFs, FakePlatform) {
    (FakeFs::new(), FakePlatform::new())
}

pub(super) fn open(fs: &FakeFs) -> Result<Journal, JournalError> {
    Journal::open(Arc::new(fs.clone()), Path::new(DIR))
}

pub(super) fn jpath() -> PathBuf {
    Path::new(DIR).join(SUBDIR).join(JOURNAL_FILE)
}

pub(super) fn env(name: &str) -> Resource {
    Resource::UserEnv { name: name.into() }
}
pub(super) fn ev(s: &str) -> Value {
    Value::Env(Some(s.into()))
}
pub(super) fn wifi() -> ServiceId {
    ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
}
pub(super) fn pac_value(url: &str, on: bool) -> Value {
    Value::Pac(PacState {
        url: Some(url.into()),
        enabled: Some(on),
    })
}


mod baseline_tests;
mod crash_tests;
mod migration_tests;
