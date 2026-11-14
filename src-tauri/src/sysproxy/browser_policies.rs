//! Journaled browser QUIC / DoH policies so AI traffic cannot bypass the local PAC proxy.
//!
//! Browsers (Chrome, Edge, Brave, Firefox) increasingly enable HTTP/3 (QUIC over UDP 443) and
//! DNS-over-HTTPS by default, which bypasses TCP HTTP PAC proxies (`127.0.0.1:8899`). When Zastava's
//! system proxy is active, we apply minimal per-user policy overrides through the ownership
//! [`Journal`] so every prior setting (or absence) is faithfully restored on disable, quit, or
//! crash recovery.
//!
//! Host access goes strictly through [`os_effects_enabled`] + [`note_dry_run_blocked`], and uses
//! `crate::win_reg` on Windows (never spawning `reg.exe`) or gated `defaults` on macOS (only for
//! browsers installed or already present in `~/Library/Preferences`).

use super::journal::{ApplyOutcome, Journal, JournalError, Resource, Value};
use super::platform::{PResult, Platform, PlatformError};
use super::{note_dry_run_blocked, os_effects_enabled};
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "test-support"))]
use std::collections::BTreeMap;
use std::fmt;
#[cfg(any(test, feature = "test-support"))]
use std::sync::{Arc, Mutex};

/// Typed policy value persisted in the ownership journal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PolicyValue {
    Bool(bool),
    Dword(u32),
    Sz(String),
}

impl fmt::Debug for PolicyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyValue::Bool(b) => write!(f, "Bool({b})"),
            PolicyValue::Dword(n) => write!(f, "Dword({n})"),
            PolicyValue::Sz(_) => write!(f, "Sz(<redacted>)"),
        }
    }
}

/// One browser policy key/value desired while Zastava system protection is active.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PolicySpec {
    pub domain: String,
    pub key: String,
    pub value: PolicyValue,
}

impl PolicySpec {
    pub fn new(domain: impl Into<String>, key: impl Into<String>, value: PolicyValue) -> Self {
        Self {
            domain: domain.into(),
            key: key.into(),
            value,
        }
    }
}

/// Abstraction over OS browser policy storage so tests run without touching real host prefs.
pub trait PolicyStore: Send + Sync {
    /// Whether this domain exists on the host (e.g. installed macOS app / existing plist).
    /// Restores bypass this check so any previously journaled entry is always cleaned up.
    fn is_domain_applicable(&self, domain: &str) -> bool;
    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>>;
    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()>;
    fn delete(&self, domain: &str, key: &str) -> PResult<()>;
}

/// Returns the platform-appropriate Chromium/Firefox QUIC & DoH policy specs.
pub fn default_policy_specs() -> Vec<PolicySpec> {
    #[cfg(target_os = "windows")]
    {
        let mut specs = Vec::new();
        for subkey in [
            r"Software\Policies\Google\Chrome",
            r"Software\Policies\Microsoft\Edge",
            r"Software\Policies\BraveSoftware\Brave",
        ] {
            specs.push(PolicySpec::new(subkey, "QuicAllowed", PolicyValue::Dword(0)));
            specs.push(PolicySpec::new(
                subkey,
                "DnsOverHttpsMode",
                PolicyValue::Sz("off".to_string()),
            ));
        }
        specs.push(PolicySpec::new(
            r"Software\Policies\Mozilla\Firefox\DNSOverHTTPS",
            "Enabled",
            PolicyValue::Dword(0),
        ));
        specs
    }
    #[cfg(target_os = "macos")]
    {
        let mut specs = Vec::new();
        for domain in [
            "com.google.Chrome",
            "com.microsoft.Edge",
            "com.brave.Browser",
        ] {
            specs.push(PolicySpec::new(
                domain,
                "QuicAllowed",
                PolicyValue::Bool(false),
            ));
            specs.push(PolicySpec::new(
                domain,
                "DnsOverHttpsMode",
                PolicyValue::Sz("off".to_string()),
            ));
        }
        specs
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Production [`PolicyStore`] backed by `crate::win_reg` on Windows and `defaults` on macOS.
pub struct RealPolicyStore;

#[cfg(target_os = "macos")]
fn macos_app_bundle_for_domain(domain: &str) -> Option<&'static str> {
    match domain {
        "com.google.Chrome" => Some("Google Chrome.app"),
        "com.microsoft.Edge" => Some("Microsoft Edge.app"),
        "com.brave.Browser" => Some("Brave Browser.app"),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn macos_domain_installed(domain: &str) -> bool {
    if let Some(app_name) = macos_app_bundle_for_domain(domain) {
        if std::path::Path::new("/Applications").join(app_name).exists() {
            return true;
        }
        if let Some(home) = super::user_home_dir()
            && home.join("Applications").join(app_name).exists()
        {
            return true;
        }
    }
    super::user_home_dir().is_some_and(|h| {
        h.join("Library")
            .join("Preferences")
            .join(format!("{domain}.plist"))
            .exists()
    })
}

#[cfg(target_os = "macos")]
fn is_defaults_not_found(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("does not exist") || lower.contains("not found")
}

#[cfg(target_os = "macos")]
fn parse_defaults_read(type_out: &str, val_out: &str) -> PResult<PolicyValue> {
    let t = type_out.trim().to_ascii_lowercase();
    let v = val_out.trim();
    if t.contains("boolean") {
        let b = matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        Ok(PolicyValue::Bool(b))
    } else if t.contains("integer") {
        let n = v
            .parse::<u32>()
            .map_err(|_| PlatformError::Unsupported("policy_defaults_int"))?;
        Ok(PolicyValue::Dword(n))
    } else if t.contains("string") {
        Ok(PolicyValue::Sz(v.to_string()))
    } else {
        Err(PlatformError::Unsupported("policy_defaults_type"))
    }
}

impl PolicyStore for RealPolicyStore {
    fn is_domain_applicable(&self, domain: &str) -> bool {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:check");
            return false;
        }
        #[cfg(target_os = "windows")]
        {
            let _ = domain;
            true
        }
        #[cfg(target_os = "macos")]
        {
            macos_domain_installed(domain)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = domain;
            false
        }
    }

    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:read");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{
                ERROR_SUCCESS, REG_DWORD, REG_SZ, RootKey, decode_dword, decode_utf16_le_string,
                is_not_found_status, read_raw,
            };
            let raw = read_raw(RootKey::HkeyCurrentUser, domain, key);
            if is_not_found_status(raw.status) {
                return Ok(None);
            }
            if raw.status != ERROR_SUCCESS {
                return Err(PlatformError::Failed("win_reg_read_policy"));
            }
            match raw.kind {
                REG_DWORD => decode_dword(&raw.data)
                    .map(|n| Some(PolicyValue::Dword(n)))
                    .map_err(|_| PlatformError::Unsupported("policy_reg_dword")),
                REG_SZ => decode_utf16_le_string(&raw.data)
                    .map(|s| Some(PolicyValue::Sz(s)))
                    .map_err(|_| PlatformError::Unsupported("policy_reg_sz")),
                _ => Err(PlatformError::Unsupported("policy_reg_type")),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let read_out = super::silent_command("defaults")
                .args(["read", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_read"))?;
            if !read_out.status.success() {
                let err = String::from_utf8_lossy(&read_out.stderr);
                if is_defaults_not_found(&err) {
                    return Ok(None);
                }
                return Err(PlatformError::Failed("defaults_read"));
            }
            let type_out = super::silent_command("defaults")
                .args(["read-type", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_read_type"))?;
            if !type_out.status.success() {
                let err = String::from_utf8_lossy(&type_out.stderr);
                if is_defaults_not_found(&err) {
                    return Ok(None);
                }
                return Err(PlatformError::Failed("defaults_read_type"));
            }
            let val_s = String::from_utf8_lossy(&read_out.stdout);
            let type_s = String::from_utf8_lossy(&type_out.stdout);
            parse_defaults_read(&type_s, &val_s).map(Some)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }

    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:write");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{RootKey, set_dword, set_sz};
            match value {
                PolicyValue::Dword(n) => set_dword(RootKey::HkeyCurrentUser, domain, key, *n)
                    .map_err(|_| PlatformError::Failed("win_reg_set_dword")),
                PolicyValue::Sz(s) => set_sz(RootKey::HkeyCurrentUser, domain, key, s)
                    .map_err(|_| PlatformError::Failed("win_reg_set_sz")),
                PolicyValue::Bool(b) => {
                    set_dword(RootKey::HkeyCurrentUser, domain, key, u32::from(*b))
                        .map_err(|_| PlatformError::Failed("win_reg_set_bool"))
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let mut cmd = super::silent_command("defaults");
            cmd.args(["write", domain, key]);
            match value {
                PolicyValue::Bool(b) => {
                    cmd.args(["-bool", if *b { "true" } else { "false" }]);
                }
                PolicyValue::Dword(n) => {
                    cmd.args(["-int", &n.to_string()]);
                }
                PolicyValue::Sz(s) => {
                    cmd.args(["-string", s]);
                }
            }
            let out = cmd
                .output()
                .map_err(|_| PlatformError::Failed("defaults_write"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(PlatformError::Failed("defaults_write"))
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key, value);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }

    fn delete(&self, domain: &str, key: &str) -> PResult<()> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:delete");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{RootKey, delete_value};
            delete_value(RootKey::HkeyCurrentUser, domain, key)
                .map_err(|_| PlatformError::Failed("win_reg_delete_policy"))
        }
        #[cfg(target_os = "macos")]
        {
            let out = super::silent_command("defaults")
                .args(["delete", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_delete"))?;
            if out.status.success() {
                return Ok(());
            }
            let err = String::from_utf8_lossy(&out.stderr);
            if is_defaults_not_found(&err) {
                Ok(())
            } else {
                Err(PlatformError::Failed("defaults_delete"))
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }
}

/// Summary of applying browser QUIC/DoH policies through the ownership journal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyApplyReport {
    pub applied: usize,
    pub unchanged: usize,
    pub skipped: usize,
    pub failed: usize,
}

/// Applies the platform's default QUIC/DoH policies through `j`. Non-fatal: individual domain/key
/// failures or unsupported platforms are logged and skipped without blocking `enable_sysproxy`.
pub fn apply_browser_policies(j: &mut Journal, p: &dyn Platform) -> PolicyApplyReport {
    let specs = default_policy_specs();
    apply_policy_specs(j, p, &specs)
}

/// Applies explicit `specs` through `j` using `j.policy_store()`, recording baselines first.
pub fn apply_policy_specs(
    j: &mut Journal,
    p: &dyn Platform,
    specs: &[PolicySpec],
) -> PolicyApplyReport {
    let mut report = PolicyApplyReport::default();
    let store = j.policy_store_arc();
    for spec in specs {
        if !store.is_domain_applicable(&spec.domain) {
            report.skipped += 1;
            continue;
        }
        let res = Resource::BrowserPolicy {
            domain: spec.domain.clone(),
            key: spec.key.clone(),
        };
        let val = Value::Policy(Some(spec.value.clone()));
        match j.apply(p, &res, val) {
            Ok(ApplyOutcome::Applied | ApplyOutcome::Rebased) => report.applied += 1,
            Ok(ApplyOutcome::Unchanged) => report.unchanged += 1,
            Err(JournalError::Platform(PlatformError::DryRun | PlatformError::Unsupported(_))) => {
                report.skipped += 1;
            }
            Err(err) => {
                report.failed += 1;
                eprintln!(
                    "Застава: не удалось применить политику {}: {err}",
                    res.id()
                );
            }
        }
    }
    report
}

/// In-memory [`PolicyStore`] for unit and integration tests.
#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
#[derive(Default)]
pub struct FakePolicyStore {
    inner: Mutex<FakePolicyState>,
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
#[derive(Default)]
struct FakePolicyState {
    applicable_domains: BTreeMap<String, bool>,
    values: BTreeMap<(String, String), PolicyValue>,
    fail_writes: bool,
    fail_reads: bool,
}

#[cfg(any(test, feature = "test-support"))]
#[allow(dead_code)]
impl FakePolicyStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn set_domain_applicable(&self, domain: &str, applicable: bool) {
        self.inner
            .lock()
            .unwrap()
            .applicable_domains
            .insert(domain.to_string(), applicable);
    }

    pub fn preset(&self, domain: &str, key: &str, value: PolicyValue) {
        let mut g = self.inner.lock().unwrap();
        g.applicable_domains.entry(domain.to_string()).or_insert(true);
        g.values
            .insert((domain.to_string(), key.to_string()), value);
    }

    pub fn get(&self, domain: &str, key: &str) -> Option<PolicyValue> {
        self.inner
            .lock()
            .unwrap()
            .values
            .get(&(domain.to_string(), key.to_string()))
            .cloned()
    }

    pub fn remove_raw(&self, domain: &str, key: &str) {
        self.inner
            .lock()
            .unwrap()
            .values
            .remove(&(domain.to_string(), key.to_string()));
    }

    pub fn set_fail_writes(&self, fail: bool) {
        self.inner.lock().unwrap().fail_writes = fail;
    }

    pub fn set_fail_reads(&self, fail: bool) {
        self.inner.lock().unwrap().fail_reads = fail;
    }
}

#[cfg(any(test, feature = "test-support"))]
impl PolicyStore for FakePolicyStore {
    fn is_domain_applicable(&self, domain: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.applicable_domains.get(domain).copied().unwrap_or(true)
    }

    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>> {
        let g = self.inner.lock().unwrap();
        if g.fail_reads {
            return Err(PlatformError::Failed("fake_read"));
        }
        Ok(g.values
            .get(&(domain.to_string(), key.to_string()))
            .cloned())
    }

    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail_writes {
            return Err(PlatformError::Failed("fake_write"));
        }
        g.values
            .insert((domain.to_string(), key.to_string()), value.clone());
        Ok(())
    }

    fn delete(&self, domain: &str, key: &str) -> PResult<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail_writes {
            return Err(PlatformError::Failed("fake_delete"));
        }
        g.values.remove(&(domain.to_string(), key.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::FakeFs;
    use crate::sysproxy::journal::{EntryState, Outcome, recover_with};
    use crate::sysproxy::platform::FakePlatform;
    use std::path::Path;

    const DIR: &str = "/data";

    fn sample_specs() -> Vec<PolicySpec> {
        vec![
            PolicySpec::new("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(false)),
            PolicySpec::new(
                "com.google.Chrome",
                "DnsOverHttpsMode",
                PolicyValue::Sz("off".to_string()),
            ),
        ]
    }

    #[test]
    fn apply_from_absent_writes_and_restore_deletes() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep.applied, 2);
        assert_eq!(rep.failed, 0);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(false))
        );
        assert_eq!(
            store.get("com.google.Chrome", "DnsOverHttpsMode"),
            Some(PolicyValue::Sz("off".to_string()))
        );

        let rec = j.restore_all(&plat);
        assert_eq!(rec.items.len(), 2);
        assert!(rec.items.iter().all(|i| i.outcome == Outcome::Restored));
        assert_eq!(store.get("com.google.Chrome", "QuicAllowed"), None);
        assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
    }

    #[test]
    fn apply_over_existing_user_setting_restores_original_value() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));
        store.preset(
            "com.google.Chrome",
            "DnsOverHttpsMode",
            PolicyValue::Sz("automatic".to_string()),
        );

        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());
        let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep.applied, 2);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(false))
        );

        // Re-applying while active is idempotent.
        let rep2 = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep2.unchanged, 2);

        let rec = j.restore_all(&plat);
        assert!(rec.items.iter().all(|i| i.outcome == Outcome::Restored));
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(true))
        );
        assert_eq!(
            store.get("com.google.Chrome", "DnsOverHttpsMode"),
            Some(PolicyValue::Sz("automatic".to_string()))
        );
    }

    #[test]
    fn external_change_blocks_blind_overwrite_on_restore() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        apply_policy_specs(&mut j, &plat, &sample_specs());
        // Admin/MDM changed QuicAllowed while Zastava was running.
        store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

        let rec = j.restore_all(&plat);
        let quic = rec
            .items
            .iter()
            .find(|i| i.resource.ends_with(":QuicAllowed"))
            .unwrap();
        assert_eq!(quic.outcome, Outcome::ExternalChange);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(true)),
            "external change must not be deleted or overwritten"
        );
        // The untouched DoH key is still restored to absent.
        assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
    }

    #[test]
    fn inapplicable_domain_is_skipped_without_reading_or_writing() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        store.set_domain_applicable("com.microsoft.Edge", false);
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());

        let specs = vec![PolicySpec::new(
            "com.microsoft.Edge",
            "QuicAllowed",
            PolicyValue::Bool(false),
        )];
        let rep = apply_policy_specs(&mut j, &plat, &specs);
        assert_eq!(rep.skipped, 1);
        assert_eq!(rep.applied, 0);
        assert!(j.entries().is_empty());
    }

    #[test]
    fn crash_recovery_from_disk_restores_baseline() {
        let fs = Arc::new(FakeFs::new());
        let plat = FakePlatform::new();
        let store = FakePolicyStore::new();
        store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

        {
            let mut j = Journal::open(fs.clone(), Path::new(DIR))
                .unwrap()
                .with_policy_store(store.clone());
            let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
            assert_eq!(rep.applied, 2);
            assert_eq!(j.entries()[0].state, EntryState::Applied);
        }

        // Simulate restart / crash recovery via a fresh Journal open + policy store.
        let mut j2 = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());
        let rec = j2.restore_all(&plat);
        assert_eq!(rec.items.len(), 2);
        assert_eq!(
            store.get("com.google.Chrome", "QuicAllowed"),
            Some(PolicyValue::Bool(true))
        );
        assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
        // Default recover_with uses RealPolicyStore; verify dry-run does not touch host.
        let _ = recover_with(fs, &plat, Path::new(DIR));
    }
}
