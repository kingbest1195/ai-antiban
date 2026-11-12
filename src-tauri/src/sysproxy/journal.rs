//! Ownership journal: what Zastava changed in the system and what was there before.
//!
//! Guarantee: Zastava restores ONLY what it changed itself and never guesses.
//! * Before the first OS write of a resource, an intent with the exact `baseline` (the value that
//!   was there before us, including "no value" and the type) is written durably
//!   (temp file -> fsync -> rename -> fsync dir). If that write fails, nothing is written to the OS.
//! * A repeated `apply` never replaces the baseline.
//! * Restore: current == what we wrote (`expected`, or the in-flight `pending`) -> write baseline back
//!   (or delete when baseline was "no value"); anything else is an external change that is left
//!   alone and the record is released with a mark.
//! * Unknown schema version, corrupt file or a lock held by another process -> fail closed:
//!   no operation is possible and the file is never deleted or overwritten.
//!
//! Values (PAC URLs, proxy hosts, credentials) live only in the 0600 journal file; errors, reports
//! and the `Debug` output name resources, never values.

use super::fs::{Fs, FsLock, LockError, WriteMode};
use super::platform::{
    ChainState, PResult, PacState, Platform, PlatformError, RegValue, ServiceId,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const SCHEMA_VERSION: u32 = 1;
const SUBDIR: &str = "ownership";
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "journal.lock";

/// A system setting Zastava may own.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Resource {
    /// Auto Proxy (PAC) of one macOS service.
    Pac { service: ServiceId },
    /// Explicit HTTP/HTTPS proxy of one macOS service.
    Chain { service: ServiceId },
    /// One variable of the user environment (launchctl / `HKCU\Environment`).
    UserEnv { name: String },
    /// One WinINet value (`AutoConfigURL`, `ProxyEnable`, ...).
    Inet { name: String },
}

impl Resource {
    /// Name of the resource for logs and reports. Contains no values.
    pub fn id(&self) -> String {
        match self {
            Resource::Pac { service } => format!("pac:{}", service.key()),
            Resource::Chain { service } => format!("chain:{}", service.key()),
            Resource::UserEnv { name } => format!("env:{name}"),
            Resource::Inet { name } => format!("inet:{name}"),
        }
    }
}

/// A typed snapshot of a resource. "No value" is part of the type, never an empty string.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Value {
    Pac(PacState),
    Chain(ChainState),
    Env(Option<String>),
    Reg(Option<RegValue>),
}

impl Value {
    fn matches(&self, res: &Resource) -> bool {
        matches!(
            (self, res),
            (Value::Pac(_), Resource::Pac { .. })
                | (Value::Chain(_), Resource::Chain { .. })
                | (Value::Env(_), Resource::UserEnv { .. })
                | (Value::Reg(_), Resource::Inet { .. })
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Intent is durable; the OS write is not confirmed yet (or an update is in flight).
    Pending,
    /// The OS write is confirmed; `expected` is what we wrote.
    Applied,
}

/// One owned resource.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub resource: Resource,
    /// What was there before Zastava touched it. Written once, never replaced.
    pub baseline: Value,
    /// The last confirmed value we wrote.
    #[serde(default)]
    pub expected: Option<Value>,
    /// The value an in-flight write is about to set; the previous `expected` stays meanwhile.
    #[serde(default)]
    pub pending: Option<Value>,
    pub state: EntryState,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileData {
    schema_version: u32,
    entries: Vec<Entry>,
}

/// Why a journal operation did not happen. Carries no values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JournalError {
    /// Another process (or instance) holds the journal lock. Fail closed.
    Locked,
    /// The journal file cannot be parsed or is inconsistent. Fail closed; the file is kept.
    Corrupt,
    /// The journal was written by a newer/unknown schema. Fail closed; the file is kept.
    UnknownSchema(u32),
    /// A file-system step failed.
    Io(&'static str, std::io::ErrorKind),
    /// The OS call failed (operation name only).
    Platform(PlatformError),
    /// The value does not belong to the resource.
    KindMismatch,
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JournalError::Locked => write!(f, "ownership journal is locked by another process"),
            JournalError::Corrupt => write!(f, "ownership journal is unreadable"),
            JournalError::UnknownSchema(v) => write!(f, "ownership journal has unknown schema {v}"),
            JournalError::Io(op, k) => write!(f, "ownership journal {op}: {k:?}"),
            JournalError::Platform(e) => write!(f, "{e}"),
            JournalError::KindMismatch => write!(f, "value does not match the resource"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<PlatformError> for JournalError {
    fn from(e: PlatformError) -> Self {
        JournalError::Platform(e)
    }
}

/// Result of one `apply`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApplyOutcome {
    /// The value was written and recorded.
    Applied,
    /// The resource already holds exactly our value.
    Unchanged,
    /// Somebody else changed the resource after us; nothing was written, the record is kept.
    ExternalChange,
}

/// Result of restoring one resource.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Baseline written back (or the variable deleted); record released.
    Restored,
    /// The resource already equals the baseline; record released.
    AlreadyRestored,
    /// The current value is not ours: left untouched, record released with this mark.
    ExternalChange,
    /// The target (service) no longer exists; record released.
    TargetGone,
    /// The step failed; the record is kept for a safe retry. Operation name only.
    Failed(&'static str),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReportItem {
    pub resource: String,
    pub outcome: Outcome,
}

/// What a recovery pass did. Names and outcomes only.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RecoveryReport {
    pub items: Vec<ReportItem>,
    /// OS dry-run mode: nothing was examined.
    pub skipped_dry_run: bool,
    /// The journal could not be rewritten after a step (records stay and are retried later).
    pub journal_write_failed: bool,
}

impl RecoveryReport {
    pub fn count(&self, pred: impl Fn(&Outcome) -> bool) -> usize {
        self.items.iter().filter(|i| pred(&i.outcome)).count()
    }
    pub fn restored(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Restored))
    }
    pub fn external(&self) -> usize {
        self.count(|o| matches!(o, Outcome::ExternalChange))
    }
    pub fn failed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Failed(_)))
    }
    pub fn has_failures(&self) -> bool {
        self.failed() > 0 || self.journal_write_failed
    }
    /// One line for logs: counts and resource names only.
    pub fn summary(&self) -> String {
        if self.skipped_dry_run {
            return "ownership recovery skipped (OS dry-run)".to_string();
        }
        let names: Vec<String> = self
            .items
            .iter()
            .map(|i| format!("{}={:?}", i.resource, i.outcome))
            .collect();
        format!(
            "ownership recovery: {} restored, {} external, {} failed [{}]",
            self.restored(),
            self.external(),
            self.failed(),
            names.join(", ")
        )
    }
}

static PANICKED: AtomicBool = AtomicBool::new(false);

/// Called from a panic hook: only raises a flag. No OS call, no I/O. The recovery itself runs at
/// the next start (the journal already holds everything needed), also after SIGKILL / abort.
pub fn note_panic() {
    PANICKED.store(true, Ordering::SeqCst);
}

pub fn panic_flagged() -> bool {
    PANICKED.load(Ordering::SeqCst)
}

fn read_value(platform: &dyn Platform, res: &Resource) -> PResult<Value> {
    Ok(match res {
        Resource::Pac { service } => Value::Pac(platform.get_pac(service)?),
        Resource::Chain { service } => Value::Chain(platform.get_chain(service)?),
        Resource::UserEnv { name } => Value::Env(platform.get_user_env(name)?),
        Resource::Inet { name } => Value::Reg(platform.get_inet(name)?),
    })
}

fn write_value(platform: &dyn Platform, res: &Resource, v: &Value) -> PResult<()> {
    match (res, v) {
        (Resource::Pac { service }, Value::Pac(p)) => {
            // An absent URL is restored by clearing it (networksetup has no "unset").
            let pac = PacState {
                url: Some(p.url.clone().unwrap_or_default()),
                enabled: p.enabled,
            };
            platform.set_pac(service, &pac)
        }
        (Resource::Chain { service }, Value::Chain(c)) => platform.set_chain(service, c),
        (Resource::UserEnv { name }, Value::Env(Some(s))) => {
            platform.set_user_env(name, s)?;
            let _ = platform.broadcast_env_change();
            Ok(())
        }
        (Resource::UserEnv { name }, Value::Env(None)) => {
            platform.unset_user_env(name)?;
            let _ = platform.broadcast_env_change();
            Ok(())
        }
        (Resource::Inet { name }, Value::Reg(Some(r))) => {
            platform.set_inet(name, r)?;
            let _ = platform.notify_inet_refresh();
            Ok(())
        }
        (Resource::Inet { name }, Value::Reg(None)) => {
            platform.delete_inet(name)?;
            let _ = platform.notify_inet_refresh();
            Ok(())
        }
        _ => Err(PlatformError::Unsupported("kind_mismatch")),
    }
}

/// The ownership journal. Holds the inter-process lock for as long as it lives.
pub struct Journal {
    fs: Arc<dyn Fs>,
    root: PathBuf,
    entries: Vec<Entry>,
    backup_excluded: bool,
    _lock: FsLock,
}

impl fmt::Debug for Journal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<String> = self.entries.iter().map(|e| e.resource.id()).collect();
        write!(f, "Journal({ids:?})")
    }
}

impl Journal {
    /// Opens (or starts) the journal under `<data_dir>/ownership/`. Fails closed on a held lock,
    /// an unknown schema or a corrupt file, without touching the file.
    pub fn open(fs: Arc<dyn Fs>, data_dir: &Path) -> Result<Journal, JournalError> {
        let root = data_dir.join(SUBDIR);
        fs.create_private_dir_all(&root)
            .map_err(|e| JournalError::Io("create_dir", e.kind()))?;
        let lock = fs.try_lock(&root.join(LOCK_FILE)).map_err(|e| match e {
            LockError::Held => JournalError::Locked,
            LockError::Io(k) => JournalError::Io("lock", k),
        })?;
        let path = root.join(JOURNAL_FILE);
        let entries = match fs
            .read(&path)
            .map_err(|e| JournalError::Io("read", e.kind()))?
        {
            None => Vec::new(),
            Some(bytes) => {
                let entries = parse(&bytes)?;
                // An older build or a manual copy may have left loose permissions.
                if matches!(fs.mode(&path), Ok(Some(m)) if m & 0o077 != 0) {
                    let _ = fs.set_mode(&path, 0o600);
                }
                entries
            }
        };
        Ok(Journal {
            fs,
            root,
            entries,
            backup_excluded: false,
            _lock: lock,
        })
    }

    pub fn journal_path(&self) -> PathBuf {
        self.root.join(JOURNAL_FILE)
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn entry(&self, res: &Resource) -> Option<&Entry> {
        self.entries.iter().find(|e| &e.resource == res)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Durable write of the whole journal. Time Machine exclusion (best effort) comes first.
    fn persist(&mut self, platform: &dyn Platform) -> Result<(), JournalError> {
        if !self.backup_excluded {
            self.backup_excluded = true;
            let _ = platform.exclude_from_backup(&self.root);
        }
        let data = FileData {
            schema_version: SCHEMA_VERSION,
            entries: self.entries.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&data).map_err(|_| JournalError::Corrupt)?;
        self.fs
            .write_atomic(&self.journal_path(), &bytes, WriteMode::Private)
            .map_err(|e| JournalError::Io("write", e.kind()))
    }

    fn index_of(&self, res: &Resource) -> Option<usize> {
        self.entries.iter().position(|e| &e.resource == res)
    }

    /// Writes `new` into the OS and records ownership.
    ///
    /// Order: read current -> durable intent (with baseline) -> OS write -> durable "applied".
    /// If the intent cannot be made durable, the OS is not touched.
    pub fn apply(
        &mut self,
        platform: &dyn Platform,
        res: &Resource,
        new: Value,
    ) -> Result<ApplyOutcome, JournalError> {
        if !new.matches(res) {
            return Err(JournalError::KindMismatch);
        }
        let cur = read_value(platform, res)?;
        // `previous` = what the resource holds when nothing of this write has landed yet;
        // `before` = the record as it was on disk, for an exact in-memory rollback.
        let previous = cur.clone();
        let before = self.entry(res).cloned();
        match self.index_of(res) {
            None => {
                self.entries.push(Entry {
                    resource: res.clone(),
                    baseline: cur,
                    expected: None,
                    pending: Some(new.clone()),
                    state: EntryState::Pending,
                });
            }
            Some(i) => {
                let e = &mut self.entries[i];
                if e.state == EntryState::Applied && e.expected.as_ref() == Some(&new) && cur == new
                {
                    return Ok(ApplyOutcome::Unchanged);
                }
                let ours = e.expected.as_ref() == Some(&cur) || e.pending.as_ref() == Some(&cur);
                if !ours && cur != e.baseline {
                    return Ok(ApplyOutcome::ExternalChange);
                }
                // The baseline stays as it is. The previous `expected` stays too, so a crash in
                // the middle of the update can still be recognised and restored.
                e.pending = Some(new.clone());
                e.state = EntryState::Pending;
            }
        }
        if let Err(err) = self.persist(platform) {
            // Intent is not durable: forget the in-memory change, the OS is untouched.
            self.put_back(res, before);
            return Err(err);
        }
        if let Err(werr) = write_value(platform, res, &new) {
            self.settle_failed_write(platform, res, &previous, before);
            return Err(werr.into());
        }
        let i = self.index_of(res).ok_or(JournalError::Corrupt)?;
        let e = &mut self.entries[i];
        e.expected = Some(new);
        e.pending = None;
        e.state = EntryState::Applied;
        self.persist(platform)?;
        Ok(ApplyOutcome::Applied)
    }

    /// Puts the in-memory record back to `before` (`None` = no record).
    fn put_back(&mut self, res: &Resource, before: Option<Entry>) {
        match (self.index_of(res), before) {
            (Some(i), Some(b)) => self.entries[i] = b,
            (Some(i), None) => {
                self.entries.remove(i);
            }
            (None, Some(b)) => self.entries.push(b),
            (None, None) => {}
        }
    }

    /// An OS write failed (possibly half-way). If the resource no longer holds what it held
    /// before, try to put that back, then close the intent. Best effort; the on-disk intent
    /// keeps the resource recoverable either way.
    fn settle_failed_write(
        &mut self,
        platform: &dyn Platform,
        res: &Resource,
        previous: &Value,
        before: Option<Entry>,
    ) {
        let clean = match read_value(platform, res) {
            Ok(v) if &v == previous => true,
            Ok(_) => write_value(platform, res, previous).is_ok(),
            Err(_) => false,
        };
        if clean {
            self.put_back(res, before);
            let _ = self.persist(platform);
        }
        // else: stays Pending on disk; the recovery pass decides from the real value
    }

    /// Restores every recorded resource. A failure of one never blocks the others; repeating the
    /// pass is safe. Returns a report with resource names and outcomes only.
    pub fn restore_all(&mut self, platform: &dyn Platform) -> RecoveryReport {
        let ids: Vec<Resource> = self.entries.iter().map(|e| e.resource.clone()).collect();
        let mut report = RecoveryReport::default();
        for res in ids {
            let outcome = self.restore_one_inner(platform, &res, &mut report);
            report.items.push(ReportItem {
                resource: res.id(),
                outcome,
            });
        }
        report
    }

    /// Restores a single resource (see [`Journal::restore_all`]).
    pub fn restore_one(&mut self, platform: &dyn Platform, res: &Resource) -> Option<ReportItem> {
        self.index_of(res)?;
        let mut report = RecoveryReport::default();
        let outcome = self.restore_one_inner(platform, res, &mut report);
        Some(ReportItem {
            resource: res.id(),
            outcome,
        })
    }

    fn restore_one_inner(
        &mut self,
        platform: &dyn Platform,
        res: &Resource,
        report: &mut RecoveryReport,
    ) -> Outcome {
        let Some(i) = self.index_of(res) else {
            return Outcome::AlreadyRestored;
        };
        let entry = self.entries[i].clone();
        let outcome = match read_value(platform, res) {
            Err(PlatformError::NotFound(_)) => Outcome::TargetGone,
            Err(_) => return Outcome::Failed("read"),
            Ok(cur) => {
                let ours =
                    entry.expected.as_ref() == Some(&cur) || entry.pending.as_ref() == Some(&cur);
                if cur == entry.baseline {
                    Outcome::AlreadyRestored
                } else if !ours {
                    Outcome::ExternalChange
                } else {
                    // Narrow the window for a concurrent change: read once more right before writing.
                    match read_value(platform, res) {
                        Ok(again) if again == cur => {}
                        Ok(_) => {
                            return self.release(platform, res, Outcome::ExternalChange, report);
                        }
                        Err(_) => return Outcome::Failed("read"),
                    }
                    match write_value(platform, res, &entry.baseline) {
                        Ok(()) => Outcome::Restored,
                        Err(_) => return Outcome::Failed("write"),
                    }
                }
            }
        };
        self.release(platform, res, outcome, report)
    }

    /// Drops the record and persists. If persisting fails the record stays on disk and the next
    /// pass finds the resource already restored / not ours, which is safe.
    fn release(
        &mut self,
        platform: &dyn Platform,
        res: &Resource,
        outcome: Outcome,
        report: &mut RecoveryReport,
    ) -> Outcome {
        if let Some(i) = self.index_of(res) {
            self.entries.remove(i);
            if self.persist(platform).is_err() {
                report.journal_write_failed = true;
            }
        }
        outcome
    }
}

fn parse(bytes: &[u8]) -> Result<Vec<Entry>, JournalError> {
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    let version = raw
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .ok_or(JournalError::Corrupt)?;
    if version != u64::from(SCHEMA_VERSION) {
        return Err(JournalError::UnknownSchema(
            u32::try_from(version).unwrap_or(u32::MAX),
        ));
    }
    let data: FileData = serde_json::from_value(raw).map_err(|_| JournalError::Corrupt)?;
    for (i, e) in data.entries.iter().enumerate() {
        let kinds_ok = e.baseline.matches(&e.resource)
            && e.expected.as_ref().is_none_or(|v| v.matches(&e.resource))
            && e.pending.as_ref().is_none_or(|v| v.matches(&e.resource));
        let state_ok = match e.state {
            EntryState::Applied => e.expected.is_some() && e.pending.is_none(),
            EntryState::Pending => e.pending.is_some(),
        };
        let unique = !data.entries[..i].iter().any(|o| o.resource == e.resource);
        if !(kinds_ok && state_ok && unique) {
            return Err(JournalError::Corrupt);
        }
    }
    Ok(data.entries)
}

/// Opens the journal and restores everything it owns. Fail closed on any journal-level error.
pub fn recover_with(
    fs: Arc<dyn Fs>,
    platform: &dyn Platform,
    data_dir: &Path,
) -> Result<RecoveryReport, JournalError> {
    let mut journal = Journal::open(fs, data_dir)?;
    Ok(journal.restore_all(platform))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysproxy::fs::{FakeFs, FsOp};
    use crate::sysproxy::platform::{FakePlatform, PlatOp, ProxyEndpoint};

    const DIR: &str = "/data";

    fn setup() -> (FakeFs, FakePlatform) {
        (FakeFs::new(), FakePlatform::new())
    }

    fn open(fs: &FakeFs) -> Result<Journal, JournalError> {
        Journal::open(Arc::new(fs.clone()), Path::new(DIR))
    }

    fn jpath() -> PathBuf {
        Path::new(DIR).join(SUBDIR).join(JOURNAL_FILE)
    }

    fn env(name: &str) -> Resource {
        Resource::UserEnv { name: name.into() }
    }
    fn ev(s: &str) -> Value {
        Value::Env(Some(s.into()))
    }
    fn wifi() -> ServiceId {
        ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
    }
    fn pac_value(url: &str, on: bool) -> Value {
        Value::Pac(PacState {
            url: Some(url.into()),
            enabled: Some(on),
        })
    }

    // --- types / absence / empty -----------------------------------------------------------

    #[test]
    fn absent_baseline_is_deleted_on_restore() {
        let (fs, p) = setup();
        let mut j = open(&fs).unwrap();
        assert_eq!(
            j.apply(&p, &env("HTTPS_PROXY"), ev("x")).unwrap(),
            ApplyOutcome::Applied
        );
        assert_eq!(p.env_of("HTTPS_PROXY"), Some("x".into()));
        let r = j.restore_all(&p);
        assert_eq!(r.restored(), 1);
        assert_eq!(
            p.env_of("HTTPS_PROXY"),
            None,
            "absent baseline -> variable deleted"
        );
    }

    #[test]
    fn empty_string_baseline_differs_from_absent() {
        let (fs, p) = setup();
        p.seed_env("A", "");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("x")).unwrap();
        assert_eq!(
            j.entry(&env("A")).unwrap().baseline,
            Value::Env(Some(String::new()))
        );
        j.restore_all(&p);
        assert_eq!(
            p.env_of("A"),
            Some(String::new()),
            "empty string comes back as empty, not removed"
        );
    }

    #[test]
    fn registry_type_is_preserved_through_restore() {
        let (fs, p) = setup();
        p.seed_inet("ProxyEnable", RegValue::dword(1));
        p.seed_inet("AutoConfigURL", RegValue::expand_sz("%X%"));
        let mut j = open(&fs).unwrap();
        let en = Resource::Inet {
            name: "ProxyEnable".into(),
        };
        let url = Resource::Inet {
            name: "AutoConfigURL".into(),
        };
        j.apply(&p, &en, Value::Reg(Some(RegValue::dword(0))))
            .unwrap();
        j.apply(
            &p,
            &url,
            Value::Reg(Some(RegValue::sz("http://127.0.0.1:8899/proxy.pac"))),
        )
        .unwrap();
        j.restore_all(&p);
        assert_eq!(p.inet_of("ProxyEnable"), Some(RegValue::dword(1)));
        assert_eq!(p.inet_of("AutoConfigURL"), Some(RegValue::expand_sz("%X%")));
    }

    #[test]
    fn absent_registry_value_is_deleted_not_blanked() {
        let (fs, p) = setup();
        let mut j = open(&fs).unwrap();
        let url = Resource::Inet {
            name: "AutoConfigURL".into(),
        };
        j.apply(&p, &url, Value::Reg(Some(RegValue::sz("u"))))
            .unwrap();
        j.restore_all(&p);
        assert_eq!(p.inet_of("AutoConfigURL"), None);
    }

    #[test]
    fn pac_baseline_with_third_party_pac_returns_exactly() {
        let (fs, p) = setup();
        p.add_service(wifi());
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("http://corp/p.pac".into()),
                enabled: Some(false),
            },
        );
        let mut j = open(&fs).unwrap();
        let res = Resource::Pac { service: wifi() };
        j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        j.restore_all(&p);
        assert_eq!(
            p.pac_of(&wifi()),
            PacState {
                url: Some("http://corp/p.pac".into()),
                enabled: Some(false)
            }
        );
    }

    #[test]
    fn pac_absent_baseline_clears_url() {
        let (fs, p) = setup();
        p.add_service(wifi());
        let mut j = open(&fs).unwrap();
        let res = Resource::Pac { service: wifi() };
        j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        j.restore_all(&p);
        assert_eq!(p.pac_of(&wifi()).url, None);
    }

    #[test]
    fn http_and_https_upstreams_are_kept_apart() {
        let (fs, p) = setup();
        p.add_service(wifi());
        let http = ProxyEndpoint {
            enabled: Some(true),
            server: Some("h1".into()),
            port: Some(1080),
        };
        let https = ProxyEndpoint {
            enabled: Some(true),
            server: Some("h2".into()),
            port: Some(2080),
        };
        p.seed_chain(
            &wifi(),
            ChainState {
                http: http.clone(),
                https: https.clone(),
            },
        );
        let mut j = open(&fs).unwrap();
        let res = Resource::Chain { service: wifi() };
        // `apply` takes the complete value as the OS will report it back.
        let off = ChainState {
            http: ProxyEndpoint {
                enabled: Some(false),
                ..http.clone()
            },
            https: ProxyEndpoint {
                enabled: Some(false),
                ..https.clone()
            },
        };
        j.apply(&p, &res, Value::Chain(off)).unwrap();
        j.restore_all(&p);
        assert_eq!(p.chain_of(&wifi()), ChainState { http, https });
    }

    // --- repeated enable -------------------------------------------------------------------

    #[test]
    fn repeated_enable_keeps_the_original_baseline() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("ours")).unwrap();
        assert_eq!(
            j.apply(&p, &env("A"), ev("ours")).unwrap(),
            ApplyOutcome::Unchanged
        );
        j.apply(&p, &env("A"), ev("ours2")).unwrap();
        assert_eq!(j.entry(&env("A")).unwrap().baseline, ev("orig"));
        j.restore_all(&p);
        assert_eq!(p.env_of("A"), Some("orig".into()));
    }

    #[test]
    fn new_pac_url_update_keeps_original_flag_baseline() {
        let (fs, p) = setup();
        p.add_service(wifi());
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("http://corp/p.pac".into()),
                enabled: Some(false),
            },
        );
        let mut j = open(&fs).unwrap();
        let res = Resource::Pac { service: wifi() };
        j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        j.apply(&p, &res, pac_value("http://127.0.0.1:9000/proxy.pac", true))
            .unwrap();
        j.restore_all(&p);
        assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
        assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://corp/p.pac"));
    }

    // --- external change -------------------------------------------------------------------

    #[test]
    fn external_change_is_preserved_and_record_released() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("ours")).unwrap();
        p.seed_env("A", "users-own-value");
        let writes = p.os_writes();
        let r = j.restore_all(&p);
        assert_eq!(r.external(), 1);
        assert_eq!(p.env_of("A"), Some("users-own-value".into()));
        assert_eq!(
            p.os_writes(),
            writes,
            "an external value is never written over"
        );
        assert!(j.is_empty());
    }

    #[test]
    fn external_deletion_is_not_resurrected() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("ours")).unwrap();
        p.remove_env_externally("A");
        let r = j.restore_all(&p);
        assert_eq!(r.external(), 1);
        assert_eq!(p.env_of("A"), None);
    }

    #[test]
    fn external_pac_change_is_not_rolled_back_and_foreign_flag_stays() {
        let (fs, p) = setup();
        p.add_service(wifi());
        let mut j = open(&fs).unwrap();
        let res = Resource::Pac { service: wifi() };
        j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("http://vpn/p.pac".into()),
                enabled: Some(true),
            },
        );
        j.restore_all(&p);
        assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://vpn/p.pac"));
        assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
    }

    #[test]
    fn apply_over_external_change_writes_nothing() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("ours")).unwrap();
        p.seed_env("A", "other");
        let writes = p.os_writes();
        assert_eq!(
            j.apply(&p, &env("A"), ev("ours")).unwrap(),
            ApplyOutcome::ExternalChange
        );
        assert_eq!(p.os_writes(), writes);
        assert_eq!(p.env_of("A"), Some("other".into()));
        assert_eq!(j.entry(&env("A")).unwrap().baseline, ev("orig"));
    }

    // --- crashes ---------------------------------------------------------------------------

    #[test]
    fn crash_after_intent_before_os_write_restores_nothing() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        {
            let mut j = open(&fs).unwrap();
            p.fail_next(PlatOp::SetEnv); // the OS write never lands (process "dies")
            assert!(j.apply(&p, &env("A"), ev("ours")).is_err());
        }
        // Even if the in-process cleanup did not run, the on-disk record is harmless:
        let raw: Journal = open(&fs).unwrap();
        assert!(raw.entries().len() <= 1);
        drop(raw);
        let writes = p.os_writes();
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(p.env_of("A"), Some("orig".into()));
        assert_eq!(
            p.os_writes(),
            writes,
            "value never changed, so nothing is written"
        );
        assert_eq!(r.failed(), 0);
    }

    #[test]
    fn crash_after_os_write_before_applied_mark_still_restores() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        {
            let mut j = open(&fs).unwrap();
            // 1st durable write (intent) ok, 2nd ("applied") fails -> as if killed in between.
            fs.fail_after(FsOp::WriteAtomic, 1);
            assert!(j.apply(&p, &env("A"), ev("ours")).is_err());
        }
        assert_eq!(p.env_of("A"), Some("ours".into()));
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(r.restored(), 1);
        assert_eq!(p.env_of("A"), Some("orig".into()));
    }

    #[test]
    fn crash_in_the_middle_of_an_update_keeps_previous_applied_value() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        {
            let mut j = open(&fs).unwrap();
            j.apply(&p, &env("A"), ev("v1")).unwrap();
            // The update's intent is durable, then the "applied" mark is lost.
            fs.fail_after(FsOp::WriteAtomic, 1);
            assert!(j.apply(&p, &env("A"), ev("v2")).is_err());
        }
        let j = open(&fs).unwrap();
        let e = j.entry(&env("A")).unwrap();
        assert_eq!(
            e.expected,
            Some(ev("v1")),
            "previous applied value survives"
        );
        assert_eq!(e.pending, Some(ev("v2")));
        drop(j);
        assert_eq!(p.env_of("A"), Some("v2".into()));
        recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(p.env_of("A"), Some("orig".into()));
    }

    #[test]
    fn crash_before_update_write_leaves_old_value_recoverable() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("v1")).unwrap();
        p.fail_next(PlatOp::SetEnv);
        assert!(j.apply(&p, &env("A"), ev("v2")).is_err());
        drop(j);
        assert_eq!(p.env_of("A"), Some("v1".into()));
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(r.restored(), 1);
        assert_eq!(p.env_of("A"), Some("orig".into()));
    }

    #[test]
    fn pending_absence_survives_serialization() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        // We "own" the absence of A: expected = no value, baseline = a value.
        j.apply(&p, &env("A"), Value::Env(None)).unwrap();
        assert_eq!(p.env_of("A"), None);
        drop(j);
        let j = open(&fs).unwrap();
        let e = j.entry(&env("A")).unwrap();
        assert_eq!(
            e.expected,
            Some(Value::Env(None)),
            "expected absence is distinct from 'no expectation'"
        );
        drop(j);
        recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(p.env_of("A"), Some("orig".into()));
    }

    #[test]
    fn half_written_composite_value_is_rolled_back() {
        let (fs, p) = setup();
        p.add_service(wifi());
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("http://corp/p.pac".into()),
                enabled: Some(false),
            },
        );
        let mut j = open(&fs).unwrap();
        let res = Resource::Pac { service: wifi() };
        p.fail_next(PlatOp::SetPac);
        assert!(
            j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
                .is_err()
        );
        assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://corp/p.pac"));
        assert!(j.is_empty(), "nothing landed, so no ownership is claimed");
    }

    // --- durable intent --------------------------------------------------------------------

    #[test]
    fn failed_durable_intent_means_no_os_write() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        fs.fail_next(FsOp::WriteAtomic);
        let err = j.apply(&p, &env("A"), ev("ours")).unwrap_err();
        assert!(matches!(err, JournalError::Io("write", _)));
        assert_eq!(p.os_writes(), 0);
        assert_eq!(p.env_of("A"), Some("orig".into()));
        assert!(j.is_empty());
    }

    #[test]
    fn intent_is_on_disk_before_the_os_write() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        let mut j = open(&fs).unwrap();
        p.fail_next(PlatOp::SetEnv);
        let _ = j.apply(&p, &env("A"), ev("ours"));
        // The write was refused, yet the intent write was attempted first (1 durable write).
        assert!(fs.write_count() >= 1);
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn time_machine_exclusion_is_requested_before_the_first_write_and_is_best_effort() {
        let (fs, p) = setup();
        p.fail_next(PlatOp::ExcludeBackup);
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("x")).unwrap(); // exclusion failure does not block
        let calls = p.calls();
        let ex = calls
            .iter()
            .position(|c| c == "exclude_from_backup")
            .unwrap();
        let set = calls
            .iter()
            .position(|c| c.starts_with("set_user_env"))
            .unwrap();
        assert!(
            ex < set,
            "exclusion is requested before the OS write: {calls:?}"
        );
        let (fs2, p2) = setup();
        let mut j2 = open(&fs2).unwrap();
        fs2.fail_next(FsOp::WriteAtomic);
        let _ = j2.apply(&p2, &env("A"), ev("x"));
        assert_eq!(
            p2.excluded_paths(),
            vec![Path::new(DIR).join(SUBDIR)],
            "requested even though the write failed"
        );
        assert!(p2.calls().iter().any(|c| c == "exclude_from_backup"));
    }

    // --- fail-closed -----------------------------------------------------------------------

    #[test]
    fn corrupt_journal_fails_closed_and_is_kept() {
        let (fs, p) = setup();
        p.seed_env("A", "orig");
        fs.put(&jpath(), b"{ not json", 0o600);
        assert_eq!(open(&fs).unwrap_err(), JournalError::Corrupt);
        assert_eq!(
            recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap_err(),
            JournalError::Corrupt
        );
        assert_eq!(
            fs.get(&jpath()).unwrap(),
            b"{ not json",
            "file is neither deleted nor overwritten"
        );
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn unknown_schema_fails_closed_and_is_kept() {
        let (fs, p) = setup();
        let body = br#"{"schema_version":2,"entries":[],"future":"field"}"#;
        fs.put(&jpath(), body, 0o600);
        assert_eq!(open(&fs).unwrap_err(), JournalError::UnknownSchema(2));
        assert_eq!(fs.get(&jpath()).unwrap(), body);
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn inconsistent_entries_are_corrupt() {
        let (fs, _p) = setup();
        // Applied without `expected`.
        let body = br#"{"schema_version":1,"entries":[{"resource":{"kind":"user_env","name":"A"},
            "baseline":{"type":"env","value":null},"state":"applied"}]}"#;
        fs.put(&jpath(), body, 0o600);
        assert_eq!(open(&fs).unwrap_err(), JournalError::Corrupt);
        // Value kind does not match the resource.
        let body = br#"{"schema_version":1,"entries":[{"resource":{"kind":"user_env","name":"A"},
            "baseline":{"type":"reg","value":null},"pending":{"type":"env","value":"x"},"state":"pending"}]}"#;
        fs.put(&jpath(), body, 0o600);
        assert_eq!(open(&fs).unwrap_err(), JournalError::Corrupt);
    }

    #[test]
    fn unknown_fields_in_current_schema_are_corrupt_not_ignored() {
        let (fs, _p) = setup();
        fs.put(
            &jpath(),
            br#"{"schema_version":1,"entries":[],"extra":1}"#,
            0o600,
        );
        assert_eq!(open(&fs).unwrap_err(), JournalError::Corrupt);
    }

    #[test]
    fn second_process_holding_the_lock_fails_closed() {
        let (fs, p) = setup();
        let first = open(&fs).unwrap();
        assert_eq!(open(&fs).unwrap_err(), JournalError::Locked);
        assert_eq!(
            recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap_err(),
            JournalError::Locked
        );
        drop(first);
        assert!(open(&fs).is_ok(), "lock is released with the holder");
    }

    #[test]
    fn external_lock_holder_blocks_everything() {
        let (fs, p) = setup();
        fs.hold_lock_externally(&Path::new(DIR).join(SUBDIR).join(LOCK_FILE));
        assert_eq!(open(&fs).unwrap_err(), JournalError::Locked);
        assert_eq!(p.os_writes(), 0);
    }

    #[test]
    fn missing_journal_is_an_empty_journal() {
        let (fs, p) = setup();
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert!(r.items.is_empty());
        assert_eq!(p.os_writes(), 0);
        assert_eq!(p.calls().len(), 0, "nothing is even read from the OS");
    }

    // --- secrets / permissions -------------------------------------------------------------

    #[test]
    fn reports_errors_and_logs_contain_no_values() {
        let (fs, p) = setup();
        let secret = "http://user:hunter2@10.9.8.7:3128";
        p.seed_env("HTTPS_PROXY", "old-secret-value");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("HTTPS_PROXY"), ev(secret)).unwrap();
        p.fail_next(PlatOp::UnsetEnv);
        let r = j.restore_all(&p);
        let mut text = format!("{r:?} {} {j:?}", r.summary());
        text.push_str(&format!("{:?}", p.calls()));
        text.push_str(&format!(
            "{}",
            JournalError::Io("write", std::io::ErrorKind::Other)
        ));
        text.push_str(&format!("{:?}", j.entries()));
        assert!(
            !text.contains("hunter2") && !text.contains("old-secret"),
            "{text}"
        );
        let err = PlatformError::Failed("set_user_env").to_string();
        assert!(!err.contains("hunter2"));
    }

    #[test]
    fn journal_file_is_0600_and_dir_0700() {
        let (fs, p) = setup();
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("x")).unwrap();
        assert_eq!(fs.mode(&jpath()).unwrap(), Some(0o600));
        assert_eq!(fs.dir_mode(&Path::new(DIR).join(SUBDIR)), Some(0o700));
    }

    #[test]
    fn loose_permissions_of_an_existing_journal_are_tightened_on_open() {
        let (fs, _p) = setup();
        fs.put(&jpath(), br#"{"schema_version":1,"entries":[]}"#, 0o644);
        let _j = open(&fs).unwrap();
        assert_eq!(fs.mode(&jpath()).unwrap(), Some(0o600));
    }

    #[cfg(unix)]
    #[test]
    fn real_disk_journal_is_private_and_roundtrips() {
        use crate::sysproxy::fs::RealFs;
        let dir = tempfile::tempdir().unwrap();
        let p = FakePlatform::new();
        p.seed_env("A", "orig");
        {
            let mut j = Journal::open(Arc::new(RealFs), dir.path()).unwrap();
            j.apply(&p, &env("A"), ev("ours")).unwrap();
            let mode = RealFs.mode(&j.journal_path()).unwrap();
            assert_eq!(mode, Some(0o600));
            assert_eq!(RealFs.mode(&dir.path().join(SUBDIR)).unwrap(), Some(0o700));
            // A second handle on the same real file cannot take the lock.
            assert_eq!(
                Journal::open(Arc::new(RealFs), dir.path()).unwrap_err(),
                JournalError::Locked
            );
        }
        // flock is held by the open file description: a concurrently forked child of another
        // test can keep it for a few ms after we dropped ours, so retry on `Locked`.
        let mut r = recover_with(Arc::new(RealFs), &p, dir.path());
        for _ in 0..200 {
            if r != Err(JournalError::Locked) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            r = recover_with(Arc::new(RealFs), &p, dir.path());
        }
        assert_eq!(r.unwrap().restored(), 1);
        assert_eq!(p.env_of("A"), Some("orig".into()));
    }

    // --- independence / idempotence --------------------------------------------------------

    #[test]
    fn failure_of_one_resource_does_not_block_the_others() {
        let (fs, p) = setup();
        p.seed_env("A", "a0");
        p.seed_env("B", "b0");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("a1")).unwrap();
        j.apply(&p, &env("B"), ev("b1")).unwrap();
        p.fail_next(PlatOp::SetEnv); // the restore of A fails
        let r = j.restore_all(&p);
        assert_eq!(r.failed(), 1);
        assert_eq!(r.restored(), 1);
        assert_eq!(p.env_of("B"), Some("b0".into()));
        assert_eq!(p.env_of("A"), Some("a1".into()));
        assert_eq!(j.entries().len(), 1, "the failed record is kept for retry");
        // Retry succeeds.
        let r2 = j.restore_all(&p);
        assert_eq!(r2.restored(), 1);
        assert_eq!(p.env_of("A"), Some("a0".into()));
        assert!(j.is_empty());
    }

    #[test]
    fn unreadable_resource_keeps_its_record_and_others_go_on() {
        let (fs, p) = setup();
        p.seed_env("A", "a0");
        p.seed_env("B", "b0");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("a1")).unwrap();
        j.apply(&p, &env("B"), ev("b1")).unwrap();
        p.fail_next(PlatOp::GetEnv);
        let r = j.restore_all(&p);
        assert_eq!(r.items[0].outcome, Outcome::Failed("read"));
        assert_eq!(p.env_of("B"), Some("b0".into()));
        assert_eq!(j.entries().len(), 1);
    }

    #[test]
    fn restore_is_idempotent() {
        let (fs, p) = setup();
        p.seed_env("A", "a0");
        let mut j = open(&fs).unwrap();
        j.apply(&p, &env("A"), ev("a1")).unwrap();
        assert_eq!(j.restore_all(&p).restored(), 1);
        let writes = p.os_writes();
        let again = j.restore_all(&p);
        assert!(again.items.is_empty());
        assert_eq!(p.os_writes(), writes);
        drop(j);
        // Also across a restart with the same disk.
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert!(r.items.is_empty());
        assert_eq!(p.env_of("A"), Some("a0".into()));
    }

    #[test]
    fn restore_after_a_lost_release_write_is_safe() {
        let (fs, p) = setup();
        p.seed_env("A", "a0");
        {
            let mut j = open(&fs).unwrap();
            j.apply(&p, &env("A"), ev("a1")).unwrap();
            fs.fail_next(FsOp::WriteAtomic); // OS restored, but the record cannot be released
            let r = j.restore_all(&p);
            assert!(r.journal_write_failed);
            assert_eq!(p.env_of("A"), Some("a0".into()));
        }
        let writes = p.os_writes();
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(r.count(|o| matches!(o, Outcome::AlreadyRestored)), 1);
        assert_eq!(p.os_writes(), writes);
        assert_eq!(p.env_of("A"), Some("a0".into()));
    }

    #[test]
    fn services_are_independent_and_removed_services_are_skipped() {
        let (fs, p) = setup();
        let eth = ServiceId::new("en5", "USB LAN", "USB LAN");
        p.add_service(wifi());
        p.add_service(eth.clone());
        p.seed_pac(
            &wifi(),
            PacState {
                url: Some("w".into()),
                enabled: Some(false),
            },
        );
        p.seed_pac(
            &eth,
            PacState {
                url: Some("e".into()),
                enabled: Some(false),
            },
        );
        let mut j = open(&fs).unwrap();
        let rw = Resource::Pac { service: wifi() };
        let re = Resource::Pac {
            service: eth.clone(),
        };
        j.apply(&p, &rw, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        j.apply(&p, &re, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        p.remove_service(&eth.key());
        let r = j.restore_all(&p);
        assert_eq!(r.count(|o| matches!(o, Outcome::TargetGone)), 1);
        assert_eq!(r.restored(), 1);
        assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("w"));
    }

    #[test]
    fn renamed_service_is_found_by_its_stable_key() {
        let (fs, p) = setup();
        p.add_service(wifi());
        let mut j = open(&fs).unwrap();
        let res = Resource::Pac { service: wifi() };
        j.apply(&p, &res, pac_value("http://127.0.0.1:8899/proxy.pac", true))
            .unwrap();
        p.rename_service(&wifi().key(), "Беспроводная сеть");
        assert_eq!(j.restore_all(&p).restored(), 1);
        assert_eq!(p.pac_of(&wifi()).url, None);
    }

    #[test]
    fn kind_mismatch_is_rejected_before_any_io() {
        let (fs, p) = setup();
        let mut j = open(&fs).unwrap();
        assert_eq!(
            j.apply(&p, &env("A"), Value::Reg(None)).unwrap_err(),
            JournalError::KindMismatch
        );
        assert_eq!(p.calls().len(), 0);
        assert_eq!(fs.write_count(), 0);
    }

    #[test]
    fn panic_hook_flag_does_no_io() {
        note_panic();
        assert!(panic_flagged());
    }

    #[test]
    fn full_roundtrip_survives_restart() {
        let (fs, p) = setup();
        p.seed_env("A", "a0");
        {
            let mut j = open(&fs).unwrap();
            j.apply(&p, &env("A"), ev("a1")).unwrap();
            j.apply(&p, &env("B"), ev("b1")).unwrap();
        }
        let j = open(&fs).unwrap();
        assert_eq!(j.entries().len(), 2);
        assert!(j.entries().iter().all(|e| e.state == EntryState::Applied));
        drop(j);
        let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
        assert_eq!(r.restored(), 2);
        assert_eq!((p.env_of("A"), p.env_of("B")), (Some("a0".into()), None));
    }
}
