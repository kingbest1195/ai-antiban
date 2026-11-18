//! Ownership journal: what Zastava changed in the system and what was there before.
//!
//! Guarantee: Zastava restores ONLY what it changed itself and never guesses.
//! * Before the first OS write of a resource, an intent with the exact `baseline` (the value that
//!   was there before us, including "no value" and the type) is written durably
//!   (temp file -> fsync -> rename -> fsync dir). If that write fails, nothing is written to the OS.
//! * A repeated `apply` never replaces the baseline, with one exception: when somebody else changed
//!   the resource after us, that foreign value becomes the new baseline (what we will restore) and
//!   our value is written on top. Zastava's protection is never silently switched off by a
//!   foreign change, and the foreign value is never lost.
//! * Restore: current == what we wrote (`expected`, or the in-flight `pending`) -> write baseline back
//!   (or delete when baseline was "no value"); anything else is an external change that is left
//!   alone and the record is released with a mark.
//! * Unknown schema version, corrupt file or a lock held by another process -> fail closed:
//!   no operation is possible and the file is never deleted or overwritten.
//!
//! Values (PAC URLs, proxy hosts, credentials) live only in the 0600 journal file; errors, reports
//! and the `Debug` output name resources, never values.

mod apply;
mod entry;
mod io;
mod recovery;

pub use entry::{Entry, EntryState, Resource, Value};
pub use recovery::{
    ApplyOutcome, JournalError, Outcome, RecoveryReport, ReportItem, recover_with,
};

use crate::sysproxy::browser_policies::{PolicyStore, RealPolicyStore};
use crate::sysproxy::fs::{Fs, FsLock, LockError, WriteMode};
use crate::sysproxy::platform::Platform;
use entry::{FileData, parse};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub const SCHEMA_VERSION: u32 = 1;
const SUBDIR: &str = "ownership";
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "journal.lock";
const APP_LOCK_FILE: &str = "app.lock";

/// The directory the journal and its locks live in.
pub fn ownership_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(SUBDIR)
}

/// The lock a running Zastava holds for its whole life (see `sysproxy::hold_app_lock`).
pub fn app_lock_path(data_dir: &Path) -> PathBuf {
    ownership_dir(data_dir).join(APP_LOCK_FILE)
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

/// The ownership journal. Holds the inter-process lock for as long as it lives.
pub struct Journal {
    pub(super) fs: Arc<dyn Fs>,
    pub(super) policy_store: Arc<dyn PolicyStore>,
    root: PathBuf,
    pub(super) entries: Vec<Entry>,
    marks: Vec<String>,
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
        Self::open_migrating(fs, data_dir, None)
    }

    /// [`Journal::open`] for a journal that moved: when `data_dir` has no journal yet and
    /// `legacy_dir` (the previous location) has one, it is carried over (written to the new place
    /// first, then removed from the old one). A journal already in the new place always wins.
    pub fn open_migrating(
        fs: Arc<dyn Fs>,
        data_dir: &Path,
        legacy_dir: Option<&Path>,
    ) -> Result<Journal, JournalError> {
        let root = ownership_dir(data_dir);
        fs.create_private_dir_all(&root)
            .map_err(|e| JournalError::Io("create_dir", e.kind()))?;
        let lock = fs.try_lock(&root.join(LOCK_FILE)).map_err(|e| match e {
            LockError::Held => JournalError::Locked,
            LockError::Io(k) => JournalError::Io("lock", k),
        })?;
        // We hold the lock: a temp file of an earlier, killed write is garbage now.
        fs.sweep_stale_tmp(&root);
        let path = root.join(JOURNAL_FILE);
        let mut found = fs
            .read(&path)
            .map_err(|e| JournalError::Io("read", e.kind()))?;
        if found.is_none()
            && let Some(old) = legacy_dir.filter(|d| *d != data_dir)
        {
            let old_path = ownership_dir(old).join(JOURNAL_FILE);
            if let Some(bytes) = fs
                .read(&old_path)
                .map_err(|e| JournalError::Io("read", e.kind()))?
            {
                fs.write_atomic(&path, &bytes, WriteMode::Private)
                    .map_err(|e| JournalError::Io("write", e.kind()))?;
                // The copy is durable; the old file must not be read again. Best effort.
                let _ = fs.remove_file(&old_path);
                found = Some(bytes);
            }
        }
        let (entries, marks) = match found {
            None => (Vec::new(), Vec::new()),
            Some(bytes) => {
                let parsed = parse(&bytes)?;
                // An older build or a manual copy may have left loose permissions.
                if matches!(fs.mode(&path), Ok(Some(m)) if m & 0o077 != 0) {
                    let _ = fs.set_mode(&path, 0o600);
                }
                parsed
            }
        };
        Ok(Journal {
            fs,
            policy_store: Arc::new(RealPolicyStore),
            root,
            entries,
            marks,
            backup_excluded: false,
            _lock: lock,
        })
    }

    pub(in crate::sysproxy) fn policy_store_arc(&self) -> Arc<dyn PolicyStore> {
        Arc::clone(&self.policy_store)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_policy_store(mut self, policy_store: Arc<dyn PolicyStore>) -> Self {
        self.policy_store = policy_store;
        self
    }

    /// The file system the journal (and its file resources) works on.
    pub fn fs(&self) -> Arc<dyn Fs> {
        self.fs.clone()
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
    pub(super) fn persist(&mut self, platform: &dyn Platform) -> Result<(), JournalError> {
        if !self.backup_excluded {
            self.backup_excluded = true;
            let _ = platform.exclude_from_backup(&self.root);
        }
        let data = FileData {
            schema_version: SCHEMA_VERSION,
            entries: self.entries.clone(),
            marks: self.marks.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&data).map_err(|_| JournalError::Corrupt)?;
        self.fs
            .write_atomic(&self.journal_path(), &bytes, WriteMode::Private)
            .map_err(|e| JournalError::Io("write", e.kind()))
    }

    pub(super) fn index_of(&self, res: &Resource) -> Option<usize> {
        self.entries.iter().position(|e| &e.resource == res)
    }

    /// Puts the in-memory record back to `before` (`None` = no record).
    pub(super) fn put_back(&mut self, res: &Resource, before: Option<Entry>) {
        match (self.index_of(res), before) {
            (Some(i), Some(b)) => self.entries[i] = b,
            (Some(i), None) => {
                self.entries.remove(i);
            }
            (None, Some(b)) => self.entries.push(b),
            (None, None) => {}
        }
    }

    /// Whether the resource currently holds a value Zastava wrote itself (`cur` equals the last
    /// confirmed or the in-flight value of its record). `false` without a record.
    pub fn owns(&self, res: &Resource, cur: &Value) -> bool {
        self.entry(res).is_some_and(|e| e.is_ours(cur))
    }

    /// Whether the one-shot marker `name` is set.
    pub fn has_mark(&self, name: &str) -> bool {
        self.marks.iter().any(|m| m == name)
    }

    /// Sets a one-shot marker durably (same file, same lock, atomic replace). If the write fails
    /// the marker is not set.
    pub fn set_mark(&mut self, platform: &dyn Platform, name: &str) -> Result<(), JournalError> {
        if self.has_mark(name) {
            return Ok(());
        }
        self.marks.push(name.to_string());
        if let Err(e) = self.persist(platform) {
            self.marks.retain(|m| m != name);
            return Err(e);
        }
        Ok(())
    }

    /// Drops the record and persists. If persisting fails the record stays on disk and the next
    /// pass finds the resource already restored / not ours, which is safe.
    pub(super) fn release(
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

#[cfg(test)]
use crate::sysproxy::platform::{ChainState, PacState, PlatformError, RegValue, ServiceId};
#[cfg(test)]
use entry::{file_label, urls_equivalent};

#[cfg(test)]
#[path = "../journal_tests/mod.rs"]
mod tests;
