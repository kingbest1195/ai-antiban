//! Journal outcomes, errors, recovery reports, and restore/recovery passes.

use super::Journal;
use super::entry::Resource;
use super::io::{Notified, notify, read_value, write_value};
use crate::sysproxy::fs::Fs;
use crate::sysproxy::platform::{Platform, PlatformError};
use std::fmt;
use std::path::Path;
use std::sync::Arc;

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
    /// Somebody else changed the resource after us: the foreign value became the new baseline and
    /// our value was written on top of it.
    Rebased,
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
    /// Deliberately not touched now (e.g. the service is a connected VPN); the record is kept and
    /// a later pass finishes it. Not an error. Reason name only.
    Skipped(&'static str),
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
    /// A network setting (PAC / explicit proxy) was NOT restored because an active VPN keeps
    /// temporary DNS settings: it stays in the journal and is put back at the next start.
    pub fn restore_deferred_by_vpn_dns(&self) -> bool {
        self.count(|o| matches!(o, Outcome::Failed("temp_dns"))) > 0
    }
    /// Every reported failure is solely `Outcome::Failed("temp_dns")` (no journal write error or
    /// other failed restore): protection can be marked off while OS proxy restore waits for VPN.
    pub fn is_only_vpn_dns_deferred(&self) -> bool {
        !self.journal_write_failed
            && self.failed() > 0
            && self.failed() == self.count(|o| matches!(o, Outcome::Failed("temp_dns")))
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

impl Journal {
    /// Restores every recorded resource. A failure of one never blocks the others; repeating the
    /// pass is safe. Returns a report with resource names and outcomes only.
    pub fn restore_all(&mut self, platform: &dyn Platform) -> RecoveryReport {
        self.restore_where(platform, |_| true)
    }

    /// Restores the recorded resources selected by `select`; the others stay untouched.
    pub fn restore_where(
        &mut self,
        platform: &dyn Platform,
        select: impl Fn(&Resource) -> bool,
    ) -> RecoveryReport {
        let mut ids: Vec<Resource> = self
            .entries
            .iter()
            .map(|e| e.resource.clone())
            .filter(|r| select(r))
            .collect();
        // Keys before the objects that held them, objects before the files (stable otherwise).
        ids.sort_by_key(Resource::restore_rank);
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
        let outcome = match read_value(&*self.fs, platform, &*self.policy_store, res) {
            Err(PlatformError::NotFound(_)) => Outcome::TargetGone,
            Err(_) => return Outcome::Failed("read"),
            Ok(cur) => {
                let ours = entry.is_ours(&cur);
                if cur == entry.baseline {
                    // A notification that failed earlier is repeated before the record goes.
                    if entry.notify_pending && notify(platform, res) == Notified::Failed {
                        return Outcome::Failed("notify");
                    }
                    Outcome::AlreadyRestored
                } else if !ours {
                    Outcome::ExternalChange
                } else {
                    // Narrow the window for a concurrent change: read once more right before writing.
                    match read_value(&*self.fs, platform, &*self.policy_store, res) {
                        Ok(again) if again == cur => {}
                        Ok(_) => {
                            return self.release(platform, res, Outcome::ExternalChange, report);
                        }
                        Err(_) => return Outcome::Failed("read"),
                    }
                    match write_value(
                        &*self.fs,
                        platform,
                        &*self.policy_store,
                        res,
                        &entry.baseline,
                    ) {
                        Ok(Notified::Yes) => Outcome::Restored,
                        Ok(Notified::Failed) => {
                            // The baseline is back; keep the record so the notification is retried.
                            self.entries[i].notify_pending = true;
                            if self.persist(platform).is_err() {
                                report.journal_write_failed = true;
                            }
                            return Outcome::Failed("notify");
                        }
                        Err(_) => return Outcome::Failed("write"),
                    }
                }
            }
        };
        self.release(platform, res, outcome, report)
    }
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
