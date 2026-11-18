//! Single-resource and batch `Journal::apply` with durable `Pending` intents.

use super::entry::{
    Entry, EntryState, Resource, Value, carries_zastava_signature, neutral_pac_baseline,
    same_as_written,
};
use super::io::{Notified, notify, read_value, write_value};
use super::{ApplyOutcome, Journal, JournalError};
use crate::sysproxy::platform::Platform;

struct PreparedApply {
    res: Resource,
    new: Value,
    previous: Value,
    before: Option<Entry>,
    outcome: ApplyOutcome,
}

impl Journal {
    /// Prepares a single entry in-memory as `Pending` (or handles `Unchanged`/leftover adoption).
    /// Returns `Ok(None)` when no OS write is required (`ApplyOutcome::Unchanged`).
    fn prepare_apply(
        &mut self,
        platform: &dyn Platform,
        res: &Resource,
        new: Value,
    ) -> Result<Option<PreparedApply>, JournalError> {
        if !new.matches(res) {
            return Err(JournalError::KindMismatch);
        }
        let cur = read_value(&*self.fs, platform, &*self.policy_store, res)?;
        // `previous` = what the resource holds when nothing of this write has landed yet;
        // `before` = the record as it was on disk, for an exact in-memory rollback.
        let previous = cur.clone();
        let before = self.entry(res).cloned();
        let mut outcome = ApplyOutcome::Applied;
        match self.index_of(res) {
            None => {
                // A PAC with our own address and no record is a leftover of a build without a
                // journal (2.0.0). It is never the baseline (a restore would put our PAC back);
                // the state before Zastava is taken as "off", the same as the legacy cleanup does.
                let leftover_pac = matches!(res, Resource::Pac { .. })
                    && carries_zastava_signature(res, &cur, &new);
                let leftover_policy = matches!(
                    res,
                    Resource::BrowserPolicy { key, .. }
                        if key == crate::sysproxy::browser_policies::KEY_PROXY_PAC_URL
                ) && carries_zastava_signature(res, &cur, &new);
                let leftover_browser_pref = matches!(res, Resource::BrowserPacPref { .. })
                    && carries_zastava_signature(res, &cur, &new);
                let neutral_baseline = if leftover_policy {
                    Some(Value::Policy(None))
                } else if leftover_browser_pref {
                    Some(Value::Json(None))
                } else if leftover_pac {
                    Some(neutral_pac_baseline())
                } else {
                    None
                };
                if same_as_written(res, &cur, &new)
                    && let Some(baseline) = neutral_baseline
                {
                    // Already what we want: adopt it without a single OS write.
                    self.entries.push(Entry {
                        resource: res.clone(),
                        baseline,
                        expected: Some(cur),
                        pending: None,
                        state: EntryState::Applied,
                        notify_pending: false,
                    });
                    if let Err(err) = self.persist(platform) {
                        self.put_back(res, before);
                        return Err(err);
                    }
                    return Ok(None);
                }
                self.entries.push(Entry {
                    resource: res.clone(),
                    baseline: neutral_baseline.unwrap_or(cur),
                    expected: None,
                    pending: Some(new.clone()),
                    state: EntryState::Pending,
                    notify_pending: false,
                });
            }
            Some(i) => {
                let e = &mut self.entries[i];
                // Unchanged: the OS still holds what we wrote last, and that is `new` (the OS may
                // have normalised the URL, so the stored value is the one that was read back).
                if e.state == EntryState::Applied
                    && e.expected.as_ref() == Some(&cur)
                    && same_as_written(res, &cur, &new)
                {
                    if e.notify_pending {
                        // The value is in place; only the earlier notification is still owed.
                        if notify(platform, res) == Notified::Yes {
                            e.notify_pending = false;
                            self.persist(platform)?;
                        }
                    }
                    return Ok(None);
                }
                let ours = e.is_ours(&cur) || carries_zastava_signature(res, &cur, &new);
                if !ours && cur != e.baseline && cur != new {
                    // A foreign change after us: it becomes the baseline. Names only in the log.
                    eprintln!(
                        "Застава: внешнее изменение {} принято как исходное",
                        res.id()
                    );
                    e.baseline = cur;
                    e.expected = None;
                    outcome = ApplyOutcome::Rebased;
                }
                // Otherwise the baseline stays as it is, and so does the previous `expected`, so
                // a crash in the middle of the update can still be recognised and restored.
                e.pending = Some(new.clone());
                e.state = EntryState::Pending;
            }
        }
        Ok(Some(PreparedApply {
            res: res.clone(),
            new,
            previous,
            before,
            outcome,
        }))
    }

    /// Reads back `res` after a successful write and marks its journal entry `Applied` in memory.
    fn mark_applied_in_memory(
        &mut self,
        platform: &dyn Platform,
        prep: PreparedApply,
        notified: Notified,
    ) -> Result<ApplyOutcome, JournalError> {
        let i = self.index_of(&prep.res).ok_or(JournalError::Corrupt)?;
        // What the OS holds now is what restore will compare against: the OS may normalise a
        // URL or a port, and the value we asked for would then never be found again. If the
        // read fails, or shows the old baseline (the write is not visible yet), `new` stays.
        let stored = match read_value(&*self.fs, platform, &*self.policy_store, &prep.res) {
            Ok(v) if v.matches(&prep.res) && v != self.entries[i].baseline => v,
            _ => prep.new,
        };
        let e = &mut self.entries[i];
        e.expected = Some(stored);
        e.pending = None;
        e.state = EntryState::Applied;
        e.notify_pending = notified == Notified::Failed;
        Ok(prep.outcome)
    }

    /// Writes `new` to `res` with a persistent journal record of what was there before.
    ///
    /// First use records the current value as the baseline and writes `new` on top
    /// ([`ApplyOutcome::Applied`]). When the resource already holds what we wrote last (even if it
    /// was left behind by a previous build without a journal), it is left alone
    /// ([`ApplyOutcome::Unchanged`]).
    ///
    /// If the resource holds neither our value nor the baseline, somebody else changed it after
    /// us: that value becomes the new baseline (durably, before the write) and `new` is written
    /// on top ([`ApplyOutcome::Rebased`]).
    pub fn apply(
        &mut self,
        platform: &dyn Platform,
        res: &Resource,
        new: Value,
    ) -> Result<ApplyOutcome, JournalError> {
        let Some(prep) = self.prepare_apply(platform, res, new)? else {
            return Ok(ApplyOutcome::Unchanged);
        };
        if let Err(err) = self.persist(platform) {
            // Intent is not durable: forget the in-memory change, the OS is untouched.
            self.put_back(res, prep.before);
            return Err(err);
        }
        let notified = match write_value(&*self.fs, platform, &*self.policy_store, res, &prep.new) {
            Ok(n) => n,
            Err(werr) => {
                self.settle_failed_write(platform, res, &prep.previous, prep.before);
                return Err(werr.into());
            }
        };
        let outcome = self.mark_applied_in_memory(platform, prep, notified)?;
        self.persist(platform)?;
        Ok(outcome)
    }

    /// Applies multiple resources via a single batch writer (e.g. an elevated `osascript` run)
    /// while preserving full `Pending -> write -> readback -> Applied` journal crash-safety.
    pub(in crate::sysproxy) fn apply_batch<F>(
        &mut self,
        platform: &dyn Platform,
        items: Vec<(Resource, Value)>,
        writer: F,
    ) -> Result<Vec<(Resource, ApplyOutcome)>, JournalError>
    where
        F: FnOnce(&[(Resource, Value)]) -> Result<(), JournalError>,
    {
        let mut preps: Vec<PreparedApply> = Vec::new();
        let mut plan: Vec<(Resource, Option<usize>)> = Vec::with_capacity(items.len());
        for (res, new) in items {
            match self.prepare_apply(platform, &res, new) {
                Ok(Some(prep)) => {
                    let idx = preps.len();
                    preps.push(prep);
                    plan.push((res, Some(idx)));
                }
                Ok(None) => plan.push((res, None)),
                Err(err) => {
                    for p in preps.into_iter().rev() {
                        self.put_back(&p.res, p.before);
                    }
                    return Err(err);
                }
            }
        }
        if preps.is_empty() {
            return Ok(plan
                .into_iter()
                .map(|(r, _)| (r, ApplyOutcome::Unchanged))
                .collect());
        }
        if let Err(err) = self.persist(platform) {
            for p in preps.into_iter().rev() {
                self.put_back(&p.res, p.before);
            }
            return Err(err);
        }
        let to_write: Vec<(Resource, Value)> = preps
            .iter()
            .map(|p| (p.res.clone(), p.new.clone()))
            .collect();
        if let Err(err) = writer(&to_write) {
            for p in preps.into_iter().rev() {
                self.settle_failed_write(platform, &p.res, &p.previous, p.before);
            }
            return Err(err);
        }
        let mut prep_outcomes = Vec::with_capacity(preps.len());
        for p in preps {
            let notified = notify(platform, &p.res);
            prep_outcomes.push(self.mark_applied_in_memory(platform, p, notified)?);
        }
        self.persist(platform)?;
        Ok(plan
            .into_iter()
            .map(|(r, idx)| {
                let outcome = idx.map_or(ApplyOutcome::Unchanged, |i| prep_outcomes[i]);
                (r, outcome)
            })
            .collect())
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
        let clean = match read_value(&*self.fs, platform, &*self.policy_store, res) {
            Ok(v) if &v == previous => true,
            Ok(_) => write_value(&*self.fs, platform, &*self.policy_store, res, previous).is_ok(),
            Err(_) => false,
        };
        if clean {
            self.put_back(res, before);
            let _ = self.persist(platform);
        }
        // else: stays Pending on disk; the recovery pass decides from the real value
    }
}
