//! System PAC and the chained upstream proxy of every network service (macOS).
//!
//! Everything goes through the ownership journal and `Platform`: before a service's PAC or
//! explicit proxy is touched, its exact previous state is recorded durably; the restore puts back
//! only what Zastava itself wrote. The logic is platform-neutral (it only talks to `Platform`),
//! so it is tested with `FakePlatform` on every OS; `RealPlatform` implements `networksetup`.

use super::EnableReport;
use super::journal::Journal;
use super::platform::Platform;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Returned when `networksetup` fails because macOS requires administrator authorization.
/// The exact `"ADMIN_AUTH_REQUIRED:"` prefix lets the frontend offer a privileged retry.
pub(super) const MSG_ADMIN_AUTH_REQUIRED: &str = "ADMIN_AUTH_REQUIRED:Не удалось изменить \
системный прокси без прав администратора macOS. Нажмите «Разрешить с паролем», чтобы \
подтвердить настройку.";

/// Shown when every enabled network service is a VPN: nothing is written into those.
pub(super) const MSG_ONLY_VPN: &str = "Защита не включена: все активные сетевые службы - VPN, а \
Застава не меняет настройки VPN-служб (подключённый VPN мог бы разорваться). Включите Wi-Fi или \
Ethernet либо настройте системный прокси в самом VPN-клиенте. Системные настройки не менялись.";

/// The type of the services could not be established, so nothing is written (a VPN service could
/// be among them).
pub(super) const MSG_KIND_UNKNOWN: &str = "Защита не включена: не удалось определить тип сетевых \
служб (список VPN-подключений недоступен), а менять VPN-службы нельзя. Системные настройки не \
менялись.";

/// How far back a foreign rewrite still counts for the self-heal.
pub(super) const HEAL_WINDOW: Duration = Duration::from_secs(120);
/// Foreign rewrites of one service within [`HEAL_WINDOW`] after which the self-heal leaves it.
pub(super) const HEAL_MAX_REWRITES: usize = 3;

/// Keeps the self-heal from fighting a VPN client (or any tool) that keeps rewriting the PAC of a
/// service: after [`HEAL_MAX_REWRITES`] foreign rewrites within [`HEAL_WINDOW`] that service is
/// left alone until the set of services changes or the protection is switched on again.
pub(super) struct HealGuard {
    st: Mutex<HealState>,
}

struct HealState {
    seen: BTreeMap<String, Vec<Instant>>,
    suspended: BTreeSet<String>,
    /// Keys of the services the last pass looked at: a change means another network.
    fingerprint: Vec<String>,
}

impl HealGuard {
    pub(super) const fn new() -> Self {
        Self {
            st: Mutex::new(HealState {
                seen: BTreeMap::new(),
                suspended: BTreeSet::new(),
                fingerprint: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HealState> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Forgets everything (the protection was switched on explicitly).
    pub(super) fn reset(&self) {
        let mut st = self.lock();
        st.seen.clear();
        st.suspended.clear();
        st.fingerprint.clear();
    }

    pub(super) fn is_suspended(&self, key: &str) -> bool {
        self.lock().suspended.contains(key)
    }

    /// A different set of services is another network: start over.
    pub(super) fn network(&self, fingerprint: Vec<String>) {
        let mut st = self.lock();
        if st.fingerprint != fingerprint {
            st.seen.clear();
            st.suspended.clear();
            st.fingerprint = fingerprint;
        }
    }

    /// Records a foreign rewrite; `true` when this one makes the service suspended.
    pub(super) fn note_rewrite(&self, key: &str, now: Instant) -> bool {
        let mut st = self.lock();
        let list = st.seen.entry(key.to_string()).or_default();
        list.retain(|t| now.saturating_duration_since(*t) < HEAL_WINDOW);
        list.push(now);
        if list.len() >= HEAL_MAX_REWRITES {
            return st.suspended.insert(key.to_string());
        }
        false
    }
}

/// The one line the log and the coverage screen show when a connected VPN service was skipped.
/// Names of services only, no values.
pub(crate) fn vpn_untouched_line(names: &[String]) -> String {
    format!("VPN-службы не изменялись: {}", names.join(", "))
}



/// Puts the PAC on every enabled physical network service and switches a third-party explicit
/// proxy off (it is chained through the PAC instead). Used for the first enable and for
/// self-healing: a repeated call changes nothing that already is as it should be.
///
/// When a VPN keeps temporary DNS settings (or DNS state cannot be checked), `networksetup` PAC
/// writes are deferred (`os_pac_deferred = true`, zero OS writes) instead of refusing activation,
/// so browser PAC policies and CLI/IDE protection can still enable cleanly. Disabled services are
/// not touched; services that appeared since the last call are picked up.
pub(super) fn enable_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
) -> Result<EnableReport, String> {
    apply_pac(j, p, pac_url, None)
}

/// The self-heal pass: the same as [`enable_pac`], but a service that something else keeps
/// rewriting is given up on (see [`HealGuard`]).
pub(super) fn refresh_pac(
    j: &mut Journal,
    p: &dyn Platform,
    pac_url: &str,
    heal: &HealGuard,
    now: Instant,
) -> Result<EnableReport, String> {
    apply_pac(j, p, pac_url, Some((heal, now)))
}

mod apply;
mod planner;
mod privileged;

use apply::apply_pac;
pub(super) use privileged::enable_pac_privileged;
#[cfg(test)]
#[allow(unused_imports)]
use privileged::{
    applescript_string_literal, build_osascript_arg, build_privileged_networksetup_script,
    enable_pac_privileged_with, is_safe_pac_url, posix_single_quote,
};

#[cfg(test)]
#[path = "../macos_tests/mod.rs"]
mod tests;

#[cfg(test)]
#[allow(unused_imports)]
use super::journal::{ApplyOutcome, EntryState, JournalError, Outcome, Resource, Value};
#[cfg(test)]
#[allow(unused_imports)]
use super::platform::{
    ChainState, PacState, PlatformError, ProxyEndpoint, ServiceId, is_admin_auth_error,
};
#[cfg(test)]
#[allow(unused_imports)]
use planner::MSG_INCOMPATIBLE_ACROSS;
