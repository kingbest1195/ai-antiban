use super::*;
use std::sync::Mutex;
use tempfile::TempDir;

type RestoreCall = (String, Option<String>, Option<bool>);

struct FakeOsTzPlatform {
    current_iana: Mutex<String>,
    current_win: Mutex<Option<String>>,
    auto_tz: Mutex<Option<bool>>,
    apply_calls: Mutex<Vec<(String, bool)>>,
    restore_calls: Mutex<Vec<RestoreCall>>,
    fail_apply: Mutex<Option<String>>,
    fail_restore: Mutex<Option<String>>,
}

impl FakeOsTzPlatform {
    fn new(iana: &str, win: Option<&str>, auto_tz: Option<bool>) -> Self {
        Self {
            current_iana: Mutex::new(iana.to_string()),
            current_win: Mutex::new(win.map(str::to_string)),
            auto_tz: Mutex::new(auto_tz),
            apply_calls: Mutex::new(Vec::new()),
            restore_calls: Mutex::new(Vec::new()),
            fail_apply: Mutex::new(None),
            fail_restore: Mutex::new(None),
        }
    }
}

impl OsTzPlatform for FakeOsTzPlatform {
    fn current_iana_timezone(&self) -> Result<String, String> {
        Ok(self.current_iana.lock().unwrap().clone())
    }

    fn current_windows_tz_id(&self) -> Result<Option<String>, String> {
        Ok(self.current_win.lock().unwrap().clone())
    }

    fn is_auto_tz_enabled(&self) -> Result<Option<bool>, String> {
        Ok(*self.auto_tz.lock().unwrap())
    }

    fn apply_timezone(&self, target_iana: &str, disable_auto_tz: bool) -> Result<(), String> {
        if let Some(err) = self.fail_apply.lock().unwrap().clone() {
            return Err(err);
        }
        self.apply_calls
            .lock()
            .unwrap()
            .push((target_iana.to_string(), disable_auto_tz));
        *self.current_iana.lock().unwrap() = target_iana.to_string();
        if let Some(win) = iana_to_windows_tz(target_iana) {
            *self.current_win.lock().unwrap() = Some(win.to_string());
        }
        if disable_auto_tz {
            *self.auto_tz.lock().unwrap() = Some(false);
        }
        Ok(())
    }

    fn restore_timezone(
        &self,
        orig_iana: &str,
        orig_win_id: Option<&str>,
        restore_auto_tz: Option<bool>,
    ) -> Result<(), String> {
        if let Some(err) = self.fail_restore.lock().unwrap().clone() {
            return Err(err);
        }
        self.restore_calls.lock().unwrap().push((
            orig_iana.to_string(),
            orig_win_id.map(str::to_string),
            restore_auto_tz,
        ));
        *self.current_iana.lock().unwrap() = orig_iana.to_string();
        *self.current_win.lock().unwrap() = orig_win_id.map(str::to_string);
        if let Some(auto) = restore_auto_tz {
            *self.auto_tz.lock().unwrap() = Some(auto);
        }
        Ok(())
    }
}

#[test]
fn iana_windows_mapping_covers_common_zones_and_aliases() {
    assert_eq!(
        iana_to_windows_tz("Europe/Paris"),
        Some("Romance Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Madrid"),
        Some("Romance Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Warsaw"),
        Some("Central European Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Berlin"),
        Some("W. Europe Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Amsterdam"),
        Some("W. Europe Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/London"),
        Some("GMT Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Helsinki"),
        Some("FLE Standard Time")
    );
    assert_eq!(iana_to_windows_tz("Europe/Kyiv"), Some("FLE Standard Time"));
    assert_eq!(iana_to_windows_tz("Europe/Kiev"), Some("FLE Standard Time"));
    assert_eq!(
        iana_to_windows_tz("Europe/Bucharest"),
        Some("GTB Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Moscow"),
        Some("Russian Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Minsk"),
        Some("Belarus Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Europe/Istanbul"),
        Some("Turkey Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Dubai"),
        Some("Arabian Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Tbilisi"),
        Some("Georgian Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Yerevan"),
        Some("Caucasus Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Almaty"),
        Some("West Asia Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Calcutta"),
        Some("India Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Tokyo"),
        Some("Tokyo Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Singapore"),
        Some("Singapore Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Asia/Hong_Kong"),
        Some("China Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("America/New_York"),
        Some("Eastern Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("America/Chicago"),
        Some("Central Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("America/Denver"),
        Some("Mountain Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("America/Los_Angeles"),
        Some("Pacific Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("America/Sao_Paulo"),
        Some("E. South America Standard Time")
    );
    assert_eq!(
        iana_to_windows_tz("Australia/Sydney"),
        Some("AUS Eastern Standard Time")
    );
    assert_eq!(iana_to_windows_tz("UTC"), Some("UTC"));
    assert_eq!(iana_to_windows_tz("Etc/UTC"), Some("UTC"));

    assert_eq!(
        windows_to_iana_tz("Romance Standard Time"),
        Some("Europe/Paris")
    );
    assert_eq!(
        windows_to_iana_tz("Russian Standard Time"),
        Some("Europe/Moscow")
    );
    assert_eq!(
        windows_to_iana_tz("W. Europe Standard Time"),
        Some("Europe/Berlin")
    );
    assert_eq!(
        windows_to_iana_tz("Eastern Standard Time"),
        Some("America/New_York")
    );
    assert!(allowlisted_windows_tz_id("Romance Standard Time").is_some());
    assert!(allowlisted_windows_tz_id("Romance Standard Time; rm -rf").is_none());
}

#[test]
fn dry_run_prevents_real_os_effects_in_tests() {
    assert!(!os_tz_effects_enabled());
}

#[test]
fn sync_writes_atomic_baseline_preserves_original_on_resync_and_restores() {
    let dir = TempDir::new().unwrap();
    let fake =
        FakeOsTzPlatform::new("Europe/Moscow", Some("Russian Standard Time"), Some(true));

    let status = sync_os_timezone_with(&fake, dir.path(), "Europe/Amsterdam").unwrap();
    assert!(status.synced);
    assert!(status.auto_restore_pending);
    assert_eq!(status.current_os_tz.as_deref(), Some("Europe/Amsterdam"));
    assert_eq!(status.original_os_tz.as_deref(), Some("Europe/Moscow"));
    assert_eq!(status.synced_target_tz.as_deref(), Some("Europe/Amsterdam"));

    let saved = read_baseline(dir.path()).unwrap().unwrap();
    assert_eq!(saved.original_iana, "Europe/Moscow");
    assert_eq!(
        saved.original_windows_id.as_deref(),
        Some("Russian Standard Time")
    );
    assert_eq!(saved.original_auto_tz, Some(true));
    assert_eq!(saved.synced_iana, "Europe/Amsterdam");

    #[cfg(unix)]
    {
        let mode = RealFs.mode(&baseline_path(dir.path())).unwrap().unwrap();
        assert_eq!(mode, 0o600);
    }

    // Re-syncing to another exit node must keep the original Moscow baseline intact.
    let status2 = sync_os_timezone_with(&fake, dir.path(), "Europe/Paris").unwrap();
    assert_eq!(status2.original_os_tz.as_deref(), Some("Europe/Moscow"));
    assert_eq!(status2.synced_target_tz.as_deref(), Some("Europe/Paris"));
    let saved2 = read_baseline(dir.path()).unwrap().unwrap();
    assert_eq!(saved2.original_iana, "Europe/Moscow");
    assert_eq!(saved2.original_auto_tz, Some(true));
    assert_eq!(saved2.synced_iana, "Europe/Paris");

    // Restoring returns to Moscow + restores auto_tz = true, and removes baseline.
    let restored = restore_os_timezone_with(&fake, dir.path()).unwrap();
    assert!(!restored.synced);
    assert!(!restored.auto_restore_pending);
    assert_eq!(restored.current_os_tz.as_deref(), Some("Europe/Moscow"));
    assert!(read_baseline(dir.path()).unwrap().is_none());
    assert_eq!(*fake.auto_tz.lock().unwrap(), Some(true));
}

#[test]
fn sync_refuses_sanctioned_tz_and_cleans_up_on_elevation_cancel() {
    let dir = TempDir::new().unwrap();
    let fake =
        FakeOsTzPlatform::new("Europe/Moscow", Some("Russian Standard Time"), Some(false));

    // Refuse syncing TO a Russian/Belarusian timezone.
    let err = sync_os_timezone_with(&fake, dir.path(), "Europe/Minsk").unwrap_err();
    assert!(err.contains("РФ/РБ"), "{err}");
    assert!(read_baseline(dir.path()).unwrap().is_none());

    // Elevation cancelled leaves OS unchanged and removes newly created baseline.
    *fake.fail_apply.lock().unwrap() = Some("OS_TZ_ELEVATION_CANCELLED: cancelled".to_string());
    let err = sync_os_timezone_with(&fake, dir.path(), "Europe/Berlin").unwrap_err();
    assert!(err.starts_with("OS_TZ_ELEVATION_CANCELLED:"), "{err}");
    assert!(read_baseline(dir.path()).unwrap().is_none());
    assert_eq!(fake.current_iana_timezone().unwrap(), "Europe/Moscow");
}

#[test]
fn restore_failure_preserves_baseline_for_retry_and_startup_recovery() {
    let dir = TempDir::new().unwrap();
    let fake =
        FakeOsTzPlatform::new("Europe/Moscow", Some("Russian Standard Time"), Some(false));

    sync_os_timezone_with(&fake, dir.path(), "Europe/London").unwrap();

    // Simulate user cancelling restore prompt on quit / disable.
    *fake.fail_restore.lock().unwrap() =
        Some("OS_TZ_ELEVATION_CANCELLED: cancelled".to_string());
    assert!(restore_if_synced_on_disable_with(&fake, dir.path()).is_err());
    assert!(read_baseline(dir.path()).unwrap().is_some());

    // Next startup recovery succeeds once elevation is permitted.
    *fake.fail_restore.lock().unwrap() = None;
    recover_baseline_on_start_with(&fake, dir.path());
    assert!(read_baseline(dir.path()).unwrap().is_none());
    assert_eq!(fake.current_iana_timezone().unwrap(), "Europe/Moscow");
}

#[test]
fn validates_iana_names_strictly() {
    assert!(validate_iana_tz("Europe/Berlin").is_ok());
    assert!(validate_iana_tz("America/Argentina/Buenos_Aires").is_ok());
    assert!(validate_iana_tz("Etc/GMT+3").is_ok());
    assert!(validate_iana_tz("Europe/Berlin; rm -rf /").is_err());
    assert!(validate_iana_tz("../etc/passwd").is_err());
    assert!(validate_iana_tz("/usr/share/zoneinfo/UTC").is_err());
    assert!(validate_iana_tz("").is_err());
}
