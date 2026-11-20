use super::*;
use crate::sysproxy::fs::FsOp;
use crate::sysproxy::platform::{FakePlatform, PlatOp};

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

// --- marks, notifications, selective restore ---------------------------------------------

#[test]
fn marker_is_durable_and_does_not_need_any_entry() {
    let (fs, p) = setup();
    {
        let mut j = open(&fs).unwrap();
        assert!(!j.has_mark("m"));
        j.set_mark(&p, "m").unwrap();
        j.set_mark(&p, "m").unwrap(); // idempotent
    }
    let j = open(&fs).unwrap();
    assert!(j.has_mark("m"));
    assert!(j.is_empty());
}

#[test]
fn marker_is_not_set_when_it_cannot_be_written() {
    let (fs, p) = setup();
    let mut j = open(&fs).unwrap();
    fs.fail_next(FsOp::WriteAtomic);
    assert!(j.set_mark(&p, "m").is_err());
    assert!(!j.has_mark("m"));
    drop(j);
    assert!(!open(&fs).unwrap().has_mark("m"));
}

#[test]
fn journal_without_marks_from_an_older_file_still_opens() {
    let (fs, _p) = setup();
    fs.put(&jpath(), br#"{"schema_version":1,"entries":[]}"#, 0o600);
    assert!(open(&fs).is_ok());
}

#[test]
fn broadcast_failure_keeps_the_record_and_the_next_pass_repeats_it() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.fail_next(PlatOp::BroadcastEnv);
    let r = j.restore_all(&p);
    assert_eq!(r.failed(), 1);
    assert_eq!(p.env_of("A"), Some("orig".into()), "the value is back");
    assert!(!j.is_empty());
    let writes = p.os_writes();
    let r = j.restore_all(&p);
    assert_eq!(r.failed(), 0);
    assert_eq!(
        p.os_writes(),
        writes,
        "only the notification is repeated, no second write"
    );
    assert!(j.is_empty());
}

#[test]
fn no_broadcast_when_nothing_really_changed() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("ours")).unwrap();
    p.seed_env("A", "foreign");
    p.clear_calls();
    j.restore_all(&p);
    assert!(
        !p.calls()
            .iter()
            .any(|c| c.starts_with("broadcast_env_change"))
    );
}

#[test]
fn restore_where_leaves_other_resources_alone() {
    let (fs, p) = setup();
    p.add_service(wifi());
    let mut j = open(&fs).unwrap();
    j.apply(&p, &env("A"), ev("x")).unwrap();
    let pac = Resource::Pac { service: wifi() };
    j.apply(&p, &pac, pac_value("http://127.0.0.1:8899/proxy.pac", true))
        .unwrap();
    let r = j.restore_where(&p, |res| matches!(res, Resource::UserEnv { .. }));
    assert_eq!(r.restored(), 1);
    assert!(j.entry(&pac).is_some());
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
}

#[test]
fn owns_recognises_the_confirmed_and_the_in_flight_value_only() {
    let (fs, p) = setup();
    let mut j = open(&fs).unwrap();
    assert!(!j.owns(&env("A"), &ev("x")));
    j.apply(&p, &env("A"), ev("x")).unwrap();
    assert!(j.owns(&env("A"), &ev("x")));
    assert!(!j.owns(&env("A"), &ev("other")));
}
