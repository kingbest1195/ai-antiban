use super::*;
use crate::sysproxy::fs::{FakeFs, FsOp};
use crate::sysproxy::platform::{FakePlatform, ProxyEndpoint};

// --- file resources ----------------------------------------------------------------------

fn jkey(file: &str, path: &[&str]) -> Resource {
    Resource::JsonKey {
        file: file.into(),
        path: path.iter().map(|s| s.to_string()).collect(),
    }
}
fn jv(s: &str) -> Value {
    Value::Json(Some(s.into()))
}

#[test]
fn a_json_key_is_restored_to_its_baseline_and_a_missing_one_is_removed() {
    let (fs, p) = setup();
    let f = "/h/s.json";
    let original = "{\n  // c\n  \"a\": 1,\n  \"k\": \"mine\"\n}\n";
    fs.put(Path::new(f), original.as_bytes(), 0o644);
    let mut j = open(&fs).unwrap();
    j.apply(&p, &jkey(f, &["k"]), jv("\"ours\"")).unwrap();
    j.apply(&p, &jkey(f, &["z"]), jv("1")).unwrap();
    assert!(
        String::from_utf8(fs.get(Path::new(f)).unwrap())
            .unwrap()
            .contains("\"z\": 1")
    );
    let r = j.restore_all(&p);
    assert_eq!(r.restored(), 2);
    assert_eq!(fs.get(Path::new(f)).unwrap(), original.as_bytes());
    assert!(j.is_empty());
}

#[test]
fn a_json_key_written_by_the_user_after_us_is_not_rolled_back() {
    let (fs, p) = setup();
    let f = "/h/s.json";
    fs.put(Path::new(f), b"{\n  \"a\": 1\n}\n", 0o644);
    let mut j = open(&fs).unwrap();
    j.apply(&p, &jkey(f, &["k"]), jv("\"ours\"")).unwrap();
    fs.put(
        Path::new(f),
        b"{\n  \"a\": 1,\n  \"k\": \"theirs\"\n}\n",
        0o644,
    );
    let r = j.restore_all(&p);
    assert_eq!(r.external(), 1);
    assert!(
        String::from_utf8(fs.get(Path::new(f)).unwrap())
            .unwrap()
            .contains("theirs")
    );
}

#[test]
fn a_file_that_cannot_be_read_as_json_fails_closed_for_apply_and_restore() {
    let (fs, p) = setup();
    let f = "/h/s.json";
    let bad = b"{\"a\": 1,,}";
    fs.put(Path::new(f), bad, 0o644);
    let mut j = open(&fs).unwrap();
    let e = j.apply(&p, &jkey(f, &["k"]), jv("1")).unwrap_err();
    assert!(matches!(e, JournalError::Platform(_)));
    assert!(
        j.is_empty(),
        "nothing is recorded for a file that is refused"
    );
    assert_eq!(fs.get(Path::new(f)).unwrap(), bad);
    // A record that outlives a later corruption is kept for a retry, never "restored" by guessing.
    fs.put(Path::new(f), b"{\"a\": 1}", 0o644);
    j.apply(&p, &jkey(f, &["k"]), jv("1")).unwrap();
    fs.put(Path::new(f), bad, 0o644);
    let r = j.restore_all(&p);
    assert_eq!(r.failed(), 1);
    assert_eq!(j.entries().len(), 1);
    assert_eq!(fs.get(Path::new(f)).unwrap(), bad);
}

#[test]
fn writing_a_key_into_a_missing_file_fails_and_leaves_no_record() {
    let (fs, p) = setup();
    let mut j = open(&fs).unwrap();
    assert!(j.apply(&p, &jkey("/h/none.json", &["k"]), jv("1")).is_err());
    assert!(j.is_empty());
    assert!(fs.get(Path::new("/h/none.json")).is_none());
}

#[test]
fn objects_and_files_go_after_the_keys_that_live_in_them_and_only_while_bare() {
    let (fs, p) = setup();
    let f = "/h/dir/s.json";
    let file = Resource::File {
        file: f.into(),
        skeleton: "{}\n".into(),
    };
    let obj = Resource::JsonObject {
        file: f.into(),
        path: vec!["env".into()],
    };
    let mut j = open(&fs).unwrap();
    j.apply(&p, &file, Value::Present(true)).unwrap();
    j.apply(&p, &obj, Value::Present(true)).unwrap();
    j.apply(&p, &jkey(f, &["env", "K"]), jv("\"v\"")).unwrap();
    let r = j.restore_all(&p);
    assert_eq!(r.restored(), 3, "{}", r.summary());
    assert!(
        fs.get(Path::new(f)).is_none(),
        "key, then object, then the file itself"
    );
    // A file the user filled meanwhile is theirs: it stays.
    drop(j);
    let mut j = open(&fs).unwrap();
    j.apply(&p, &file, Value::Present(true)).unwrap();
    fs.put(Path::new(f), b"{\"mine\": 1}\n", 0o644);
    j.restore_all(&p);
    assert_eq!(fs.get(Path::new(f)).unwrap(), b"{\"mine\": 1}\n");
}

#[test]
fn file_resources_survive_serialization_and_kind_mismatch_is_rejected() {
    let (fs, p) = setup();
    let f = "/h/s.json";
    fs.put(Path::new(f), b"{}\n", 0o644);
    {
        let mut j = open(&fs).unwrap();
        j.apply(&p, &jkey(f, &["a", "b"]).clone(), jv("1"))
            .unwrap_err(); // parent missing
        j.apply(&p, &jkey(f, &["k"]), jv("2")).unwrap();
        assert!(matches!(
            j.apply(&p, &jkey(f, &["k"]), Value::Present(true)),
            Err(JournalError::KindMismatch)
        ));
    }
    let j = open(&fs).unwrap();
    assert_eq!(j.entries().len(), 1);
    assert_eq!(j.entry(&jkey(f, &["k"])).unwrap().expected, Some(jv("2")));
    assert!(
        j.entry(&jkey(f, &["k"]))
            .unwrap()
            .resource
            .is_file_resource()
    );
}

#[test]
fn file_resource_ids_carry_no_home_directory_and_no_values() {
    let id = jkey(
        "/Users/someone/Library/Application Support/Code/User/settings.json",
        &["http.proxy"],
    )
    .id();
    assert_eq!(id, "json:Code/User/settings.json:http.proxy");
    let b = Resource::TextBlock {
        file: "C:\\Users\\someone\\Documents\\PowerShell\\profile.ps1".into(),
    };
    assert_eq!(b.id(), "block:Documents/PowerShell/profile.ps1");
}

// --- WP-26: set_chain killed between its two commands ------------------------------------

fn upstream(host: &str, port: u16, on: bool) -> ProxyEndpoint {
    ProxyEndpoint {
        enabled: Some(on),
        server: Some(host.into()),
        port: Some(port),
        ..Default::default()
    }
}

/// Both sides point at their own upstream; `http_on` / `https_on` are the state flags.
fn two_sided(http_on: bool, https_on: bool) -> ChainState {
    ChainState {
        http: upstream("h1", 1080, http_on),
        https: upstream("h2", 2080, https_on),
    }
}

fn chain_res() -> Resource {
    Resource::Chain { service: wifi() }
}

/// The process dies between `-setwebproxystate` and `-setsecurewebproxystate`: the journal
/// holds the intent, the service holds {http off, https on}.
fn kill_between_chain_commands(fs: &FakeFs, p: &FakePlatform) {
    p.add_service(wifi());
    p.seed_chain(&wifi(), two_sided(true, true));
    let mut j = open(fs).unwrap();
    p.tear_next_set_chain();
    assert!(
        j.apply(p, &chain_res(), Value::Chain(two_sided(false, false)))
            .is_err()
    );
    assert_eq!(
        p.chain_of(&wifi()),
        two_sided(false, true),
        "setup: exactly the half-written state"
    );
}

#[test]
fn kill_between_the_chain_commands_is_ours_and_the_user_proxy_comes_back() {
    let (fs, p) = setup();
    kill_between_chain_commands(&fs, &p);
    let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(
        r.external(),
        0,
        "a half-written chain is not an external change"
    );
    assert_eq!(r.restored(), 1);
    assert_eq!(p.chain_of(&wifi()), two_sided(true, true));
}

#[test]
fn kill_between_the_chain_commands_does_not_rebase_the_baseline() {
    let (fs, p) = setup();
    kill_between_chain_commands(&fs, &p);
    let mut j = open(&fs).unwrap();
    let outcome = j
        .apply(&p, &chain_res(), Value::Chain(two_sided(false, false)))
        .unwrap();
    assert_eq!(outcome, ApplyOutcome::Applied, "not Rebased");
    assert_eq!(
        j.entry(&chain_res()).unwrap().baseline,
        Value::Chain(two_sided(true, true)),
        "the baseline stays what the user had, not the half state"
    );
    j.restore_all(&p);
    assert_eq!(p.chain_of(&wifi()), two_sided(true, true));
}

#[test]
fn a_mixed_chain_after_a_completed_write_is_an_external_change() {
    let (fs, p) = setup();
    p.add_service(wifi());
    p.seed_chain(&wifi(), two_sided(true, true));
    let mut j = open(&fs).unwrap();
    j.apply(&p, &chain_res(), Value::Chain(two_sided(false, false)))
        .unwrap();
    // The user switches only the HTTP proxy back on: that is theirs, not a half write.
    p.seed_chain(&wifi(), two_sided(true, false));
    let r = j.restore_all(&p);
    assert_eq!(r.external(), 1);
    assert_eq!(p.chain_of(&wifi()), two_sided(true, false));
}

#[test]
fn a_mix_with_a_value_nobody_wrote_is_external_even_while_a_write_is_in_flight() {
    let (fs, p) = setup();
    kill_between_chain_commands(&fs, &p);
    // Somebody points the HTTP side somewhere else while the intent is still open.
    p.seed_chain(
        &wifi(),
        ChainState {
            http: upstream("elsewhere", 9, true),
            https: upstream("h2", 2080, true),
        },
    );
    let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(r.external(), 1);
    assert_eq!(
        p.chain_of(&wifi()).http.server.as_deref(),
        Some("elsewhere")
    );
}

// --- WP-26: read-back and the OS rewriting a URL -----------------------------------------

fn pac_res() -> Resource {
    Resource::Pac { service: wifi() }
}

/// An OS that stores the host of a PAC URL in upper case.
fn shouting_os(p: &FakePlatform) {
    p.add_service(wifi());
    p.normalize_pac_urls_with(|u| u.replace("localhost", "LOCALHOST"));
}

const OURS: &str = "http://localhost:8899/proxy.pac";
const OURS_STORED: &str = "http://LOCALHOST:8899/proxy.pac";

#[test]
fn what_the_os_reads_back_is_stored_as_expected() {
    let (fs, p) = setup();
    shouting_os(&p);
    let mut j = open(&fs).unwrap();
    j.apply(&p, &pac_res(), pac_value(OURS, true)).unwrap();
    assert_eq!(
        j.entry(&pac_res()).unwrap().expected,
        Some(pac_value(OURS_STORED, true)),
        "expected is the normalised value, not the one we asked for"
    );
}

#[test]
fn a_normalised_value_is_unchanged_on_the_next_apply() {
    let (fs, p) = setup();
    shouting_os(&p);
    let mut j = open(&fs).unwrap();
    j.apply(&p, &pac_res(), pac_value(OURS, true)).unwrap();
    let writes = p.os_writes();
    assert_eq!(
        j.apply(&p, &pac_res(), pac_value(OURS, true)).unwrap(),
        ApplyOutcome::Unchanged
    );
    assert_eq!(p.os_writes(), writes, "no rewrite on every refresh");
    assert_eq!(j.entry(&pac_res()).unwrap().baseline, pac_value_absent());
}

fn pac_value_absent() -> Value {
    Value::Pac(PacState::default())
}

#[test]
fn restore_after_the_os_normalised_the_url_puts_the_baseline_back() {
    let (fs, p) = setup();
    shouting_os(&p);
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://corp/p.pac".into()),
            enabled: Some(false),
        },
    );
    let mut j = open(&fs).unwrap();
    j.apply(&p, &pac_res(), pac_value(OURS, true)).unwrap();
    let r = j.restore_all(&p);
    assert_eq!((r.restored(), r.external()), (1, 0));
    assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some("http://corp/p.pac"));
    assert_eq!(p.pac_of(&wifi()).enabled, Some(false));
}

#[test]
fn crash_before_the_applied_mark_with_a_normalising_os_still_restores() {
    let (fs, p) = setup();
    shouting_os(&p);
    {
        let mut j = open(&fs).unwrap();
        fs.fail_after(FsOp::WriteAtomic, 1); // intent lands, the "applied" write does not
        assert!(j.apply(&p, &pac_res(), pac_value(OURS, true)).is_err());
    }
    assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some(OURS_STORED));
    let r = recover_with(Arc::new(fs.clone()), &p, Path::new(DIR)).unwrap();
    assert_eq!(
        (r.restored(), r.external()),
        (1, 0),
        "pending ~ stored value"
    );
    assert_eq!(p.pac_of(&wifi()).url, None);
}

#[test]
fn a_zastava_signed_pac_is_never_taken_for_a_foreign_baseline() {
    let (fs, p) = setup();
    p.add_service(wifi());
    let mut j = open(&fs).unwrap();
    j.apply(
        &p,
        &pac_res(),
        pac_value("http://127.0.0.1:8899/proxy.pac", true),
    )
    .unwrap();
    // The OS (or an older Zastava) leaves our own address, in a spelling we did not write.
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://localhost:8900/proxy.pac".into()),
            enabled: Some(true),
        },
    );
    let outcome = j
        .apply(
            &p,
            &pac_res(),
            pac_value("http://127.0.0.1:8899/proxy.pac", true),
        )
        .unwrap();
    assert_eq!(outcome, ApplyOutcome::Applied, "no rebase onto our own PAC");
    assert_eq!(j.entry(&pac_res()).unwrap().baseline, pac_value_absent());
    j.restore_all(&p);
    assert_eq!(
        p.pac_of(&wifi()).url,
        None,
        "restore removes our PAC, not re-adds it"
    );
}

#[test]
fn a_foreign_pac_still_becomes_the_baseline() {
    let (fs, p) = setup();
    p.add_service(wifi());
    let mut j = open(&fs).unwrap();
    j.apply(
        &p,
        &pac_res(),
        pac_value("http://127.0.0.1:8899/proxy.pac", true),
    )
    .unwrap();
    p.seed_pac(
        &wifi(),
        PacState {
            url: Some("http://corp:8899/proxy.pac".into()),
            enabled: Some(true),
        },
    );
    let outcome = j
        .apply(
            &p,
            &pac_res(),
            pac_value("http://127.0.0.1:8899/proxy.pac", true),
        )
        .unwrap();
    assert_eq!(outcome, ApplyOutcome::Rebased);
}

#[test]
fn urls_are_compared_up_to_case_default_port_and_empty_path() {
    assert!(urls_equivalent("http://Host:80/x.pac", "HTTP://host/x.pac"));
    assert!(urls_equivalent("https://h:443", "https://h/"));
    assert!(!urls_equivalent("http://h:8080/x.pac", "http://h/x.pac"));
    assert!(
        !urls_equivalent("http://h/X.pac", "http://h/x.pac"),
        "the path is case-sensitive"
    );
    assert!(!urls_equivalent("not a url", "http://h/"));
    assert!(urls_equivalent("same", "same"));
}

// --- WP-26: no values in Debug, no account name in labels --------------------------------

#[test]
fn debug_of_a_value_never_shows_it() {
    let secret = "hunter2";
    let values = [
        Value::Env(Some(secret.into())),
        Value::Json(Some(format!("\"{secret}\""))),
        Value::Block(Some(format!("export P={secret}"))),
        Value::Bypass(vec![format!("{secret}.corp")]),
        Value::Pac(PacState {
            url: Some(format!("http://{secret}/p.pac")),
            enabled: Some(true),
        }),
        Value::Chain(ChainState {
            http: upstream(secret, 1, true),
            https: upstream(secret, 2, true),
        }),
        Value::Reg(Some(RegValue::sz(secret))),
    ];
    for v in values {
        let text = format!("{v:?}");
        assert!(!text.contains(secret), "{text}");
    }
    assert_eq!(format!("{:?}", Value::Env(None)), "Env(None)");
    assert_eq!(format!("{:?}", Value::Present(true)), "Present(true)");
}

#[test]
fn file_labels_cut_the_account_name_off() {
    for (path, want) in [
        ("/Users/ivan/.zshrc", ".zshrc"),
        ("/home/ivan/.claude/settings.json", ".claude/settings.json"),
        ("C:\\Users\\Иван\\.zshrc", ".zshrc"),
        (
            "C:\\Users\\Иван\\AppData\\Roaming\\Code\\User\\settings.json",
            "Code/User/settings.json",
        ),
        ("/Users/ivan", ""),
        ("/opt/x/y/z/.profile", "y/z/.profile"),
    ] {
        let label = file_label(path);
        assert_eq!(label, want, "{path}");
        assert!(
            !label.contains("ivan") && !label.contains("Иван"),
            "{label}"
        );
    }
}

// --- WP-26: where the journal lives ------------------------------------------------------

fn legacy_journal(fs: &FakeFs, p: &FakePlatform, dir: &str) {
    let mut j = Journal::open(Arc::new(fs.clone()), Path::new(dir)).unwrap();
    j.apply(p, &env("A"), ev("ours")).unwrap();
}

#[test]
fn a_journal_in_the_old_place_is_carried_to_the_new_one() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    legacy_journal(&fs, &p, "/roaming");
    let old = Path::new("/roaming").join(SUBDIR).join(JOURNAL_FILE);
    let new = Path::new("/local").join(SUBDIR).join(JOURNAL_FILE);
    assert!(fs.get(&old).is_some());
    let j = Journal::open_migrating(
        Arc::new(fs.clone()),
        Path::new("/local"),
        Some(Path::new("/roaming")),
    )
    .unwrap();
    assert_eq!(j.entries().len(), 1, "the record came along");
    assert!(fs.get(&new).is_some(), "written to the new place");
    assert!(fs.get(&old).is_none(), "and gone from the old one");
    assert_eq!(fs.mode(&new).unwrap(), Some(0o600));
}

#[test]
fn a_journal_in_the_new_place_wins_over_an_old_one() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    legacy_journal(&fs, &p, "/roaming");
    let j = Journal::open_migrating(
        Arc::new(fs.clone()),
        Path::new("/local"),
        Some(Path::new("/roaming")),
    )
    .unwrap();
    drop(j);
    // The new journal is now empty-handed on purpose: restore it, then bring a stale old one.
    let mut j = Journal::open(Arc::new(fs.clone()), Path::new("/local")).unwrap();
    j.restore_all(&p);
    drop(j);
    legacy_journal(&fs, &p, "/roaming");
    let j = Journal::open_migrating(
        Arc::new(fs.clone()),
        Path::new("/local"),
        Some(Path::new("/roaming")),
    )
    .unwrap();
    assert!(j.is_empty(), "the old journal is not read again");
    assert!(
        fs.get(&Path::new("/roaming").join(SUBDIR).join(JOURNAL_FILE))
            .is_some(),
        "and not deleted either"
    );
}

#[test]
fn a_failed_copy_to_the_new_place_leaves_the_old_journal_alone() {
    let (fs, p) = setup();
    p.seed_env("A", "orig");
    legacy_journal(&fs, &p, "/roaming");
    fs.fail_next(FsOp::WriteAtomic);
    let r = Journal::open_migrating(
        Arc::new(fs.clone()),
        Path::new("/local"),
        Some(Path::new("/roaming")),
    );
    assert!(matches!(r, Err(JournalError::Io("write", _))));
    assert!(
        fs.get(&Path::new("/roaming").join(SUBDIR).join(JOURNAL_FILE))
            .is_some()
    );
}

#[test]
fn temp_files_of_a_killed_write_are_swept_when_the_journal_opens() {
    let (fs, _p) = setup();
    let dir = Path::new(DIR).join(SUBDIR);
    let stale = dir.join(".journal.json.zastava-tmp.4242.7");
    let keep = dir.join("journal.json");
    fs.put(&stale, b"half", 0o600);
    fs.put(&keep, br#"{"schema_version":1,"entries":[]}"#, 0o600);
    let _j = open(&fs).unwrap();
    assert!(fs.get(&stale).is_none(), "the stale temp file is gone");
    assert!(fs.get(&keep).is_some(), "the journal itself stays");
}

#[test]
fn is_only_vpn_dns_deferred_detects_pure_temp_dns_deferral() {
    let deferred = RecoveryReport {
        items: vec![
            ReportItem {
                resource: "pac(Wi-Fi)".into(),
                outcome: Outcome::Failed("temp_dns"),
            },
            ReportItem {
                resource: "env(HTTP_PROXY)".into(),
                outcome: Outcome::Restored,
            },
        ],
        skipped_dry_run: false,
        journal_write_failed: false,
    };
    assert!(deferred.restore_deferred_by_vpn_dns());
    assert!(deferred.is_only_vpn_dns_deferred());

    let mixed = RecoveryReport {
        items: vec![
            ReportItem {
                resource: "pac(Wi-Fi)".into(),
                outcome: Outcome::Failed("temp_dns"),
            },
            ReportItem {
                resource: "env(HTTP_PROXY)".into(),
                outcome: Outcome::Failed("env_write"),
            },
        ],
        skipped_dry_run: false,
        journal_write_failed: false,
    };
    assert!(!mixed.is_only_vpn_dns_deferred());

    let journal_err = RecoveryReport {
        journal_write_failed: true,
        ..deferred
    };
    assert!(!journal_err.is_only_vpn_dns_deferred());
}
