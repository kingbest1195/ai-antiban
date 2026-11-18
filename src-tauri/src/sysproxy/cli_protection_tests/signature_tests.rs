use super::*;
use crate::sysproxy::ZASTAVA_RC_START;
use crate::sysproxy::shell_rc::build_shell_rc_guard_block_with_tz;

#[test]
fn an_lc_all_key_an_earlier_build_recorded_is_given_back_when_the_zone_is_applied() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let claude = e.ctx.claude_settings();
    let mut j = e.journal();
    let keys = [
        crate::sysproxy::ide::KeySpec::new(&["env", "LC_ALL"], "en_US.UTF-8"),
        crate::sysproxy::ide::KeySpec::new(&["env", "TZ"], "Europe/Paris"),
    ];
    crate::sysproxy::ide::apply_settings_keys(&mut j, &e.p, &*e.ctx.fs, &claude, &keys, &[])
        .unwrap();
    drop(j);
    e.apply(None, Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    let text = e.text(&claude);
    assert_eq!(raw(&text, &["env", "LC_ALL"]), None);
    assert_eq!(raw(&text, &["env", "TZ"]), Some(json_str(ZONE)));
}

// Migration by signature: strict parse, values checked.

fn legacy_run(e: &Env, file: &Path, gw: Option<u16>) -> bool {
    let j = e.journal();
    clean_legacy_json(&j, &*e.ctx.fs, file, false, &["env"], gw)
}

#[test]
fn a_russian_locale_next_to_a_signed_proxy_stays_and_the_zone_goes_only_with_the_signature() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let f = e.ctx.claude_settings();
    let text = format!(
        "{{\n  \"env\": {{\n    \"HTTPS_PROXY\": \"{URL}\",\n    \"TZ\": \"Europe/Berlin\",\n    \"LANG\": \"ru_RU.UTF-8\",\n    \"LC_TIME\": \"en_US.UTF-8\",\n    \"LC_ALL\": \"ru_RU.UTF-8\"\n  }}\n}}\n"
    );
    e.fs.put(&f, text.as_bytes(), 0o644);
    assert!(legacy_run(&e, &f, None));
    let after = e.text(&f);
    assert_eq!(raw(&after, &["env", "HTTPS_PROXY"]), None);
    assert_eq!(raw(&after, &["env", "TZ"]), None, "co-signed zone");
    assert_eq!(
        raw(&after, &["env", "LC_TIME"]),
        None,
        "the value Zastava wrote"
    );
    assert_eq!(raw(&after, &["env", "LANG"]), Some(json_str("ru_RU.UTF-8")));
    assert_eq!(
        raw(&after, &["env", "LC_ALL"]),
        Some(json_str("ru_RU.UTF-8"))
    );

    // No signed proxy variable: nothing is ours, not even a well-formed zone.
    let own = "{\n  \"env\": {\n    \"HTTPS_PROXY\": \"http://corp:3128\",\n    \"TZ\": \"Europe/Berlin\",\n    \"LC_ALL\": \"en_US.UTF-8\"\n  }\n}\n";
    e.fs.put(&f, own.as_bytes(), 0o644);
    assert!(legacy_run(&e, &f, None));
    assert_eq!(e.text(&f), own);
}

#[test]
fn the_signature_is_the_strict_one_userinfo_lookalike_hosts_and_the_gateway_port() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let f = e.ctx.claude_settings();
    for (value, gw, removed) in [
        ("http://user:pw@127.0.0.1:8899", None, false),
        ("http://my-localhost:8900", None, false),
        ("http://127.0.0.1:88990", None, false),
        ("http://127.0.0.1:9123", None, false),
        ("http://127.0.0.1:9123", Some(9123), true),
        ("http://localhost:8900", None, true),
        ("127.0.0.1:8899", None, true),
    ] {
        let text = format!(
            "{{\n  \"env\": {{\n    \"HTTPS_PROXY\": \"{value}\",\n    \"TZ\": \"Asia/Tokyo\"\n  }}\n}}\n"
        );
        e.fs.put(&f, text.as_bytes(), 0o644);
        assert!(legacy_run(&e, &f, gw));
        let after = e.text(&f);
        assert_eq!(
            raw(&after, &["env", "HTTPS_PROXY"]).is_none(),
            removed,
            "{value}"
        );
        assert_eq!(raw(&after, &["env", "TZ"]).is_none(), removed, "{value}");
    }
}

#[test]
fn the_status_uses_the_same_strict_signature_and_ignores_the_time_zone_keys() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let f = e.ctx.claude_settings();
    let put = |v: &str| {
        e.fs.put(
            &f,
            format!("{{\"env\": {{\"HTTPS_PROXY\": \"{v}\"}}}}").as_bytes(),
            0o644,
        )
    };
    put(URL);
    assert!(files_show_protection(&e.ctx));
    put("http://u@127.0.0.1:8899");
    assert!(
        !files_show_protection(&e.ctx),
        "userinfo is not our address"
    );
    put("http://my-localhost:8900");
    assert!(!files_show_protection(&e.ctx));
    // Time zone keys alone are not "protection".
    e.fs.put(&f, b"{\"env\": {\"TZ\": \"Europe/Berlin\", \"LANG\": \"en_US.UTF-8\", \"LC_TIME\": \"en_US.UTF-8\"}}", 0o644);
    assert!(!files_show_protection(&e.ctx));
    assert!(files_show_tz_sync(&e.ctx));
}

#[test]
fn the_status_of_a_terminal_block_is_the_proxy_part_only() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    e.apply(None, Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    assert!(
        !files_show_protection(&e.ctx),
        "a zone-only block is not protection"
    );
    assert!(files_show_tz_sync(&e.ctx));
    e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    assert!(files_show_protection(&e.ctx));
    e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
    assert!(files_show_protection(&e.ctx));
    assert!(
        !files_show_tz_sync(&e.ctx),
        "proxy without a zone says nothing about the locale"
    );
}

// Run::Failed (journal busy / damaged): nothing is on.

#[test]
fn a_refused_journal_means_not_enabled_and_no_active_flag() {
    use crate::sysproxy::journal::JournalError;
    for err in [
        JournalError::Locked,
        JournalError::Corrupt,
        JournalError::UnknownSchema(99),
    ] {
        let st = SysState::new();
        let report = finish_enable(
            &st,
            Run::Failed(err),
            (URL.to_string(), 8899),
            Some(ZONE.to_string()),
            CliMode::AiOnly,
        );
        assert!(!report.enabled);
        assert!(report.configured_targets.is_empty() && report.shell_command.is_empty());
        assert!(
            report
                .error
                .as_deref()
                .is_some_and(|t| t.starts_with("Защита не включена"))
        );
        assert!(!st.cli_protection_active());
        assert_eq!(st.cli_proxy(), None);
        assert_eq!(st.cli_tz(), None);
    }
    let st = SysState::new();
    let ok = finish_enable(
        &st,
        Run::Done(FilesApplied::default()),
        (URL.to_string(), 8899),
        None,
        CliMode::GlobalTerminal,
    );
    assert!(ok.enabled && ok.error.is_none());
    assert!(st.cli_protection_active());
    assert_eq!(st.cli_proxy(), Some((URL.to_string(), 8899)));
    assert_eq!(st.cli_mode(), CliMode::GlobalTerminal);
}

#[test]
fn a_refused_journal_on_apply_changes_nothing_and_a_refused_disable_is_a_failure() {
    use crate::sysproxy::journal::JournalError;
    let st = SysState::new();
    st.set_cli_tz(Some("Asia/Tokyo".into()));
    let r = finish_apply(
        &st,
        Run::Failed(JournalError::Locked),
        Some(ZONE.into()),
        CliMode::GlobalTerminal,
    );
    assert!(!r.ok && r.error.is_some());
    assert_eq!(st.cli_tz().as_deref(), Some("Asia/Tokyo"));
    assert_eq!(st.cli_mode(), CliMode::AiOnly);

    st.set_cli_protection_active(true);
    let mut report = RecoveryReport::default();
    finish_disable(&st, Run::Failed(JournalError::Corrupt), &mut report);
    assert!(report.has_failures());
    assert!(st.cli_protection_active(), "nothing was put back: still on");
    let mut report = RecoveryReport::default();
    finish_disable(&st, Run::Done(FilesApplied::default()), &mut report);
    assert!(!report.has_failures());
    assert!(!st.cli_protection_active());
}

#[test]
fn the_runtime_state_forgets_proxy_and_zone_on_reset_but_keeps_the_mode() {
    let st = SysState::new();
    st.set_cli_proxy(Some((URL.into(), 8899)));
    st.set_cli_tz(Some(ZONE.into()));
    st.set_cli_mode(CliMode::GlobalTerminal);
    st.reset();
    assert_eq!((st.cli_proxy(), st.cli_tz()), (None, None));
    assert_eq!(st.cli_mode(), CliMode::GlobalTerminal);
}

#[test]
fn notes_and_errors_carry_no_values_or_home_paths() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshenv = e.ctx.home.join(".zshenv");
    e.fs.put(
        &zshenv,
        format!("{ZASTAVA_RC_START}\nexport HTTP_PROXY=\"http://u:secret@127.0.0.1:8899\"\n")
            .as_bytes(),
        0o644,
    );
    let a = e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    for n in &a.notes {
        assert!(
            !n.contains("secret") && !n.contains("/home/u") && !n.contains("8899"),
            "{n}"
        );
    }
}

#[test]
fn a_zshenv_block_an_early_2_1_build_recorded_is_given_back_through_the_journal() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshenv = e.ctx.home.join(".zshenv");
    e.fs.put(&zshenv, b"export A=1\n", 0o600);
    let mut j = e.journal();
    let block = build_shell_rc_guard_block_with_tz(URL, 8899, None);
    apply_profile_block(&mut j, &e.p, &*e.ctx.fs, &zshenv, &block).unwrap();
    assert!(e.text(&zshenv).contains(ZASTAVA_RC_START));
    let (strip, _) = clean_zshenv(&mut j, &e.p, &e.ctx);
    assert_eq!(strip, Strip::Absent);
    drop(j);
    assert_eq!(e.text(&zshenv), "export A=1\n");
    assert!(e.journal_is_empty());
}

#[test]
fn enable_without_a_proxy_in_ai_only_is_only_a_zone_apply_and_names_no_terminal() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let a = e.apply(None, Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    assert_eq!(a.targets, vec!["Claude Code".to_string()]);
    let none = e.apply(None, None, CliMode::AiOnly, HostOs::Unix);
    assert!(none.targets.is_empty());
    assert!(e.journal_is_empty());
}

#[test]
fn restore_preserves_trailing_newline_and_handles_empty_and_no_newline_files() {
    let e = env();
    let zshrc = e.ctx.home.join(".zshrc");
    let bash_profile = e.ctx.home.join(".bash_profile");

    // 1. Journaled apply + disable preserves exact trailing '\n' on .zshrc and .bash_profile.
    e.fs.put(&zshrc, b"export A=1\n", 0o644);
    e.fs.put(&bash_profile, b"export B=2\n", 0o644);
    e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
    assert!(e.text(&zshrc).contains(ZASTAVA_RC_START));
    e.disable();
    assert_eq!(e.text(&zshrc), "export A=1\n");
    assert_eq!(e.text(&bash_profile), "export B=2\n");

    // 2. Switching GlobalTerminal -> AiOnly also restores .zshrc with trailing '\n' intact.
    e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
    e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&zshrc), "export A=1\n");

    // 3. No trailing '\n' originally -> exact original without trailing '\n' restored.
    e.fs.put(&zshrc, b"export NO_EOL=1", 0o644);
    e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
    e.disable();
    assert_eq!(e.text(&zshrc), "export NO_EOL=1");

    // 4. Legacy unjournaled blocks in .bash_profile / .zshenv / .zshrc / .bashrc on a fresh environment:
    //    - trailing '\n' before block is preserved when block is stripped
    //    - file that contained only the block becomes completely empty ""
    let e2 = env();
    let bash_profile2 = e2.ctx.home.join(".bash_profile");
    let zshenv2 = e2.ctx.home.join(".zshenv");
    let zshrc2 = e2.ctx.home.join(".zshrc");
    let bashrc2 = e2.ctx.home.join(".bashrc");
    let legacy_block = shell_block();
    e2.fs.put(
        &bash_profile2,
        format!("export C=3\n\n{legacy_block}\n").as_bytes(),
        0o644,
    );
    e2.fs
        .put(&zshenv2, format!("{legacy_block}\n").as_bytes(), 0o644);
    e2.fs
        .put(&zshrc2, format!("{legacy_block}\n").as_bytes(), 0o644);
    e2.fs.put(
        &bashrc2,
        format!("export D=4\n\n{legacy_block}\n").as_bytes(),
        0o644,
    );
    e2.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e2.text(&bash_profile2), "export C=3\n");
    assert_eq!(e2.text(&zshenv2), "");
    assert_eq!(e2.text(&zshrc2), "");
    assert_eq!(
        strip_marked_block(&e2.journal(), &*e2.ctx.fs, &bashrc2),
        Strip::Removed
    );
    assert_eq!(e2.text(&bashrc2), "export D=4\n");
}
