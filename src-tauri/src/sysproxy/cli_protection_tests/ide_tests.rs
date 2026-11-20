use super::*;
use crate::sysproxy::fs::FsOp;
use crate::sysproxy::ide::ide_env_key;

// --- IDE settings.json -----------------------------------------------------------------

#[test]
fn ide_apply_then_restore_is_byte_exact_with_bom_crlf_comments_and_mode() {
    let e = env();
    let ide = e.ide_with(COMMENTED, 0o640);
    let targets = e.enable(None);
    assert!(targets.contains(&"VS Code".to_string()), "{targets:?}");
    let after = e.text(&ide);
    assert!(after.starts_with('\u{feff}'));
    assert!(after.contains("// my theme") && after.contains("/* px */"));
    assert!(
        !after.replace("\r\n", "").contains('\n'),
        "only CRLF line ends"
    );
    jsonc::validate(&after).unwrap();
    assert_eq!(raw(&after, &["http.proxy"]), Some(format!("\"{URL}\"")));
    assert_eq!(
        raw(&after, &[ide_env_key(), "HTTPS_PROXY"]),
        Some(format!("\"{URL}\""))
    );
    assert_eq!(e.fs.mode(&ide).unwrap(), Some(0o640));

    let report = e.disable();
    assert!(!report.has_failures(), "{}", report.summary());
    assert_eq!(e.text(&ide), COMMENTED, "restored byte for byte");
    assert_eq!(e.fs.mode(&ide).unwrap(), Some(0o640));
    assert!(e.journal_is_empty());
}

#[test]
fn files_zastava_created_are_removed_again_while_they_are_bare() {
    let e = env();
    e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
    let claude = e.ctx.claude_settings();
    e.enable(None);
    assert!(e.fs.get(Path::new(IDE_FILE)).is_some());
    assert!(e.fs.get(&claude).is_some());
    e.disable();
    assert!(
        e.fs.get(Path::new(IDE_FILE)).is_none(),
        "settings.json is gone again"
    );
    assert!(e.fs.get(&claude).is_none());
    if cfg!(unix) {
        assert!(e.fs.get(&e.ctx.home.join(".zshrc")).is_none());
        assert!(e.fs.get(&e.ctx.home.join(".zshenv")).is_none());
    }
    assert!(e.journal_is_empty());
}

#[test]
fn a_trailing_comma_with_a_comment_round_trips_exactly() {
    let original = "{\n  \"editor.fontSize\": 14, // keep\n}\n";
    let e = env();
    let ide = e.ide_with(original, 0o644);
    e.enable(None);
    let after = e.text(&ide);
    assert!(
        after.contains("\"editor.fontSize\": 14, // keep"),
        "{after}"
    );
    jsonc::validate(&after).unwrap();
    e.disable();
    assert_eq!(e.text(&ide), original, "restored byte for byte");
}

#[test]
fn an_empty_object_file_round_trips_exactly() {
    let e = env();
    let ide = e.ide_with("{}\n", 0o644);
    e.enable(None);
    assert!(e.text(&ide).contains("http.proxy"));
    e.disable();
    assert_eq!(e.text(&ide), "{}\n");
}

#[test]
fn a_value_the_user_changed_after_us_is_kept_and_the_rest_is_restored() {
    let e = env();
    let ide = e.ide_with(COMMENTED, 0o644);
    e.enable(None);
    let edited = e.text(&ide).replace(
        &format!("\"http.proxy\": \"{URL}\""),
        "\"http.proxy\": \"http://mine:1\"",
    );
    e.user_writes(&ide, &edited);
    let report = e.disable();
    assert_eq!(report.external(), 1, "{}", report.summary());
    let after = e.text(&ide);
    assert_eq!(
        raw(&after, &["http.proxy"]),
        Some("\"http://mine:1\"".into())
    );
    assert_eq!(
        raw(&after, &["http.proxySupport"]),
        None,
        "our other keys are gone"
    );
    assert_eq!(
        raw(&after, &[ide_env_key()]),
        None,
        "the object we made is gone"
    );
    assert!(after.contains("// my theme") && after.contains("/* px */"));
    jsonc::validate(&after).unwrap();
}

#[test]
fn a_neighbour_key_added_after_us_is_kept() {
    let e = env();
    let ide = e.ide_with(COMMENTED, 0o644);
    e.enable(None);
    let with_neighbour = jsonc::set(&e.text(&ide), &["editor.tabSize"], "2").unwrap();
    e.user_writes(&ide, &with_neighbour);
    e.disable();
    let after = e.text(&ide);
    assert_eq!(raw(&after, &["editor.tabSize"]), Some("2".into()));
    assert_eq!(raw(&after, &["http.proxy"]), None);
    assert_eq!(raw(&after, &["editor.fontSize"]), Some("14".into()));
    assert!(after.starts_with('\u{feff}') && after.contains("// my theme"));
    jsonc::validate(&after).unwrap();
}

#[test]
fn a_variable_the_user_added_to_our_object_keeps_the_object() {
    let e = env();
    let ide = e.ide_with("{\n  \"a\": 1\n}\n", 0o644);
    e.enable(None);
    let mine = jsonc::set(&e.text(&ide), &[ide_env_key(), "MINE"], "\"1\"").unwrap();
    e.user_writes(&ide, &mine);
    e.disable();
    let after = e.text(&ide);
    assert_eq!(raw(&after, &[ide_env_key(), "MINE"]), Some("\"1\"".into()));
    assert_eq!(raw(&after, &[ide_env_key(), "HTTP_PROXY"]), None);
    assert_eq!(raw(&after, &["http.proxy"]), None);
}

#[test]
fn a_comment_inside_the_object_we_made_keeps_the_object() {
    let e = env();
    let ide = e.ide_with("{\n  \"a\": 1\n}\n", 0o644);
    e.enable(None);
    // The user removed our variables and left a note in the (now empty) object.
    let mut t = e.text(&ide);
    for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
        t = jsonc::remove(&t, &[ide_env_key(), k]).unwrap();
    }
    let key = ide_env_key();
    let obj = format!("\"{key}\": {{}}");
    assert!(t.contains(&obj), "{t}");
    t = t.replace(&obj, &format!("\"{key}\": {{ /* mine */ }}"));
    e.user_writes(&ide, &t);
    e.disable();
    let after = e.text(&ide);
    assert!(after.contains("/* mine */"), "{after}");
    assert!(
        jsonc::get(&after, &[key]).unwrap().is_some(),
        "the container stays"
    );
    assert_eq!(raw(&after, &["http.proxy"]), None);
}

#[test]
fn values_the_user_had_before_us_are_the_baseline_and_come_back() {
    let e = env();
    let original = "{\n  \"http.proxy\": \"http://corp:3128\",\n  \"http.proxySupport\": \"on\",\n  // keep\n  \"x\": [1, 2, 3],\n}\n";
    let ide = e.ide_with(original, 0o644);
    e.enable(None);
    assert_eq!(
        raw(&e.text(&ide), &["http.proxy"]),
        Some(format!("\"{URL}\""))
    );
    e.disable();
    assert_eq!(e.text(&ide), original);
}

#[test]
fn damaged_or_ambiguous_files_are_never_written() {
    let cases: [(&str, &[u8]); 5] = [
        ("syntax", b"{\n  \"a\": 1,, \"b\": \n}\n"),
        ("unterminated", b"{\n  \"a\": \"x\n"),
        (
            "duplicate",
            b"{\n  \"http.proxy\": \"a\",\n  \"http.proxy\": \"b\"\n}\n",
        ),
        ("array", b"[1, 2, 3]\n"),
        ("not utf-8", b"{\"a\": \"\xff\xfe\"}\n"),
    ];
    for (name, bytes) in cases {
        let e = env();
        e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
        e.fs.put(Path::new(IDE_FILE), bytes, 0o644);
        let targets = e.enable(None);
        assert!(
            !targets.contains(&"VS Code".to_string()),
            "{name}: {targets:?}"
        );
        assert!(
            targets.contains(&"Claude Code".to_string()),
            "{name}: the others go on"
        );
        assert_eq!(e.fs.get(Path::new(IDE_FILE)).unwrap(), bytes, "{name}");
        let j = e.journal();
        assert!(
            j.entries()
                .iter()
                .all(|r| !r.resource.id().contains("Code/User")),
            "{name}: nothing recorded for the refused file"
        );
        drop(j);
        e.disable();
        assert_eq!(e.fs.get(Path::new(IDE_FILE)).unwrap(), bytes, "{name}");
    }
}

#[test]
fn a_crash_before_the_file_write_leaves_file_and_journal_recoverable() {
    let e = env();
    let original = "{\n  // c\n  \"a\": 1\n}\n";
    let ide = e.ide_with(original, 0o644);
    {
        let mut j = e.journal();
        // intent lands, the file write fails, and so does the clean-up: as if killed there
        e.fs.fail_range(FsOp::WriteAtomic, 1, 2);
        let r = apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, Some(URL), None);
        assert!(r.is_err());
    }
    assert_eq!(e.text(&ide), original, "the file was not touched");
    let mut j = e.journal();
    assert_eq!(j.entries().len(), 1, "the durable intent is still there");
    let report = j.restore_all(&e.p);
    assert_eq!(report.failed(), 0);
    assert_eq!(e.text(&ide), original);
    assert!(j.is_empty());
}

#[test]
fn a_crash_after_the_file_write_before_the_applied_mark_still_restores() {
    let e = env();
    let original = "{\n  \"a\": 1\n}\n";
    let ide = e.ide_with(original, 0o644);
    {
        let mut j = e.journal();
        e.fs.fail_after(FsOp::WriteAtomic, 2); // intent, file write, then "applied" fails
        assert!(apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, Some(URL), None).is_err());
    }
    assert_ne!(e.text(&ide), original, "the write landed");
    let mut j = e.journal();
    let report = j.restore_all(&e.p);
    assert_eq!(report.failed(), 0, "{}", report.summary());
    assert_eq!(e.text(&ide), original);
}

#[cfg(unix)]
#[test]
fn a_symlinked_settings_file_keeps_its_link_and_its_target_gets_the_edit() {
    let e = env();
    e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
    let target = Path::new("/dotfiles/vscode-settings.json");
    let original = "{\n  \"a\": 1\n}\n";
    e.fs.put(target, original.as_bytes(), 0o600);
    e.fs.symlink(Path::new(IDE_FILE), target);
    e.enable(None);
    assert!(
        e.fs.is_symlink(Path::new(IDE_FILE)),
        "the link was not replaced"
    );
    assert!(e.text(target).contains("http.proxy"));
    assert_eq!(e.fs.mode(target).unwrap(), Some(0o600));
    e.disable();
    assert!(e.fs.is_symlink(Path::new(IDE_FILE)));
    assert_eq!(e.text(target), original);
}

#[test]
fn timezone_keys_follow_the_synced_timezone_and_leave_with_it() {
    let e = env();
    let claude = e.ctx.claude_settings();
    let original = "{\n  \"model\": \"opus\"\n}\n";
    e.fs.create_private_dir_all(&e.ctx.home.join(".claude"))
        .unwrap();
    e.fs.put(&claude, original.as_bytes(), 0o644);
    e.enable(Some("Europe/Berlin"));
    let t = e.text(&claude);
    assert_eq!(raw(&t, &["env", "TZ"]), Some("\"Europe/Berlin\"".into()));
    assert_eq!(raw(&t, &["env", "LANG"]), Some("\"en_US.UTF-8\"".into()));
    e.enable(None);
    let t = e.text(&claude);
    assert_eq!(
        raw(&t, &["env", "TZ"]),
        None,
        "no timezone is synced any more"
    );
    assert_eq!(raw(&t, &["env", "LC_ALL"]), None);
    assert_eq!(raw(&t, &["env", "HTTPS_PROXY"]), Some(format!("\"{URL}\"")));
    assert_eq!(raw(&t, &["model"]), Some("\"opus\"".into()));
    e.disable();
    assert_eq!(e.text(&claude), original);
}

#[test]
fn enabling_twice_changes_nothing_and_a_new_port_updates_in_place() {
    let e = env();
    let ide = e.ide_with("{}\n", 0o644);
    e.enable(None);
    let writes = e.fs.write_count();
    let first = e.text(&ide);
    e.enable(None);
    assert_eq!(
        e.fs.write_count(),
        writes,
        "nothing was written the second time"
    );
    let mut j = e.journal();
    let plan = FilePlan {
        proxy_url: Some("http://127.0.0.1:8900"),
        port: 8900,
        tz: None,
        mode: CliMode::GlobalTerminal,
        os: HostOs::Unix,
        strip_unjournaled_blocks: false,
    };
    apply_files(&mut j, &e.p, &e.ctx, &plan);
    drop(j);
    let moved = e.text(&ide);
    assert_ne!(moved, first);
    assert!(moved.contains("127.0.0.1:8900") && !moved.contains("127.0.0.1:8899"));
    e.disable();
    assert_eq!(
        e.text(&ide),
        "{}\n",
        "the original baseline survived the update"
    );
}

#[test]
fn gemini_is_configured_only_when_its_directory_exists() {
    let e = env();
    assert!(!e.enable(None).contains(&"Gemini CLI".to_string()));
    e.disable();
    e.fs.create_private_dir_all(&e.ctx.home.join(".gemini"))
        .unwrap();
    assert!(e.enable(None).contains(&"Gemini CLI".to_string()));
    assert!(e.text(&e.ctx.gemini_settings()).contains("HTTPS_PROXY"));
    e.disable();
    assert!(e.fs.get(&e.ctx.gemini_settings()).is_none());
}

#[test]
fn leftovers_of_a_build_without_a_journal_are_cleaned_once_and_user_values_stay() {
    let e = env();
    let key = ide_env_key();
    let legacy = format!(
        "{{\n  \"http.proxy\": \"{URL}\",\n  \"http.proxySupport\": \"override\",\n  \"{key}\": {{\n    \"HTTP_PROXY\": \"{URL}\",\n    \"HTTPS_PROXY\": \"{URL}\",\n    \"NO_PROXY\": \"localhost,127.0.0.1,::1,.local\",\n    \"FOO\": \"keep\"\n  }},\n  \"editor.fontSize\": 14\n}}\n"
    );
    let ide = e.ide_with(&legacy, 0o644);
    let claude = e.ctx.claude_settings();
    let corp = "{\n  \"env\": {\n    \"HTTPS_PROXY\": \"http://corp:3128\",\n    \"TZ\": \"Europe/Berlin\"\n  }\n}\n";
    e.fs.put(&claude, corp.as_bytes(), 0o644);
    e.disable();
    let t = e.text(&ide);
    assert!(!t.contains("127.0.0.1"), "{t}");
    assert_eq!(raw(&t, &[key, "FOO"]), Some("\"keep\"".into()));
    assert_eq!(raw(&t, &["editor.fontSize"]), Some("14".into()));
    assert_eq!(e.text(&claude), corp, "no Zastava signature, not ours");
    // After the one-time pass a value that looks like ours is left alone.
    let again = jsonc::set(&t, &["http.proxy"], &format!("\"{URL}\"")).unwrap();
    e.user_writes(&ide, &again);
    e.disable();
    assert_eq!(
        raw(&e.text(&ide), &["http.proxy"]),
        Some(format!("\"{URL}\""))
    );
}

#[test]
fn journal_ids_and_logs_name_files_without_the_home_path_or_values() {
    let e = env();
    e.ide_with("{}\n", 0o644);
    e.enable(Some("Europe/Berlin"));
    let j = e.journal();
    assert!(!j.entries().is_empty());
    let shown = format!("{j:?}");
    for entry in j.entries() {
        let id = entry.resource.id();
        assert!(!id.contains(HOME) && !id.contains("127.0.0.1"), "{id}");
    }
    assert!(!shown.contains(HOME) && !shown.contains("127.0.0.1") && !shown.contains("Berlin"));
}

#[test]
fn a_failing_read_skips_that_file_and_records_nothing() {
    let e = env();
    let original = "{\n  \"a\": 1\n}\n";
    let ide = e.ide_with(original, 0o644);
    let mut j = e.journal();
    e.fs.fail_next(FsOp::Read);
    let r = apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, Some(URL), None);
    assert!(r.is_err());
    assert!(j.is_empty(), "no intent for a file that could not be read");
    assert_eq!(e.text(&ide), original);
    // The next file is independent.
    let claude = e.ctx.claude_settings();
    apply_agent_settings(&mut j, &e.p, &e.ctx, &claude, Some(URL), None).unwrap();
    assert!(e.text(&claude).contains("HTTPS_PROXY"));
}
