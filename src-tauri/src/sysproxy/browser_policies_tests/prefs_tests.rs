use super::*;

#[test]
fn preferences_json_injection_preserves_existing_keys_and_reverts() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);
    let probe = StubProbe::fixed(Some(""));

    let chrome_prefs = ctx
        .home
        .join("Library/Application Support/Google/Chrome/Default/Preferences");
    let comet_prefs = ctx
        .home
        .join("Library/Application Support/Comet/Profile 1/Preferences");

    put_prefs(
        &fs,
        &chrome_prefs,
        r#"{"browser":{"show_home_button":true},"extensions":{"theme":{"id":"abc"}}}"#,
    );
    put_prefs(
        &fs,
        &comet_prefs,
        r#"{"proxy":{"mode":"fixed_servers","server":"10.0.0.1:8080"},"profile":{"name":"Work"}}"#,
    );

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    let rep = apply_browser_policies_with_pac_in(
        &mut j,
        &plat,
        Some(pac),
        Some(&ctx),
        Os::Macos,
        &probe,
    );
    assert_eq!(rep.failed, 0);
    assert!(rep.pac_policy_active);

    let chrome_after = read_json(&fs, &chrome_prefs);
    assert_eq!(chrome_after["browser"]["show_home_button"], true);
    assert_eq!(chrome_after["extensions"]["theme"]["id"], "abc");
    assert_eq!(chrome_after["proxy"]["mode"], "pac_script");
    assert_eq!(chrome_after["proxy"]["pac_url"], pac);
    assert_eq!(chrome_after["proxy"]["pac_mandatory"], false);

    let comet_after = read_json(&fs, &comet_prefs);
    assert_eq!(comet_after["profile"]["name"], "Work");
    assert_eq!(comet_after["proxy"]["mode"], "pac_script");
    assert_eq!(comet_after["proxy"]["pac_url"], pac);

    let rec = revert_browser_policies_with(&mut j, &plat, Os::Macos, &probe);
    assert!(!rec.has_failures());

    let chrome_reverted = read_json(&fs, &chrome_prefs);
    assert!(chrome_reverted.get("proxy").is_none());
    assert_eq!(chrome_reverted["browser"]["show_home_button"], true);

    let comet_reverted = read_json(&fs, &comet_prefs);
    assert_eq!(comet_reverted["proxy"]["mode"], "fixed_servers");
    assert_eq!(comet_reverted["proxy"]["server"], "10.0.0.1:8080");
    assert_eq!(comet_reverted["profile"]["name"], "Work");
}

#[test]
fn multi_profile_discovery_includes_local_state_and_opera_single_profile() {
    let fs = Arc::new(FakeFs::new());
    let ctx = test_ctx(&fs);
    let comet_dir = ctx.home.join("Library/Application Support/Comet");
    let opera_dir = ctx
        .home
        .join("Library/Application Support/com.operasoftware.Opera");

    put_prefs(&fs, &comet_dir.join("Default/Preferences"), "{}");
    put_prefs(&fs, &comet_dir.join("Profile 2/Preferences"), "{}");
    put_prefs(&fs, &comet_dir.join("CustomWork/Preferences"), "{}");
    fs.put(
        &comet_dir.join("Local State"),
        br#"{"profile":{"info_cache":{"Default":{},"CustomWork":{}}}}"#,
        0o600,
    );
    put_prefs(&fs, &opera_dir.join("Preferences"), "{}");

    let comet_def = CHROMIUM_BROWSERS
        .iter()
        .find(|b| b.id == "ai.perplexity.comet")
        .unwrap();
    let opera_def = CHROMIUM_BROWSERS
        .iter()
        .find(|b| b.id == "com.operasoftware.Opera")
        .unwrap();

    let comet_files = browser_prefs_files_in(comet_def, &ctx, Os::Macos);
    assert_eq!(comet_files.len(), 3);
    assert!(comet_files.contains(&comet_dir.join("Default/Preferences")));
    assert!(comet_files.contains(&comet_dir.join("Profile 2/Preferences")));
    assert!(comet_files.contains(&comet_dir.join("CustomWork/Preferences")));

    let opera_files = browser_prefs_files_in(opera_def, &ctx, Os::Macos);
    assert_eq!(opera_files, vec![opera_dir.join("Preferences")]);
}

#[test]
fn corrupt_or_non_object_preferences_are_skipped_without_overwrite() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);
    let probe = StubProbe::fixed(Some(""));

    let bad_prefs = ctx
        .home
        .join("Library/Application Support/Google/Chrome/Default/Preferences");
    let raw_bad = b"{not valid json";
    fs.put(&bad_prefs, raw_bad, 0o600);

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store);
    let rep = apply_browser_policies_with_pac_in(
        &mut j,
        &plat,
        Some(pac),
        Some(&ctx),
        Os::Macos,
        &probe,
    );
    assert_eq!(rep.failed, 1);
    assert!(!rep.pac_policy_active);
    assert_eq!(fs.read(&bad_prefs).unwrap().unwrap(), raw_bad);
}

#[test]
fn running_browser_skips_preferences_injection_and_revert_until_exited() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);

    let chrome_prefs = ctx
        .home
        .join("Library/Application Support/Google/Chrome/Default/Preferences");
    let yandex_prefs = ctx
        .home
        .join("Library/Application Support/Yandex/YandexBrowser/Default/Preferences");
    put_prefs(&fs, &chrome_prefs, r#"{"profile":{"name":"Main"}}"#);
    put_prefs(&fs, &yandex_prefs, r#"{"profile":{"name":"Ya"}}"#);

    // Chrome is running without PAC flag; Yandex is closed.
    let running_chrome = StubProbe::fixed(Some(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n",
    ));

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store);

    let rep = apply_browser_policies_with_pac_in(
        &mut j,
        &plat,
        Some(pac),
        Some(&ctx),
        Os::Macos,
        &running_chrome,
    );
    assert!(rep.applied >= 1);
    assert!(rep.skipped >= 1);
    assert!(read_json(&fs, &chrome_prefs).get("proxy").is_none());
    assert_eq!(read_json(&fs, &yandex_prefs)["proxy"]["pac_url"], pac);

    // Chrome exits -> reconciler injects Chrome's Preferences.
    let all_closed = StubProbe::fixed(Some(""));
    assert!(reconcile_browser_pac_prefs_in(
        &mut j,
        &plat,
        Some(pac),
        &ctx,
        Os::Macos,
        &all_closed
    ));
    assert_eq!(read_json(&fs, &chrome_prefs)["proxy"]["pac_url"], pac);

    // Now Yandex is running at revert time -> Yandex revert is skipped, Chrome reverts.
    let running_yandex =
        StubProbe::fixed(Some("/Applications/Yandex.app/Contents/MacOS/Yandex\n"));
    let rec = revert_browser_policies_with(&mut j, &plat, Os::Macos, &running_yandex);
    assert!(!rec.has_failures());
    assert!(read_json(&fs, &chrome_prefs).get("proxy").is_none());
    assert_eq!(read_json(&fs, &yandex_prefs)["proxy"]["pac_url"], pac);

    // Yandex closes -> reconcile(None) restores Yandex's baseline.
    assert!(reconcile_browser_pac_prefs_in(
        &mut j,
        &plat,
        None,
        &ctx,
        Os::Macos,
        &all_closed
    ));
    assert!(read_json(&fs, &yandex_prefs).get("proxy").is_none());
}

#[test]
fn clear_stale_browser_pac_prefs_removes_only_zastava_local_pac_urls() {
    let fs = Arc::new(FakeFs::new());
    let ctx = test_ctx(&fs);
    let chrome_prefs = ctx
        .home
        .join("Library/Application Support/Google/Chrome/Default/Preferences");
    let brave_prefs = ctx
        .home
        .join("Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences");
    let comet_prefs = ctx
        .home
        .join("Library/Application Support/Comet/Default/Preferences");

    put_prefs(
        &fs,
        &chrome_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:54321/proxy.pac","pac_mandatory":false},"keep":1}"#,
    );
    put_prefs(
        &fs,
        &brave_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"https://corp.example/wpad.dat"}}"#,
    );
    put_prefs(
        &fs,
        &comet_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac"}}"#,
    );

    // Comet is still running, Chrome & Brave are closed.
    let probe = StubProbe::fixed(Some("/Applications/Comet.app/Contents/MacOS/Comet\n"));
    let cleaned = clear_stale_browser_pac_prefs_in(&ctx, Os::Macos, &probe);
    assert_eq!(cleaned, 1);

    let chrome = read_json(&fs, &chrome_prefs);
    assert!(chrome.get("proxy").is_none());
    assert_eq!(chrome["keep"], 1);
    assert_eq!(
        read_json(&fs, &brave_prefs)["proxy"]["pac_url"],
        "https://corp.example/wpad.dat"
    );
    assert_eq!(
        read_json(&fs, &comet_prefs)["proxy"]["pac_url"],
        "http://127.0.0.1:8899/proxy.pac"
    );
}

#[test]
fn detect_browser_pac_status_distinguishes_active_and_needing_restart() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let ctx = test_ctx(&fs);

    let chrome_prefs = ctx
        .home
        .join("Library/Application Support/Google/Chrome/Default/Preferences");
    let comet_prefs = ctx
        .home
        .join("Library/Application Support/Comet/Default/Preferences");
    let dia_prefs = ctx
        .home
        .join("Library/Application Support/Dia/User Data/Default/Preferences");
    let arc_prefs = ctx
        .home
        .join("Library/Application Support/Arc/User Data/Default/Preferences");

    // Chrome: running WITHOUT flag and WITHOUT Preferences -> needs restart.
    put_prefs(&fs, &chrome_prefs, "{}");
    // Comet: running WITH --proxy-pac-url=<pac> -> active even without Preferences.
    put_prefs(&fs, &comet_prefs, "{}");
    // Dia: running WITHOUT flag, but Preferences ALREADY has our PAC -> active.
    put_prefs(
        &fs,
        &dia_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
    );
    // Arc: closed, Preferences has our PAC -> active.
    put_prefs(
        &fs,
        &arc_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac","pac_mandatory":false}}"#,
    );

    let ps = format!(
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n\
         /Applications/Comet.app/Contents/MacOS/Comet --proxy-pac-url={pac}\n\
         /Applications/Dia.app/Contents/MacOS/Dia\n"
    );
    let probe = StubProbe::fixed(Some(&ps));
    let status = detect_browser_pac_status_in(&ctx, Os::Macos, &probe, Some(pac));

    assert_eq!(
        status.browsers_needing_restart,
        vec!["Google Chrome".to_string()]
    );
    assert_eq!(
        status.browsers_pac_active,
        vec!["Comet".to_string(), "Arc".to_string(), "Dia".to_string()]
    );
}

#[test]
fn relaunch_browsers_with_pac_quits_patches_and_reopens_with_flag() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);

    fs.create_private_dir_all(&PathBuf::from("/Applications/Google Chrome.app"))
        .unwrap();
    let chrome_prefs = ctx
        .home
        .join("Library/Application Support/Google/Chrome/Default/Preferences");
    put_prefs(&fs, &chrome_prefs, r#"{"keep":"yes"}"#);

    // First call (detect status): Chrome running; second call (wait after osascript): exited.
    let probe = StubProbe::sequence(vec![
        Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n"),
        Some(""),
    ]);
    let launcher = StubLauncher::default();
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store);
    let timing = QuitTiming {
        timeout: Duration::from_millis(50),
        interval: Duration::from_millis(5),
    };

    let summary = relaunch_browsers_with_pac_with(
        &mut j,
        &plat,
        pac,
        &ctx,
        Os::Macos,
        &probe,
        &launcher,
        timing,
    );

    assert_eq!(summary.restarted, vec!["Google Chrome".to_string()]);
    assert!(summary.skipped.is_empty());
    assert!(summary.failed.is_empty());
    assert_eq!(read_json(&fs, &chrome_prefs)["proxy"]["pac_url"], pac);
    assert_eq!(read_json(&fs, &chrome_prefs)["keep"], "yes");

    let calls = launcher.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].0, "osascript");
    assert!(calls[0].1[1].contains("com.google.Chrome"));
    assert_eq!(calls[1].0, "open");
    assert_eq!(
        calls[1].1,
        vec![
            "-a".to_string(),
            "/Applications/Google Chrome.app".to_string(),
            "--args".to_string(),
            format!("--proxy-pac-url={pac}"),
        ]
    );
}

#[test]
fn relaunch_browsers_with_pac_returns_unsupported_on_windows() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);
    let probe = StubProbe::fixed(Some(""));
    let launcher = StubLauncher::default();
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store);
    let timing = QuitTiming {
        timeout: Duration::from_millis(10),
        interval: Duration::from_millis(5),
    };

    let summary = relaunch_browsers_with_pac_with(
        &mut j,
        &plat,
        pac,
        &ctx,
        Os::Windows,
        &probe,
        &launcher,
        timing,
    );

    assert!(summary.unsupported);
    assert!(summary.restarted.is_empty());
    assert!(summary.skipped.is_empty());
    assert!(summary.failed.is_empty());
    assert!(launcher.calls.lock().unwrap().is_empty());
}

