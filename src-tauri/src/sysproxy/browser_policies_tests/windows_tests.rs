use super::*;

#[test]
fn windows_skips_user_data_local_state_and_preferences_scanning() {
    use crate::sysproxy::fs::Fs;

    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);
    let probe = StubProbe::fixed(Some(""));

    let chrome_ud = ctx.local_appdata.join("Google/Chrome/User Data");
    let default_prefs = chrome_ud.join("Default/Preferences");
    let profile1_prefs = chrome_ud.join("Profile 1/Preferences");
    let custom_prefs = chrome_ud.join("CustomProfile/Preferences");
    let local_state = chrome_ud.join("Local State");
    let opera_prefs = ctx
        .home
        .join("AppData/Roaming/Opera Software/Opera Stable/Preferences");

    put_prefs(&fs, &default_prefs, r#"{"homepage":"about:blank"}"#);
    put_prefs(
        &fs,
        &profile1_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac"}}"#,
    );
    put_prefs(&fs, &custom_prefs, "{}");
    put_prefs(&fs, &opera_prefs, "{}");
    fs.put(
        &local_state,
        br#"{"profile":{"info_cache":{"CustomProfile":{}}}}"#,
        0o600,
    );

    for browser in &CHROMIUM_BROWSERS {
        assert!(
            browser_user_data_dirs(browser, &ctx, Os::Windows).is_empty(),
            "{}",
            browser.id
        );
        assert!(
            browser_prefs_files_in(browser, &ctx, Os::Windows).is_empty(),
            "{}",
            browser.id
        );
    }

    store.set_domain_applicable(r"Software\Policies\Google\Chrome", true);
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    // apply_browser_policies_with_pac_in must not touch Windows Preferences even on Os::Windows.
    let rep = apply_browser_policies_with_pac_in(
        &mut j,
        &plat,
        Some(pac),
        Some(&ctx),
        Os::Windows,
        &probe,
    );
    assert_eq!(rep.failed, 0);
    // Apply Windows policy specs explicitly so cross-platform tests verify all 4 HKCU values
    // regardless of host compile target.
    let win_rep = apply_policy_specs(&mut j, &plat, &policy_specs_for_windows(Some(pac)));
    assert_eq!(win_rep.failed, 0);
    assert!(
        !j.entries()
            .iter()
            .any(|e| matches!(e.resource, Resource::BrowserPacPref { .. }))
    );
    assert_eq!(
        store.get(r"Software\Policies\Google\Chrome", KEY_QUIC_ALLOWED),
        Some(PolicyValue::Dword(0))
    );
    assert_eq!(
        store.get(r"Software\Policies\Google\Chrome", KEY_DOH_MODE),
        Some(PolicyValue::Sz("off".to_string()))
    );
    assert_eq!(
        store.get(r"Software\Policies\Google\Chrome", KEY_PROXY_MODE),
        Some(PolicyValue::Sz("pac_script".to_string()))
    );
    assert_eq!(
        store.get(r"Software\Policies\Google\Chrome", KEY_PROXY_PAC_URL),
        Some(PolicyValue::Sz(pac.to_string()))
    );
    assert_eq!(
        fs.read(&default_prefs).unwrap().as_deref(),
        Some(br#"{"homepage":"about:blank"}"#.as_slice())
    );

    assert!(!any_non_running_browser_needs_pac_sync_in(
        &ctx,
        Os::Windows,
        &probe,
        pac
    ));
    assert!(!reconcile_browser_pac_prefs_in(
        &mut j,
        &plat,
        Some(pac),
        &ctx,
        Os::Windows,
        &probe
    ));
    assert_eq!(
        clear_stale_browser_pac_prefs_in(&ctx, Os::Windows, &probe),
        0
    );
    // Existing Windows Profile 1 Preferences was not touched by cleanup either.
    assert!(
        fs.read(&profile1_prefs)
            .unwrap()
            .is_some_and(|b| !b.is_empty())
    );
}

#[test]
fn windows_detect_browser_pac_status_uses_hkcu_policies_and_wininet() {
    use crate::sysproxy::platform::RegValue;

    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let ctx = test_ctx(&fs);
    let probe = StubProbe::fixed(Some(""));

    // Even if a Preferences file with Zastava PAC exists in Edge User Data,
    // Windows status ignores User Data / Preferences.
    let edge_prefs = ctx
        .local_appdata
        .join("Microsoft/Edge/User Data/Default/Preferences");
    put_prefs(
        &fs,
        &edge_prefs,
        r#"{"proxy":{"mode":"pac_script","pac_url":"http://127.0.0.1:8899/proxy.pac"}}"#,
    );
    let s0 = detect_browser_pac_status_with(
        Some(&ctx),
        Os::Windows,
        &probe,
        Some(pac),
        &*store,
        &plat,
    );
    assert!(s0.browsers_pac_active.is_empty());
    assert!(s0.browsers_needing_restart.is_empty());

    // When only WinINet AutoConfigURL matches, WinINet is reported.
    plat.seed_inet("AutoConfigURL", RegValue::sz(pac));
    let s1 = detect_browser_pac_status_with(
        None,
        Os::Windows,
        &probe,
        Some(pac),
        &*store,
        &plat,
    );
    assert_eq!(
        s1.browsers_pac_active,
        vec!["Windows Internet Settings (WinINet)".to_string()]
    );

    // When HKCU policy keys are applied (even across both Yandex keys), Chromium browsers
    // are reported and deduped, and remain active even if WinINet is overridden by a VPN.
    for domain in WINDOWS_CHROMIUM_DOMAIN_NAMES {
        store.set_domain_applicable(domain, false);
    }
    store.set_domain_applicable(r"Software\Policies\Microsoft\Edge", true);
    store.set_domain_applicable(r"Software\Policies\YandexBrowser", true);
    store.set_domain_applicable(r"Software\Policies\Yandex\YandexBrowser", true);
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());
    let rep = apply_policy_specs(&mut j, &plat, &policy_specs_for_windows(Some(pac)));
    assert_eq!(rep.failed, 0);

    plat.seed_inet("AutoConfigURL", RegValue::sz(""));
    let s2 = detect_browser_pac_status_with(
        Some(&ctx),
        Os::Windows,
        &probe,
        Some(pac),
        &*store,
        &plat,
    );
    assert_eq!(
        s2.browsers_pac_active,
        vec!["Microsoft Edge".to_string(), "Yandex Browser".to_string()]
    );
    assert!(s2.browsers_needing_restart.is_empty());
}
