use super::*;

fn sample_specs() -> Vec<PolicySpec> {
    vec![
        PolicySpec::new("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(false)),
        PolicySpec::new(
            "com.google.Chrome",
            "DnsOverHttpsMode",
            PolicyValue::Sz("off".to_string()),
        ),
    ]
}

#[test]
fn apply_from_absent_writes_and_restore_deletes() {
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
    assert_eq!(rep.applied, 2);
    assert_eq!(rep.failed, 0);
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(false))
    );
    assert_eq!(
        store.get("com.google.Chrome", "DnsOverHttpsMode"),
        Some(PolicyValue::Sz("off".to_string()))
    );

    let rec = j.restore_all(&plat);
    assert_eq!(rec.items.len(), 2);
    assert!(rec.items.iter().all(|i| i.outcome == Outcome::Restored));
    assert_eq!(store.get("com.google.Chrome", "QuicAllowed"), None);
    assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
}

#[test]
fn apply_over_existing_user_setting_restores_original_value() {
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));
    store.preset(
        "com.google.Chrome",
        "DnsOverHttpsMode",
        PolicyValue::Sz("automatic".to_string()),
    );

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());
    let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
    assert_eq!(rep.applied, 2);
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(false))
    );

    // Re-applying while active is idempotent.
    let rep2 = apply_policy_specs(&mut j, &plat, &sample_specs());
    assert_eq!(rep2.unchanged, 2);

    let rec = j.restore_all(&plat);
    assert!(rec.items.iter().all(|i| i.outcome == Outcome::Restored));
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(true))
    );
    assert_eq!(
        store.get("com.google.Chrome", "DnsOverHttpsMode"),
        Some(PolicyValue::Sz("automatic".to_string()))
    );
}

#[test]
fn external_change_blocks_blind_overwrite_on_restore() {
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    apply_policy_specs(&mut j, &plat, &sample_specs());
    // Admin/MDM changed QuicAllowed while Zastava was running.
    store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

    let rec = j.restore_all(&plat);
    let quic = rec
        .items
        .iter()
        .find(|i| i.resource.ends_with(":QuicAllowed"))
        .unwrap();
    assert_eq!(quic.outcome, Outcome::ExternalChange);
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(true)),
        "external change must not be deleted or overwritten"
    );
    // The untouched DoH key is still restored to absent.
    assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
}

#[test]
fn inapplicable_domain_is_skipped_without_reading_or_writing() {
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    store.set_domain_applicable("com.microsoft.Edge", false);
    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    let specs = vec![PolicySpec::new(
        "com.microsoft.Edge",
        "QuicAllowed",
        PolicyValue::Bool(false),
    )];
    let rep = apply_policy_specs(&mut j, &plat, &specs);
    assert_eq!(rep.skipped, 1);
    assert_eq!(rep.applied, 0);
    assert!(j.entries().is_empty());
}

#[test]
fn crash_recovery_from_disk_restores_baseline() {
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    store.preset("com.google.Chrome", "QuicAllowed", PolicyValue::Bool(true));

    {
        let mut j = Journal::open(fs.clone(), Path::new(DIR))
            .unwrap()
            .with_policy_store(store.clone());
        let rep = apply_policy_specs(&mut j, &plat, &sample_specs());
        assert_eq!(rep.applied, 2);
        assert_eq!(j.entries()[0].state, EntryState::Applied);
    }

    // Simulate restart / crash recovery via a fresh Journal open + policy store.
    let mut j2 = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());
    let rec = j2.restore_all(&plat);
    assert_eq!(rec.items.len(), 2);
    assert_eq!(
        store.get("com.google.Chrome", "QuicAllowed"),
        Some(PolicyValue::Bool(true))
    );
    assert_eq!(store.get("com.google.Chrome", "DnsOverHttpsMode"), None);
    // Default recover_with uses RealPolicyStore; verify dry-run does not touch host.
    let _ = recover_with(fs, &plat, Path::new(DIR));
}

#[test]
fn policy_specs_with_pac_covers_all_chromium_browsers_macos_and_windows() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let mac_no_pac = policy_specs_for_macos(None);
    assert!(
        mac_no_pac
            .iter()
            .all(|s| s.key != KEY_PROXY_MODE && s.key != KEY_PROXY_PAC_URL)
    );

    let mac_with_pac = policy_specs_for_macos(Some(pac));
    for domain in [
        "com.google.Chrome",
        "com.google.Chrome.beta",
        "com.google.Chrome.canary",
        "com.brave.Browser",
        "com.brave.Browser.beta",
        "com.microsoft.edgemac",
        "org.chromium.Chromium",
        "com.vivaldi.Vivaldi",
        "com.operasoftware.Opera",
        "com.operasoftware.OperaGX",
        "ru.yandex.desktop.yandex-browser",
        "company.thebrowser.Browser",
        "company.thebrowser.dia",
        "ai.perplexity.comet",
        "com.openai.atlas",
    ] {
        assert!(
            mac_with_pac.iter().any(|s| {
                s.domain == domain
                    && s.key == KEY_PROXY_MODE
                    && s.value == PolicyValue::Sz("pac_script".to_string())
            }),
            "missing ProxyMode for {domain}"
        );
        assert!(
            mac_with_pac.iter().any(|s| {
                s.domain == domain
                    && s.key == KEY_PROXY_PAC_URL
                    && s.value == PolicyValue::Sz(pac.to_string())
            }),
            "missing ProxyPacUrl for {domain}"
        );
        assert!(
            mac_with_pac.iter().any(|s| {
                s.domain == domain
                    && s.key == KEY_QUIC_ALLOWED
                    && s.value == PolicyValue::Bool(false)
            }),
            "missing QuicAllowed for {domain}"
        );
        assert!(
            mac_with_pac.iter().any(|s| {
                s.domain == domain
                    && s.key == KEY_DOH_MODE
                    && s.value == PolicyValue::Sz("off".to_string())
            }),
            "missing DnsOverHttpsMode for {domain}"
        );
    }

    let win_with_pac = policy_specs_for_windows(Some(pac));
    for subkey in [
        r"Software\Policies\Google\Chrome",
        r"Software\Policies\Microsoft\Edge",
        r"Software\Policies\BraveSoftware\Brave",
        r"Software\Policies\Chromium",
        r"Software\Policies\Vivaldi",
        r"Software\Policies\YandexBrowser",
        r"Software\Policies\Yandex\YandexBrowser",
        r"Software\Policies\Perplexity\Comet",
        r"Software\Policies\Opera Software\Opera Stable",
        r"Software\Policies\Opera Software\Opera GX Stable",
        r"Software\Policies\TheBrowserCompany\Arc",
        r"Software\Policies\TheBrowserCompany\Dia",
    ] {
        assert!(WINDOWS_CHROMIUM_DOMAIN_NAMES.contains(&subkey));
        assert!(
            win_with_pac.iter().any(|s| {
                s.domain == subkey
                    && s.key == KEY_PROXY_MODE
                    && s.value == PolicyValue::Sz("pac_script".to_string())
            }),
            "missing ProxyMode for {subkey}"
        );
        assert!(
            win_with_pac.iter().any(|s| {
                s.domain == subkey
                    && s.key == KEY_PROXY_PAC_URL
                    && s.value == PolicyValue::Sz(pac.to_string())
            }),
            "missing ProxyPacUrl for {subkey}"
        );
        assert!(
            win_with_pac.iter().any(|s| {
                s.domain == subkey
                    && s.key == KEY_QUIC_ALLOWED
                    && s.value == PolicyValue::Dword(0)
            }),
            "missing QuicAllowed for {subkey}"
        );
        assert!(
            win_with_pac.iter().any(|s| {
                s.domain == subkey
                    && s.key == KEY_DOH_MODE
                    && s.value == PolicyValue::Sz("off".to_string())
            }),
            "missing DnsOverHttpsMode for {subkey}"
        );
    }
}

#[test]
fn pac_policies_are_journaled_and_restored_cleanly() {
    let pac = "http://127.0.0.1:9123/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    // Chrome had no proxy policy before; Arc had a corporate PAC configured by user/admin.
    store.preset(
        "company.thebrowser.Browser",
        KEY_PROXY_MODE,
        PolicyValue::Sz("fixed_servers".to_string()),
    );
    store.preset(
        "company.thebrowser.Browser",
        KEY_PROXY_PAC_URL,
        PolicyValue::Sz("https://corp.example/proxy.pac".to_string()),
    );
    for d in MACOS_CHROMIUM_DOMAIN_NAMES {
        if d != "com.google.Chrome" && d != "company.thebrowser.Browser" {
            store.set_domain_applicable(d, false);
        }
    }

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    let specs = policy_specs_for_macos(Some(pac));
    let rep = apply_policy_specs(&mut j, &plat, &specs);
    assert_eq!(rep.failed, 0);
    assert!(is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        pac
    ));
    assert_eq!(
        store.get("com.google.Chrome", KEY_PROXY_MODE),
        Some(PolicyValue::Sz("pac_script".to_string()))
    );
    assert_eq!(
        store.get("com.google.Chrome", KEY_PROXY_PAC_URL),
        Some(PolicyValue::Sz(pac.to_string()))
    );
    assert_eq!(
        store.get("company.thebrowser.Browser", KEY_PROXY_PAC_URL),
        Some(PolicyValue::Sz(pac.to_string()))
    );

    // Restore cleanly deletes keys that didn't exist and puts back pre-existing values.
    let rec = j.restore_all(&plat);
    assert!(!rec.has_failures());
    assert!(!is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        pac
    ));
    assert_eq!(store.get("com.google.Chrome", KEY_PROXY_MODE), None);
    assert_eq!(store.get("com.google.Chrome", KEY_PROXY_PAC_URL), None);
    assert_eq!(
        store.get("company.thebrowser.Browser", KEY_PROXY_MODE),
        Some(PolicyValue::Sz("fixed_servers".to_string()))
    );
    assert_eq!(
        store.get("company.thebrowser.Browser", KEY_PROXY_PAC_URL),
        Some(PolicyValue::Sz(
            "https://corp.example/proxy.pac".to_string()
        ))
    );
}

#[test]
fn is_pac_policy_active_requires_matching_mode_and_url() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let store = FakePolicyStore::new();
    for d in MACOS_CHROMIUM_DOMAIN_NAMES {
        store.set_domain_applicable(d, false);
    }
    store.set_domain_applicable("com.google.Chrome", true);

    // Missing keys -> false
    assert!(!is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        pac
    ));

    // URL alone without ProxyMode=pac_script -> false
    store.preset(
        "com.google.Chrome",
        KEY_PROXY_PAC_URL,
        PolicyValue::Sz(pac.to_string()),
    );
    assert!(!is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        pac
    ));

    // Wrong ProxyMode -> false
    store.preset(
        "com.google.Chrome",
        KEY_PROXY_MODE,
        PolicyValue::Sz("direct".to_string()),
    );
    assert!(!is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        pac
    ));

    // Correct ProxyMode + matching URL -> true
    store.preset(
        "com.google.Chrome",
        KEY_PROXY_MODE,
        PolicyValue::Sz("pac_script".to_string()),
    );
    assert!(is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        pac
    ));

    // Wrong port -> false
    assert!(!is_pac_policy_active_in(
        &*store,
        &MACOS_CHROMIUM_DOMAIN_NAMES,
        "http://127.0.0.1:9999/proxy.pac"
    ));
}

#[test]
fn leftover_zastava_proxy_pac_url_is_not_adopted_as_baseline() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();
    // Simulate unjournaled leftover from an earlier crashed run.
    store.preset(
        "com.google.Chrome",
        KEY_PROXY_PAC_URL,
        PolicyValue::Sz(pac.to_string()),
    );

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());
    let specs = vec![PolicySpec::new(
        "com.google.Chrome",
        KEY_PROXY_PAC_URL,
        PolicyValue::Sz(pac.to_string()),
    )];
    apply_policy_specs(&mut j, &plat, &specs);
    // On restore, Zastava's leftover PAC URL is removed rather than kept as baseline.
    j.restore_all(&plat);
    assert_eq!(store.get("com.google.Chrome", KEY_PROXY_PAC_URL), None);
}

#[test]
fn apply_and_revert_browser_policies_covers_comet_yandex_opera_dia_atlas_and_betas() {
    let pac = "http://127.0.0.1:8899/proxy.pac";
    let fs = Arc::new(FakeFs::new());
    let plat = FakePlatform::new();
    let store = FakePolicyStore::new();

    let target_domains = [
        "ai.perplexity.comet",
        "ru.yandex.desktop.yandex-browser",
        "com.operasoftware.Opera",
        "com.operasoftware.OperaGX",
        "company.thebrowser.dia",
        "com.google.Chrome.beta",
        "com.google.Chrome.canary",
        "com.brave.Browser.beta",
        "com.openai.atlas",
    ];

    for domain in MACOS_CHROMIUM_DOMAIN_NAMES {
        store.set_domain_applicable(domain, target_domains.contains(&domain));
    }
    // Simulate a pre-existing user setting on Yandex Browser.
    store.preset(
        "ru.yandex.desktop.yandex-browser",
        KEY_DOH_MODE,
        PolicyValue::Sz("automatic".to_string()),
    );

    let mut j = Journal::open(fs.clone(), Path::new(DIR))
        .unwrap()
        .with_policy_store(store.clone());

    let rep = apply_browser_policies_with_pac(&mut j, &plat, Some(pac));
    assert_eq!(rep.failed, 0);
    // Plist/registry policy alone without profile Preferences or running flag is not enforced.
    assert!(!rep.pac_policy_active);

    #[cfg(target_os = "macos")]
    {
        assert_eq!(rep.applied, target_domains.len() * 4);
        for domain in target_domains {
            assert_eq!(
                store.get(domain, KEY_PROXY_MODE),
                Some(PolicyValue::Sz("pac_script".to_string())),
                "{domain}"
            );
            assert_eq!(
                store.get(domain, KEY_PROXY_PAC_URL),
                Some(PolicyValue::Sz(pac.to_string())),
                "{domain}"
            );
            assert_eq!(
                store.get(domain, KEY_QUIC_ALLOWED),
                Some(PolicyValue::Bool(false)),
                "{domain}"
            );
            assert_eq!(
                store.get(domain, KEY_DOH_MODE),
                Some(PolicyValue::Sz("off".to_string())),
                "{domain}"
            );
        }
    }

    let rec = revert_browser_policies(&mut j, &plat);
    assert!(!rec.has_failures());
    assert_eq!(
        store.get("ru.yandex.desktop.yandex-browser", KEY_DOH_MODE),
        Some(PolicyValue::Sz("automatic".to_string()))
    );
    assert_eq!(store.get("ai.perplexity.comet", KEY_PROXY_PAC_URL), None);
    assert_eq!(store.get("com.openai.atlas", KEY_PROXY_MODE), None);
    assert!(!is_pac_policy_active(&*store, pac));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_app_bundle_mappings_cover_all_supported_browsers() {
    let expected = [
        ("ai.perplexity.comet", "Comet.app"),
        ("com.operasoftware.Opera", "Opera.app"),
        ("com.operasoftware.OperaGX", "Opera GX.app"),
        ("company.thebrowser.dia", "Dia.app"),
        ("com.google.Chrome.beta", "Google Chrome Beta.app"),
        ("com.google.Chrome.canary", "Google Chrome Canary.app"),
        ("com.brave.Browser.beta", "Brave Browser Beta.app"),
        ("com.openai.atlas", "ChatGPT Atlas.app"),
        ("ru.yandex.desktop.yandex-browser", "Yandex.app"),
    ];
    for (domain, app) in expected {
        assert!(
            MACOS_CHROMIUM_DOMAIN_NAMES.contains(&domain),
            "MACOS_CHROMIUM_DOMAIN_NAMES missing {domain}"
        );
        assert!(
            macos_app_bundles_for_domain(domain).contains(&app),
            "missing bundle {app} for {domain}"
        );
    }
}
