use super::*;
use crate::sysproxy::fs::FakeFs;
use crate::sysproxy::journal::Journal;
use crate::sysproxy::platform::{FakePlatform, PlatOp};

// --- WP-28: VPN services are never written; no pointless writes; no ping-pong ------------

fn leftover() -> PacState {
    pac(Some(PAC), Some(true))
}

#[test]
fn a_connected_vpn_service_is_neither_read_nor_written() {
    let (fs, p) = setup();
    let vpn = p.add_vpn_service("Alpha VPN", true);
    p.seed_pac(&vpn, leftover());
    let mut j = open(&fs);
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(r.configured, vec!["Wi-Fi".to_string()]);
    assert_eq!(r.skipped_vpn, vec!["Alpha VPN".to_string()]);
    assert!(!touched(&p, &vpn), "calls: {:?}", p.calls());
    assert_eq!(p.pac_of(&vpn), leftover());
    assert!(j.entry(&Resource::Pac { service: vpn }).is_none());
    assert_eq!(
        vpn_untouched_line(&r.skipped_vpn),
        "VPN-службы не изменялись: Alpha VPN"
    );
}

#[test]
fn a_disconnected_vpn_service_gets_no_pac_either() {
    let (fs, p) = setup();
    let vpn = p.add_vpn_service("Alpha VPN", false);
    let mut j = open(&fs);
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert!(
        r.skipped_vpn.is_empty(),
        "only connected ones are announced"
    );
    assert!(!touched(&p, &vpn));
    assert_eq!(p.pac_of(&vpn), PacState::default());
}

#[test]
fn a_vpn_service_never_gets_the_chain_or_bypass_either() {
    let (fs, p) = setup();
    let vpn = p.add_vpn_service("Alpha VPN", true);
    let both = ChainState {
        http: ep(true, "127.0.0.1", 2080),
        https: ep(true, "127.0.0.1", 2080),
    };
    p.seed_chain(&vpn, both.clone());
    p.seed_bypass(&vpn, &["vpn.local"]);
    p.seed_chain(&wifi(), both);
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert!(!touched(&p, &vpn));
    assert_eq!(p.chain_of(&vpn).http.enabled, Some(true));
    assert_eq!(p.bypass_of(&vpn), vec!["vpn.local"]);
    assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
}

#[test]
fn with_only_vpn_services_nothing_is_written_and_the_user_is_told() {
    let p = FakePlatform::new();
    let vpn = p.add_vpn_service("Alpha VPN", true);
    let mut j = open(&FakeFs::new());
    let err = enable_pac(&mut j, &p, PAC).unwrap_err();
    assert_eq!(err, MSG_ONLY_VPN);
    assert_eq!(p.os_writes(), 0);
    assert!(!touched(&p, &vpn));
    assert!(!err.contains("://"));
}

#[test]
fn when_the_connection_list_is_unreadable_nothing_is_written() {
    let (fs, p) = setup();
    p.fail_next(PlatOp::VpnList);
    let mut j = open(&fs);
    // Wi-Fi has a device but cannot be vouched for: fail closed, say so.
    assert_eq!(enable_pac(&mut j, &p, PAC).unwrap_err(), MSG_KIND_UNKNOWN);
    assert_eq!(p.os_writes(), 0);
    assert!(j.is_empty());
}

#[test]
fn a_service_without_a_device_is_a_vpn_even_if_scutil_does_not_list_it() {
    let (fs, p) = setup();
    let odd = ServiceId::new("", "com.example.tunnel", "Odd Tunnel");
    p.add_service(odd.clone());
    let mut j = open(&fs);
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(r.configured, vec!["Wi-Fi".to_string()]);
    assert!(!touched(&p, &odd));
}

#[test]
fn repeated_self_heal_on_a_physical_service_writes_nothing() {
    let (fs, p) = setup();
    let vpn = p.add_vpn_service("Alpha VPN", true);
    let mut j = open(&fs);
    let guard = HealGuard::new();
    let t0 = Instant::now();
    refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
    let writes = p.os_writes();
    for i in 1..5 {
        let r = refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(5 * i)).unwrap();
        assert!(!r.changed);
    }
    assert_eq!(p.os_writes(), writes);
    assert!(!touched(&p, &vpn));
}

#[test]
fn a_vpn_client_that_keeps_rewriting_the_pac_does_not_start_a_ping_pong() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    let guard = HealGuard::new();
    let t0 = Instant::now();
    refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
    let mut healed = 0;
    for i in 1..=8u64 {
        // The VPN client puts its own PAC back, every pass.
        p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
        let before = p.os_writes();
        refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(5 * i)).unwrap();
        if p.os_writes() > before {
            healed += 1;
        }
    }
    assert_eq!(
        healed, HEAL_MAX_REWRITES,
        "healed three times, then stopped"
    );
    assert_eq!(
        p.pac_of(&wifi()),
        pac(Some("http://vpn.example/p.pac"), Some(true)),
        "the foreign value is left as it is"
    );
    // An explicit enable starts a fresh account.
    guard.reset();
    refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(60)).unwrap();
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
}

#[test]
fn rewrites_far_apart_are_not_a_ping_pong_and_a_new_network_resumes_the_heal() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    let guard = HealGuard::new();
    let t0 = Instant::now();
    refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
    // Rewrites a window apart: each one is healed, none ever suspends the service.
    for i in 1..=5u64 {
        p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
        refresh_pac(
            &mut j,
            &p,
            PAC,
            &guard,
            t0 + (HEAL_WINDOW + Duration::from_secs(1)) * i as u32,
        )
        .unwrap();
        assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)), "pass {i}");
    }
    // Now a burst suspends it ...
    let base = t0 + HEAL_WINDOW * 10;
    for i in 0..HEAL_MAX_REWRITES as u64 {
        p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
        refresh_pac(&mut j, &p, PAC, &guard, base + Duration::from_secs(i)).unwrap();
    }
    p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
    refresh_pac(&mut j, &p, PAC, &guard, base + Duration::from_secs(10)).unwrap();
    assert_eq!(
        p.pac_of(&wifi()).url.as_deref(),
        Some("http://vpn.example/p.pac")
    );
    // ... until the set of services changes (another network).
    p.add_service(usb());
    refresh_pac(&mut j, &p, PAC, &guard, base + Duration::from_secs(20)).unwrap();
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
}

#[test]
fn a_suspended_service_does_not_stop_the_healing_of_the_others() {
    let (fs, p) = setup();
    p.add_service(usb());
    let mut j = open(&fs);
    let guard = HealGuard::new();
    let t0 = Instant::now();
    refresh_pac(&mut j, &p, PAC, &guard, t0).unwrap();
    for i in 1..=4u64 {
        p.seed_pac(&wifi(), pac(Some("http://vpn.example/p.pac"), Some(true)));
        refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(i)).unwrap();
    }
    // USB loses its PAC for once: it is healed although Wi-Fi is given up on.
    p.seed_pac(&usb(), pac(None, Some(false)));
    refresh_pac(&mut j, &p, PAC, &guard, t0 + Duration::from_secs(10)).unwrap();
    assert_eq!(p.pac_of(&usb()), pac(Some(PAC), Some(true)));
    assert_eq!(
        p.pac_of(&wifi()).url.as_deref(),
        Some("http://vpn.example/p.pac")
    );
}

// --- first start after 2.0.0: no "off, then on" pair on one service ------------------------

fn start_like_the_app(fs: &FakeFs, p: &FakePlatform) -> Journal {
    let mut j = open(fs);
    crate::sysproxy::cleanup::restore_and_migrate_with(&mut j, p, true);
    enable_pac(&mut j, p, PAC).unwrap();
    j
}

#[test]
fn first_start_after_2_0_0_leaves_a_physical_service_with_our_pac_untouched() {
    let (fs, p) = setup();
    p.seed_pac(&wifi(), leftover()); // what 2.0.0 left
    let j = start_like_the_app(&fs, &p);
    assert_eq!(p.os_writes(), 0, "calls: {:?}", p.calls());
    assert_eq!(p.pac_of(&wifi()), leftover());
    // The state "before Zastava" is off: that is what the restore brings back.
    let mut j = j;
    j.restore_all(&p);
    assert_eq!(p.pac_of(&wifi()), pac(None, Some(false)));
}

#[test]
fn first_start_with_an_old_port_leftover_is_one_write_not_two() {
    let (fs, p) = setup();
    p.seed_pac(
        &wifi(),
        pac(Some("http://127.0.0.1:8900/proxy.pac"), Some(true)),
    );
    start_like_the_app(&fs, &p);
    assert_eq!(p.os_writes(), 1, "calls: {:?}", p.calls());
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
}

#[test]
fn the_cleanup_pass_without_the_start_flag_still_clears_a_physical_leftover() {
    let (fs, p) = setup();
    p.seed_pac(&wifi(), leftover());
    let mut j = open(&fs);
    crate::sysproxy::cleanup::restore_and_migrate_with(&mut j, &p, false);
    assert_eq!(p.pac_of(&wifi()), pac(None, Some(false)));
}

#[test]
fn a_physical_leftover_is_not_given_a_mark_until_the_enable_pass_has_taken_it() {
    let (fs, p) = setup();
    p.seed_pac(&wifi(), leftover());
    let mut j = open(&fs);
    crate::sysproxy::cleanup::restore_and_migrate_with(&mut j, &p, true);
    assert!(!j.has_mark(crate::sysproxy::cleanup::LEGACY_MIGRATION_MARK));
    enable_pac(&mut j, &p, PAC).unwrap();
    drop(j); // the journal is locked while it is open
    // Next start: the service is in the journal, nothing is deferred, the mark is set.
    let mut next = open(&fs);
    crate::sysproxy::cleanup::restore_and_migrate_with(&mut next, &p, true);
    assert!(next.has_mark(crate::sysproxy::cleanup::LEGACY_MIGRATION_MARK));
}

#[test]
fn the_owners_first_start_with_one_connected_vpn_among_six() {
    let (fs, p) = setup();
    let bridge = ServiceId::new("bridge0", "Thunderbolt Bridge", "Thunderbolt Bridge");
    let phone = ServiceId::new("en5", "iPhone USB", "iPhone USB");
    p.add_service(bridge.clone());
    p.add_service(phone.clone());
    let mut vpns = Vec::new();
    for (name, up) in [
        ("Alpha", false),
        ("Beta Proxy", false),
        ("Gamma", false),
        ("Delta Pro", true),
        ("Epsilon", false),
        ("Zeta", false),
    ] {
        vpns.push((p.add_vpn_service(name, up), up));
    }
    // 2.0.0 wrote its PAC into all nine services.
    for svc in [wifi(), bridge.clone(), phone.clone()] {
        p.seed_pac(&svc, leftover());
    }
    for (svc, _) in &vpns {
        p.seed_pac(svc, leftover());
    }
    start_like_the_app(&fs, &p);
    // Physical services: our PAC stays, no write. Connected VPN: not touched at all.
    for svc in [wifi(), bridge, phone] {
        assert_eq!(p.pac_of(&svc), leftover());
    }
    for (svc, up) in &vpns {
        if *up {
            assert!(!touched(&p, svc), "a connected VPN was touched");
            assert_eq!(p.pac_of(svc), leftover());
        } else {
            // The one-time cleanup of 2.0.0's leftover: one write, only while disconnected.
            assert_eq!(p.pac_of(svc), pac(None, Some(false)));
        }
    }
    assert_eq!(p.os_writes(), 5, "five idle VPN services, one clear each");
}

#[test]
fn admin_auth_required_error_surfaces_exact_prefix_without_writes() {
    let (fs, p) = setup();
    p.fail_next_auth(PlatOp::SetPac);
    let mut j = open(&fs);
    let err = enable_pac(&mut j, &p, PAC).unwrap_err();
    assert!(
        err.starts_with("ADMIN_AUTH_REQUIRED:"),
        "expected ADMIN_AUTH_REQUIRED: prefix, got {err}"
    );
    assert_eq!(p.os_writes(), 0);
    // Journal entry must not be left dangling Applied when auth failed.
    let pac_res = Resource::Pac { service: wifi() };
    assert!(j.entry(&pac_res).is_none());
}

#[test]
fn unlisted_utun_tunnel_is_skipped_while_wifi_is_configured() {
    let (fs, p) = setup();
    let amnezia = ServiceId::new("utun4", "AmneziaWG", "AmneziaWG");
    p.add_service(amnezia.clone());
    let mut j = open(&fs);
    let report = enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(report.configured, vec!["Wi-Fi"]);
    assert_eq!(report.skipped_vpn, vec!["AmneziaWG"]);
    assert!(!touched(&p, &amnezia));
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
}

#[test]
fn privileged_script_quotes_special_names_and_rejects_injections() {
    assert!(is_safe_pac_url(PAC));
    assert!(!is_safe_pac_url("ftp://127.0.0.1:8899/proxy.pac"));
    assert!(!is_safe_pac_url("http://127.0.0.1:8899/proxy.pac;id"));
    assert!(!is_safe_pac_url("http://127.0.0.1/$(whoami)"));

    let quoted = posix_single_quote("Bob's Wi-Fi; $(id)").unwrap();
    assert_eq!(quoted, "'Bob'\\''s Wi-Fi; $(id)'");
    assert!(posix_single_quote("bad\nname").is_err());

    let p = FakePlatform::new();
    let sneaky = ServiceId::new("en0", "Wi-Fi", "Bob's Wi-Fi \"1\"");
    p.add_service(sneaky.clone());
    let script = build_privileged_networksetup_script(
        &p,
        &[(
            Resource::Pac { service: sneaky },
            Value::Pac(pac(Some(PAC), Some(true))),
        )],
    )
    .unwrap();
    assert!(script.contains("'Bob'\\''s Wi-Fi \"1\"'"), "{script}");
    assert!(script.contains(&format!("'{PAC}'")), "{script}");
    let osa = build_osascript_arg(&script).unwrap();
    assert!(osa.starts_with("do shell script \""));
    assert!(osa.ends_with("\" with administrator privileges"));
    assert!(osa.contains("\\\"1\\\""), "{osa}");
}

#[test]
fn privileged_enable_batches_services_records_journal_and_rolls_back_on_cancel() {
    let (fs, p) = setup();
    let eth = ServiceId::new("en7", "USB 10/100/1000 LAN", "Ethernet");
    p.add_service(eth.clone());
    p.seed_chain(
        &wifi(),
        ChainState {
            http: ProxyEndpoint {
                enabled: Some(true),
                server: Some("127.0.0.1".into()),
                port: Some(10808),
                authenticated: Some(false),
            },
            https: ProxyEndpoint::default(),
        },
    );
    let mut j = open(&fs);
    // Cancelled UAC / AppleScript prompt must roll back cleanly.
    let err = enable_pac_privileged_with(&mut j, &p, PAC, |_| {
        Err(JournalError::Platform(PlatformError::AdminAuthRequired(
            "osascript",
        )))
    })
    .unwrap_err();
    assert!(err.starts_with("ADMIN_AUTH_REQUIRED:"));
    assert!(j.entry(&Resource::Pac { service: wifi() }).is_none());

    // Successful batch applies both physical services in a single prompt and commits journal.
    let mut exec_count = 0usize;
    let report = enable_pac_privileged_with(&mut j, &p, PAC, |script| {
        exec_count += 1;
        assert!(script.contains("-setautoproxyurl 'Wi-Fi'"));
        assert!(script.contains("-setautoproxyurl 'Ethernet'"));
        assert!(script.contains("-setwebproxystate 'Wi-Fi' off"));
        p.set_pac(&wifi(), &pac(Some(PAC), Some(true))).unwrap();
        p.set_pac(&eth, &pac(Some(PAC), Some(true))).unwrap();
        p.set_chain(
            &wifi(),
            &ChainState {
                http: ProxyEndpoint {
                    enabled: Some(false),
                    server: Some("127.0.0.1".into()),
                    port: Some(10808),
                    authenticated: Some(false),
                },
                https: ProxyEndpoint::default(),
            },
        )
        .unwrap();
        Ok(())
    })
    .unwrap();
    assert_eq!(exec_count, 1);
    assert_eq!(report.configured, vec!["Wi-Fi", "Ethernet"]);
    assert_eq!(
        j.entry(&Resource::Pac { service: wifi() }).unwrap().state,
        EntryState::Applied
    );
    assert_eq!(
        j.entry(&Resource::Pac { service: eth }).unwrap().state,
        EntryState::Applied
    );
    assert_eq!(
        j.entry(&Resource::Chain { service: wifi() }).unwrap().state,
        EntryState::Applied
    );
}

#[test]
fn vpn_disconnect_resets_heal_guard_so_physical_pac_heals_again() {
    let (fs, p) = setup();
    let _vpn = p.add_vpn_service("WireGuard", true);

    let mut j = open(&fs);
    let guard = HealGuard::new();
    let t0 = Instant::now();
    enable_pac(&mut j, &p, PAC).unwrap();

    // Simulate VPN rewriting Wi-Fi PAC repeatedly until HealGuard suspends Wi-Fi.
    for step in 0..HEAL_MAX_REWRITES {
        p.seed_pac(&wifi(), pac(None, Some(false)));
        let report = refresh_pac(
            &mut j,
            &p,
            PAC,
            &guard,
            t0 + Duration::from_secs(step as u64 + 1),
        )
        .unwrap();
        assert_eq!(report.skipped_vpn, vec!["WireGuard"]);
    }
    assert!(guard.is_suspended(&wifi().key()));

    // While the same VPN stays connected, Wi-Fi stays suspended (no ping-pong).
    p.seed_pac(&wifi(), pac(None, Some(false)));
    let rep = refresh_pac(
        &mut j,
        &p,
        PAC,
        &guard,
        t0 + Duration::from_secs(HEAL_MAX_REWRITES as u64 + 5),
    )
    .unwrap();
    assert!(rep.configured.is_empty());

    // Once the VPN disconnects, fingerprint changes and Wi-Fi PAC heals immediately.
    p.set_vpn_connection("WireGuard", false);
    let rep = refresh_pac(
        &mut j,
        &p,
        PAC,
        &guard,
        t0 + Duration::from_secs(HEAL_MAX_REWRITES as u64 + 10),
    )
    .unwrap();
    assert!(!guard.is_suspended(&wifi().key()));
    assert_eq!(rep.configured, vec!["Wi-Fi"]);
    assert_eq!(p.pac_of(&wifi()).url.as_deref(), Some(PAC));
}

#[test]
fn partial_admin_auth_required_rolls_back_and_returns_prefix() {
    // Secondary service already has our PAC (Unchanged), primary Wi-Fi fails SetPac with
    // AdminAuthRequired -> must roll back & return Err(MSG_ADMIN_AUTH_REQUIRED), never Ok.
    let (fs, p) = setup();
    let usb_svc = usb();
    p.add_service(usb_svc.clone());
    p.seed_pac(&usb_svc, pac(Some(PAC), Some(true)));
    p.seed_pac(&wifi(), pac(None, Some(false)));
    p.fail_next_auth(PlatOp::SetPac);
    let mut j = open(&fs);

    let err = enable_pac(&mut j, &p, PAC).unwrap_err();
    assert!(
        err.starts_with("ADMIN_AUTH_REQUIRED:"),
        "expected ADMIN_AUTH_REQUIRED: prefix, got {err}"
    );
    assert!(
        j.is_empty(),
        "partial journal entries must be rolled back: {:?}",
        j.entries()
    );

    // Also test reverse order: USB succeeds with a write, then Wi-Fi fails with AdminAuthRequired.
    let (fs2, p2) = setup();
    let p2_first_wifi = wifi();
    p2.seed_pac(&p2_first_wifi, pac(None, Some(false)));
    p2.add_service(usb());
    p2.seed_pac(&usb(), pac(None, Some(false)));
    // First SetPac succeeds (Wi-Fi), second fails with AdminAuthRequired (USB LAN).
    p2.remove_service(&p2_first_wifi.key());
    p2.add_service(p2_first_wifi.clone());
    // Now order is: usb(), wifi(). Fail the 2nd SetPac? fail_next_auth fails the NEXT call, so
    // put wifi second by making usb succeed and failing wifi on SetChain via explicit proxy.
    p2.seed_chain(
        &usb(),
        ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ProxyEndpoint::default(),
        },
    );
    let mut j2 = open(&fs2);
    // Fail SetChain (2nd write after USB SetPac succeeds) -> must roll back USB PAC too.
    p2.fail_next_auth(PlatOp::SetChain);
    let err2 = enable_pac(&mut j2, &p2, PAC).unwrap_err();
    assert!(err2.starts_with("ADMIN_AUTH_REQUIRED:"), "{err2}");
    assert_eq!(p2.pac_of(&usb()), pac(None, Some(false)));
    assert!(j2.is_empty(), "journal must be rolled back: {:?}", j2.entries());
}
