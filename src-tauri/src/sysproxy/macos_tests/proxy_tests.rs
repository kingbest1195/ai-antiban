use super::*;
use crate::sysproxy::journal::Outcome;
use crate::sysproxy::platform::PlatOp;

#[test]
fn enable_records_the_baseline_and_restore_brings_it_back() {
    let (fs, p) = setup();
    p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(false)));
    let mut j = open(&fs);
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(r.configured, vec!["Wi-Fi".to_string()]);
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
    j.restore_all(&p);
    assert_eq!(
        p.pac_of(&wifi()),
        pac(Some("http://corp/p.pac"), Some(false))
    );
}

#[test]
fn services_are_independent_and_disabled_ones_are_not_captured() {
    let (fs, p) = setup();
    let mut off = usb();
    off.enabled = false;
    p.add_service(off.clone());
    p.seed_pac(&off, pac(Some("http://user/p.pac"), Some(true)));
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert!(
        j.entry(&Resource::Pac {
            service: off.clone()
        })
        .is_none()
    );
    assert_eq!(
        p.pac_of(&off),
        pac(Some("http://user/p.pac"), Some(true)),
        "a disabled service is left alone"
    );
    // One failing restore does not block the other service.
    p.add_service(usb());
    enable_pac(&mut j, &p, PAC).unwrap();
    p.fail_next(PlatOp::SetPac);
    let rep = j.restore_all(&p);
    assert_eq!(rep.failed(), 1);
    assert_eq!(rep.restored(), 1);
}

#[test]
fn repeated_enable_keeps_baseline_and_writes_nothing() {
    let (fs, p) = setup();
    p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(true)));
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    let writes = p.os_writes();
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert!(!r.changed);
    assert_eq!(p.os_writes(), writes);
    assert_eq!(
        j.entry(&Resource::Pac { service: wifi() })
            .unwrap()
            .baseline,
        Value::Pac(pac(Some("http://corp/p.pac"), Some(true)))
    );
}

#[test]
fn own_pac_url_update_keeps_the_original_flag_and_survives_a_crash() {
    let (fs, p) = setup();
    p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(false)));
    {
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        // The gateway moved to another port; the update's OS write is lost to a crash.
        p.fail_next(PlatOp::SetPac);
        let _ = enable_pac(&mut j, &p, "http://127.0.0.1:9100/proxy.pac");
    }
    recover(&fs, &p);
    assert_eq!(
        p.pac_of(&wifi()),
        pac(Some("http://corp/p.pac"), Some(false))
    );
}

#[test]
fn a_foreign_pac_after_us_is_adopted_as_baseline_and_not_rolled_back_later() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    // A VPN client replaces the PAC after us; the self-heal puts ours back on top.
    p.seed_pac(&wifi(), pac(Some("http://vpn/p.pac"), Some(true)));
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert!(r.changed);
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
    // Then the user changes it again by hand: the restore leaves that alone.
    p.seed_pac(&wifi(), pac(Some("http://mine/p.pac"), Some(true)));
    let rep = j.restore_all(&p);
    assert_eq!(rep.external(), 1);
    assert_eq!(
        p.pac_of(&wifi()),
        pac(Some("http://mine/p.pac"), Some(true))
    );
}

#[test]
fn foreign_pac_flag_is_not_switched_off_when_only_the_url_changed() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    // Somebody else keeps the flag on but points it at their own URL.
    p.seed_pac(&wifi(), pac(Some("http://theirs/p.pac"), Some(true)));
    let rep = j.restore_all(&p);
    assert_eq!(rep.external(), 1);
    assert_eq!(p.pac_of(&wifi()).enabled, Some(true));
}

#[test]
fn absent_key_empty_string_and_off_are_kept_apart() {
    let (fs, p) = setup();
    // Empty string with the flag key missing is different from "no URL at all".
    p.seed_pac(&wifi(), pac(Some(""), None));
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(
        j.entry(&Resource::Pac { service: wifi() })
            .unwrap()
            .baseline,
        Value::Pac(pac(Some(""), None))
    );
}

#[test]
fn new_service_between_enable_and_restore_is_not_touched_and_removed_one_is_skipped() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    // A service that appeared afterwards has no record, so the restore never touches it.
    p.add_service(usb());
    p.seed_pac(&usb(), pac(Some("http://other/p.pac"), Some(true)));
    // The enabled service disappears before the restore.
    p.remove_service(&wifi().key());
    let rep = j.restore_all(&p);
    assert_eq!(rep.count(|o| matches!(o, Outcome::TargetGone)), 1);
    assert_eq!(
        p.pac_of(&usb()),
        pac(Some("http://other/p.pac"), Some(true))
    );
    assert!(j.is_empty());
    // The self-heal picks the new service up.
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(r.configured, vec!["USB LAN".to_string()]);
}

#[test]
fn renamed_service_is_still_the_same_service() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    p.rename_service(&wifi().key(), "Беспроводная сеть");
    let rep = j.restore_all(&p);
    assert_eq!(rep.restored(), 1);
}

#[test]
fn temporary_vpn_dns_gracefully_skips_os_pac_writes_and_reports_deferred() {
    let (fs, p) = setup();
    let happ = p.add_vpn_service("Happ Plus", true);
    p.set_temp_dns(true);
    p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(true)));
    let mut j = open(&fs);
    let report = enable_pac(&mut j, &p, PAC).unwrap();
    assert!(report.os_pac_deferred);
    assert!(report.configured.is_empty());
    assert!(!report.changed);
    assert_eq!(report.skipped_vpn, vec!["Happ Plus".to_string()]);
    assert_eq!(p.os_writes(), 0);
    assert!(!touched(&p, &happ));
    assert!(j.is_empty(), "no OS PAC intent recorded when deferred");

    // Privileged enable also returns Ok with os_pac_deferred and triggers no admin prompt.
    let mut exec_count = 0usize;
    let priv_report = enable_pac_privileged_with(&mut j, &p, PAC, |_| {
        exec_count += 1;
        Ok(())
    })
    .unwrap();
    assert!(priv_report.os_pac_deferred);
    assert_eq!(
        exec_count, 0,
        "no osascript prompt when temp_dns defers OS PAC"
    );
    assert_eq!(p.os_writes(), 0);
}

#[test]
fn unknown_dns_state_also_gracefully_skips_os_pac_writes() {
    let (fs, p) = setup();
    p.fail_next(PlatOp::TempDns);
    let mut j = open(&fs);
    let report = enable_pac(&mut j, &p, PAC).unwrap();
    assert!(report.os_pac_deferred);
    assert!(report.configured.is_empty());
    assert!(!report.changed);
    assert_eq!(p.os_writes(), 0);
    assert!(j.is_empty());
}

#[test]
fn third_party_explicit_proxy_is_chained_and_returned_after_a_crash() {
    let (fs, p) = setup();
    let both = ChainState {
        http: ep(true, "127.0.0.1", 2080),
        https: ep(true, "127.0.0.1", 2080),
    };
    p.seed_chain(&wifi(), both.clone());
    {
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        let now = p.chain_of(&wifi());
        assert_eq!(now.http.enabled, Some(false));
        assert_eq!(now.https.enabled, Some(false));
        assert_eq!(now.http.server.as_deref(), Some("127.0.0.1"));
        // "kill -9": the journal object is gone, only the file is left.
    }
    recover(&fs, &p);
    assert_eq!(p.chain_of(&wifi()), both);
    assert_eq!(p.pac_of(&wifi()).url, None);
}

#[test]
fn different_http_and_https_upstreams_are_refused_before_any_write() {
    let (fs, p) = setup();
    p.seed_chain(
        &wifi(),
        ChainState {
            http: ep(true, "10.0.0.1", 1080),
            https: ep(true, "10.0.0.2", 2080),
        },
    );
    let mut j = open(&fs);
    let err = enable_pac(&mut j, &p, PAC).unwrap_err();
    assert!(err.contains("Wi-Fi") && !err.contains("10.0.0."));
    assert_eq!(p.os_writes(), 0);
    assert!(j.is_empty());
}

#[test]
fn upstream_with_authentication_is_refused() {
    let (fs, p) = setup();
    let mut web = ep(true, "10.0.0.1", 1080);
    web.authenticated = Some(true);
    p.seed_chain(
        &wifi(),
        ChainState {
            http: web,
            https: ProxyEndpoint::default(),
        },
    );
    let mut j = open(&fs);
    assert!(enable_pac(&mut j, &p, PAC).is_err());
    assert_eq!(p.os_writes(), 0);
}

#[test]
fn only_the_active_endpoint_is_switched_off_and_the_other_stays_as_it_was() {
    let (fs, p) = setup();
    let https_off = ep(false, "old.example", 8443);
    p.seed_chain(
        &wifi(),
        ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: https_off.clone(),
        },
    );
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    let now = p.chain_of(&wifi());
    assert_eq!(now.http.enabled, Some(false));
    assert_eq!(
        now.https, https_off,
        "the HTTPS side is not flattened or rewritten"
    );
}

#[test]
fn explicit_proxy_pointing_at_our_own_gateway_is_not_a_third_party() {
    let (fs, p) = setup();
    let ours = ChainState {
        http: ep(true, "127.0.0.1", 8899),
        https: ep(true, "127.0.0.1", 8899),
    };
    p.seed_chain(&wifi(), ours.clone());
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(p.chain_of(&wifi()), ours);
    assert!(j.entry(&Resource::Chain { service: wifi() }).is_none());
}

#[test]
fn different_upstreams_on_different_services_are_refused() {
    let (fs, p) = setup();
    p.add_service(usb());
    p.seed_chain(
        &wifi(),
        ChainState {
            http: ep(true, "10.0.0.1", 1080),
            https: ProxyEndpoint::default(),
        },
    );
    p.seed_chain(
        &usb(),
        ChainState {
            http: ep(true, "10.0.0.9", 1080),
            https: ProxyEndpoint::default(),
        },
    );
    let mut j = open(&fs);
    assert_eq!(
        enable_pac(&mut j, &p, PAC).unwrap_err(),
        MSG_INCOMPATIBLE_ACROSS
    );
    assert_eq!(p.os_writes(), 0);
}

#[test]
fn throne_enabling_its_proxy_after_us_is_chained_by_the_self_heal() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    let throne = ChainState {
        http: ep(true, "127.0.0.1", 2080),
        https: ep(true, "127.0.0.1", 2080),
    };
    p.seed_chain(&wifi(), throne.clone());
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert!(r.changed);
    assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
    j.restore_all(&p);
    assert_eq!(
        p.chain_of(&wifi()),
        throne,
        "their proxy comes back, not ours"
    );
}

#[test]
fn a_failing_service_does_not_block_the_others_and_keeps_its_explicit_proxy() {
    let (fs, p) = setup();
    p.add_service(usb());
    p.fail_next(PlatOp::SetPac);
    let mut j = open(&fs);
    let r = enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(r.configured, vec!["USB LAN".to_string()]);
}

// --- WP-23: PAC off clears the URL; explicit proxy returns per service, with bypass -------

#[test]
fn switching_the_pac_off_also_clears_our_url() {
    let (fs, p) = setup();
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(p.pac_of(&wifi()), pac(Some(PAC), Some(true)));
    j.restore_all(&p);
    assert_eq!(p.pac_of(&wifi()), pac(None, Some(false)));
}

#[test]
fn a_foreign_pac_url_and_its_state_come_back_as_they_were() {
    for on in [true, false] {
        let (fs, p) = setup();
        p.seed_pac(&wifi(), pac(Some("http://corp/p.pac"), Some(on)));
        let mut j = open(&fs);
        enable_pac(&mut j, &p, PAC).unwrap();
        j.restore_all(&p);
        assert_eq!(p.pac_of(&wifi()), pac(Some("http://corp/p.pac"), Some(on)));
    }
}

#[test]
fn the_explicit_proxy_returns_on_its_own_service_with_the_original_bypass_list() {
    let (fs, p) = setup();
    p.add_service(usb());
    let mut quiet = usb();
    quiet.enabled = true;
    // Wi-Fi: a third-party web proxy (enabled) with its own bypass list.
    let both = ChainState {
        http: ep(true, "127.0.0.1", 2080),
        https: ep(true, "127.0.0.1", 2080),
    };
    p.seed_chain(&wifi(), both.clone());
    p.seed_bypass(&wifi(), &["*.corp.example", "10.1.0.0/16"]);
    // USB: a proxy that is configured but off, and a bypass list the user has.
    let off = ChainState {
        http: ep(false, "old.example", 3128),
        https: ep(false, "old.example", 3128),
    };
    p.seed_chain(&usb(), off.clone());
    p.seed_bypass(&usb(), &["usb.local"]);
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
    assert_eq!(
        j.entry(&Resource::Bypass { service: wifi() })
            .unwrap()
            .baseline,
        Value::Bypass(vec!["*.corp.example".into(), "10.1.0.0/16".into()]),
        "the baseline holds the bypass list"
    );
    assert!(
        j.entry(&Resource::Bypass { service: usb() }).is_none()
            && j.entry(&Resource::Chain { service: usb() }).is_none(),
        "the service whose proxy was off is not recorded"
    );
    p.clear_calls();
    j.restore_all(&p);
    assert_eq!(p.chain_of(&wifi()), both);
    assert_eq!(p.bypass_of(&wifi()), vec!["*.corp.example", "10.1.0.0/16"]);
    assert_eq!(p.chain_of(&usb()), off);
    assert_eq!(p.bypass_of(&usb()), vec!["usb.local"]);
    assert!(
        !p.calls()
            .iter()
            .any(|c| c.contains("set_chain") && c.contains("en5")),
        "no chain write on USB: {:?}",
        p.calls()
    );
    assert!(
        !p.calls()
            .iter()
            .any(|c| c.starts_with("set_proxy_bypass_domains:dev:en5"))
    );
}

#[test]
fn a_service_zastava_did_not_touch_gets_no_call_at_all() {
    let (fs, p) = setup();
    let mut off_svc = usb();
    off_svc.enabled = false;
    p.add_service(off_svc.clone());
    p.seed_chain(
        &off_svc,
        ChainState {
            http: ep(true, "192.168.1.5", 3128),
            https: ep(true, "192.168.1.5", 3128),
        },
    );
    p.seed_bypass(&off_svc, &["x.local"]);
    p.seed_pac(&off_svc, pac(Some("http://user/p.pac"), Some(true)));
    p.seed_chain(
        &wifi(),
        ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        },
    );
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    j.restore_all(&p);
    let key = off_svc.key();
    assert!(
        !p.calls().iter().any(|c| c.contains(&key)),
        "{:?}",
        p.calls()
    );
    assert_eq!(
        p.pac_of(&off_svc),
        pac(Some("http://user/p.pac"), Some(true))
    );
}

#[test]
fn a_bypass_list_the_user_changed_after_us_is_left_and_the_proxy_still_returns() {
    let (fs, p) = setup();
    let both = ChainState {
        http: ep(true, "127.0.0.1", 2080),
        https: ep(true, "127.0.0.1", 2080),
    };
    p.seed_chain(&wifi(), both.clone());
    p.seed_bypass(&wifi(), &["a.example"]);
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    p.seed_bypass(&wifi(), &["a.example", "b.example"]); // the user edits it meanwhile
    let rep = j.restore_all(&p);
    assert_eq!(
        rep.external(),
        1,
        "only the bypass list is a foreign change"
    );
    assert_eq!(p.bypass_of(&wifi()), vec!["a.example", "b.example"]);
    assert_eq!(p.chain_of(&wifi()), both);
}

#[test]
fn an_unreadable_bypass_list_does_not_stop_the_chain() {
    let (fs, p) = setup();
    p.seed_chain(
        &wifi(),
        ChainState {
            http: ep(true, "127.0.0.1", 2080),
            https: ep(true, "127.0.0.1", 2080),
        },
    );
    p.fail_next(PlatOp::GetBypass);
    let mut j = open(&fs);
    enable_pac(&mut j, &p, PAC).unwrap();
    assert_eq!(p.chain_of(&wifi()).http.enabled, Some(false));
    assert!(j.entry(&Resource::Bypass { service: wifi() }).is_none());
}
