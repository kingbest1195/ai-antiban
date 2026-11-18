use super::*;

#[test]
fn service_key_is_device_and_port_not_the_display_name() {
    let a = ServiceId::new("en0", "Wi-Fi", "Wi-Fi");
    let renamed = ServiceId::new("en0", "Wi-Fi", "Беспроводная сеть");
    assert_eq!(a, renamed);
    assert_eq!(a.key(), "dev:en0/Wi-Fi");
    let vpn = ServiceId::new("", "com.vpn", "My VPN");
    assert_eq!(vpn.key(), "svc:com.vpn/My VPN");
}

#[test]
fn debug_output_never_contains_values() {
    let secret = "http://user:hunter2@10.0.0.1:3128/proxy.pac";
    let pac = PacState {
        url: Some(secret.into()),
        enabled: Some(true),
    };
    let ep = ProxyEndpoint {
        enabled: Some(true),
        server: Some("hunter2.example".into()),
        port: Some(1),
        authenticated: None,
    };
    let reg = RegValue::sz(secret);
    let all = format!(
        "{pac:?} {ep:?} {reg:?} {:?}",
        ChainState {
            http: ep.clone(),
            https: ep.clone()
        }
    );
    assert!(!all.contains("hunter2"), "{all}");
}

#[test]
fn autoproxy_distinguishes_null_empty_and_value() {
    assert_eq!(
        parse_autoproxy("URL: (null)\nEnabled: No\n"),
        PacState {
            url: None,
            enabled: Some(false)
        }
    );
    assert_eq!(
        parse_autoproxy("URL: http://x/p.pac\nEnabled: Yes\n")
            .url
            .as_deref(),
        Some("http://x/p.pac")
    );
    assert_eq!(parse_autoproxy("").enabled, None);
}

#[test]
fn webproxy_absent_empty_and_zero_are_different() {
    let absent = parse_webproxy("");
    assert_eq!(absent, ProxyEndpoint::default());
    let empty = parse_webproxy("Enabled: No\nServer: \nPort: 0\n");
    assert_eq!(empty.server, Some(String::new()));
    assert_eq!(empty.port, Some(0));
    assert_ne!(absent, empty);
}

#[test]
fn service_order_parses_device_port_and_disabled_flag() {
    let text = "An asterisk (*) denotes that a network service is disabled.\n\
        (1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n\
        (*) USB 10/100 LAN\n(Hardware Port: USB 10/100 LAN, Device: en5)\n\n\
        (2) My VPN\n(Hardware Port: com.vpn, Device: )\n";
    let s = parse_service_order(text);
    assert_eq!(s.len(), 3);
    assert_eq!(s[0].key(), "dev:en0/Wi-Fi");
    assert!(s[0].enabled);
    assert!(!s[1].enabled);
    assert_eq!(s[2].key(), "svc:com.vpn/My VPN");
}

#[test]
fn reg_query_keeps_exact_type_and_absence() {
    let sz =
        "\r\nHKEY\\x\r\n    AutoConfigURL    REG_SZ    http://127.0.0.1:8899/proxy.pac\r\n";
    assert_eq!(
        parse_reg_query_value(sz, "AutoConfigURL"),
        Some(RegValue::sz("http://127.0.0.1:8899/proxy.pac"))
    );
    let empty = "    AutoConfigURL    REG_SZ    \n";
    assert_eq!(
        parse_reg_query_value(empty, "AutoConfigURL"),
        Some(RegValue::sz(""))
    );
    let dw = "    ProxyEnable    REG_DWORD    0x1\n";
    assert_eq!(
        parse_reg_query_value(dw, "ProxyEnable"),
        Some(RegValue::dword(1))
    );
    let ex = "    Path    REG_EXPAND_SZ    %USERPROFILE%\\bin\n";
    assert_eq!(
        parse_reg_query_value(ex, "Path").unwrap().kind,
        RegKind::ExpandSz
    );
    assert_eq!(
        parse_reg_query_value("ERROR: not found", "AutoConfigURL"),
        None
    );
    // A longer value name with the same prefix is not a match.
    assert_eq!(
        parse_reg_query_value("    AutoConfigURLX    REG_SZ    a\n", "AutoConfigURL"),
        None
    );
}

#[test]
fn webproxy_reports_the_authentication_flag() {
    let ep = parse_webproxy(
        "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\nAuthenticated Proxy Enabled: 1\n",
    );
    assert_eq!(ep.authenticated, Some(true));
    let ep = parse_webproxy(
        "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\nAuthenticated Proxy Enabled: 0\n",
    );
    assert_eq!(ep.authenticated, Some(false));
    assert_eq!(parse_webproxy("Enabled: No\n").authenticated, None);
}

#[test]
fn reg_query_names_lists_values_of_any_type_and_skips_key_lines() {
    let out = "\r\nHKEY_CURRENT_USER\\Environment\r\n    HTTPS_PROXY    REG_SZ    http://x\r\n    TEMP    REG_EXPAND_SZ    %X%\r\n    Flags    REG_DWORD    0x1\r\n";
    assert_eq!(
        parse_reg_query_names(out),
        vec!["HTTPS_PROXY", "TEMP", "Flags"]
    );
}

#[test]
fn scutil_dns_order_independent_and_unknown_fields_flagged() {
    let a = "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 8.8.8.8\n  }\n  SearchDomains : <array> {\n    0 : lan\n  }\n}\n";
    let b = "<dictionary> {\n  SearchDomains : <array> {\n    0 : lan\n  }\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 8.8.8.8\n  }\n}\n";
    let (da, db) = (parse_scutil_dns(a), parse_scutil_dns(b));
    assert_eq!(da, db);
    assert_eq!(da.servers, vec!["1.1.1.1", "8.8.8.8"]);
    let benign = "<dictionary> {\n  ConfirmedServiceID : 1234-ABCD\n  DomainName : vpn.internal\n  InterfaceName : utun4\n  SupplementalMatchDomains : <array> {\n    0 : corp\n  }\n  _Reserved : <dictionary> {\n    foo : bar\n  }\n}\n";
    assert!(!parse_scutil_dns(benign).unknown_fields);
    let unknown = "<dictionary> {\n  UnexpectedCustomDnsFlag : 1\n}\n";
    assert!(parse_scutil_dns(unknown).unknown_fields);
    assert!(parse_getdnsservers("There aren't any DNS Servers set on Wi-Fi.\n").is_empty());
    assert!(
        parse_getsearchdomains("There aren't any Search Domains set on Wi-Fi.\n").is_empty()
    );
}

#[test]
fn scutil_dns_amneziavpn_metadata_and_synthetic_services_do_not_trigger_temp_dns() {
    let amnezia_dns = parse_scutil_dns(
        "<dictionary> {\n  ConfirmedServiceID : E1A2-AMNEZIA\n  DomainName : amnezia.local\n  InterfaceName : utun4\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n  }\n  SupplementalMatchDomains : <array> {\n    0 : \n  }\n  __ORDER__ : 1\n}\n",
    );
    assert!(!amnezia_dns.unknown_fields);
    assert_eq!(amnezia_dns.servers, vec!["1.1.1.1"]);

    let wifi = svc("en0", "Wi-Fi");
    let entries = vec![
        // Synthetic / VPN Setup:/Network/Service/AmneziaWG/DNS not matching physical services.
        SetupDnsEntry {
            service_id: "E1A2-AMNEZIA".into(),
            user_defined_name: Some("AmneziaWG".into()),
            dns: amnezia_dns,
        },
        // Unmapped synthetic service with no UserDefinedName.
        SetupDnsEntry {
            service_id: "SYNTHETIC-TUN".into(),
            user_defined_name: None,
            dns: parse_scutil_dns("<dictionary> {\n  UnexpectedField : 1\n}\n"),
        },
        // Wi-Fi matches preferences.plist (192.168.1.1 + SearchDomains empty), plus benign keys.
        SetupDnsEntry {
            service_id: "WIFI-UUID".into(),
            user_defined_name: Some("Wi-Fi".into()),
            dns: parse_scutil_dns(
                "<dictionary> {\n  ConfirmedServiceID : WIFI-UUID\n  InterfaceName : en0\n  ServerAddresses : <array> {\n    0 : 192.168.1.1\n  }\n}\n",
            ),
        },
    ];
    let triggered =
        has_physical_temp_dns_override(std::slice::from_ref(&wifi), &entries, |name| {
            assert_eq!(name, "Wi-Fi");
            Ok((vec!["192.168.1.1".into()], Vec::new()))
        })
        .unwrap();
    assert!(
        !triggered,
        "AmneziaVPN / synthetic DNS entries must be ignored"
    );

    // Now simulate Wi-Fi having an ephemeral DNS server override differing from preferences.
    let mut override_entries = entries.clone();
    override_entries[2].dns.servers = vec!["9.9.9.9".into()];
    assert!(
        has_physical_temp_dns_override(std::slice::from_ref(&wifi), &override_entries, |_| Ok(
            (vec!["192.168.1.1".into()], Vec::new())
        ))
        .unwrap()
    );

    // And simulate Wi-Fi having an ephemeral SearchDomains override differing from preferences.
    let mut search_entries = entries;
    search_entries[2].dns.search_domains = vec!["corp.local".into()];
    assert!(
        has_physical_temp_dns_override(&[wifi], &search_entries, |_| Ok((
            vec!["192.168.1.1".into()],
            Vec::new()
        )))
        .unwrap()
    );
}

#[test]
fn inactive_secondary_physical_service_with_stale_setup_dns_is_ignored() {
    let active_ids = extract_active_service_ids(
        "  subKey [0] = State:/Network/Service/USB-LAN-UUID/IPv4\n  subKey [1] = State:/Network/Service/WIFI-UUID/IPv6\n  subKey [2] = State:/Network/Service/VPN-UUID/IPv4\n",
    );
    assert!(active_ids.contains("USB-LAN-UUID"));
    assert!(active_ids.contains("WIFI-UUID"));
    assert!(!active_ids.contains("P30T-UUID"));

    let usb_lan = svc("en7", "USB 10/100/1000 LAN");
    let p30t = svc("en9", "P30T");
    let wifi = svc("en0", "Wi-Fi");
    let physical = vec![usb_lan, p30t, wifi];

    // P30T (en9) has a stale Setup:/.../DNS with 2 servers while saved_servers=0,
    // but no live State:/Network/Service/P30T-UUID/IPv4|IPv6 -> ignored (Log 2 scenario).
    let stale_p30t_only = vec![SetupDnsEntry {
        service_id: "P30T-UUID".into(),
        user_defined_name: Some("P30T".into()),
        dns: parse_scutil_dns(
            "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 1.1.1.1\n    1 : 1.0.0.1\n  }\n}\n",
        ),
    }];
    assert!(
        !has_physical_temp_dns_override_active(
            &physical,
            &stale_p30t_only,
            &active_ids,
            |_| { Ok((Vec::new(), Vec::new())) }
        )
        .unwrap()
    );

    // When an active interface (Wi-Fi) holds temporary DNS differing from saved DHCP (0),
    // it still triggers temp_dns (Log 1 scenario).
    let mut with_active_wifi = stale_p30t_only;
    with_active_wifi.push(SetupDnsEntry {
        service_id: "WIFI-UUID".into(),
        user_defined_name: Some("Wi-Fi".into()),
        dns: parse_scutil_dns(
            "<dictionary> {\n  ServerAddresses : <array> {\n    0 : 10.0.0.1\n  }\n}\n",
        ),
    });
    assert!(
        has_physical_temp_dns_override_active(
            &physical,
            &with_active_wifi,
            &active_ids,
            |_| { Ok((Vec::new(), Vec::new())) }
        )
        .unwrap()
    );
}

#[test]
fn dry_run_gate_blocks_and_counts() {
    // Unit tests always run in OS dry-run mode.
    let before = crate::sysproxy::dry_run_blocked_calls();
    assert_eq!(dry_run_gate("probe"), Err(PlatformError::DryRun));
    assert_eq!(write_gate("probe"), Ok(false));
    assert!(crate::sysproxy::dry_run_blocked_calls() >= before + 2);
}

#[test]
fn fake_platform_counts_only_successful_writes() {
    let p = FakePlatform::new();
    p.set_user_env("A", "1").unwrap();
    p.fail_next(PlatOp::SetEnv);
    assert!(p.set_user_env("B", "2").is_err());
    assert_eq!(p.os_writes(), 1);
    assert_eq!(p.env_of("B"), None);
    assert_eq!(p.get_user_env("A").unwrap(), Some("1".into()));
    assert_eq!(p.os_writes(), 1);
    // The log names resources but carries no values.
    assert!(p.calls().iter().all(|c| !c.contains('=')));
}

#[test]
fn bypass_domains_parse_the_empty_list_quirk() {
    assert!(parse_bypass_domains("There aren't any bypass domains set on Wi-Fi.\n").is_empty());
    assert!(parse_bypass_domains("").is_empty());
    assert_eq!(
        parse_bypass_domains("*.local\n169.254/16\n\n  corp.example \n"),
        vec!["*.local", "169.254/16", "corp.example"]
    );
}

#[test]
fn fake_bypass_write_is_skipped_when_the_list_is_unchanged() {
    let p = FakePlatform::new();
    let svc = ServiceId::new("en0", "Wi-Fi", "Wi-Fi");
    p.add_service(svc.clone());
    p.seed_bypass(&svc, &["a", "b"]);
    let same = vec!["a".to_string(), "b".to_string()];
    p.set_proxy_bypass_domains(&svc, &same).unwrap();
    assert_eq!(p.os_writes(), 0);
    p.set_proxy_bypass_domains(&svc, &[]).unwrap();
    assert_eq!(p.os_writes(), 1);
    assert!(p.get_proxy_bypass_domains(&svc).unwrap().is_empty());
}

// --- WP-26: registry reads through the API (pure part, any OS) ---------------------------

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn utf16_nul(s: &str) -> Vec<u8> {
    let mut b = utf16(s);
    b.extend([0, 0]);
    b
}

#[test]
fn registry_string_with_a_cyrillic_profile_path_survives_exactly() {
    let path = "file:///C:/Users/Иван/AppData/Local/zastava/proxy.pac";
    let got = reg_read_outcome(0, 1, &utf16_nul(path), "get_inet").unwrap();
    assert_eq!(got, Some(RegValue::sz(path)));
    // The same text, as the OEM-decoded `reg query` output would have damaged it.
    assert!(!got.unwrap().data.contains('\u{FFFD}'));
}

#[test]
fn registry_value_types_are_kept_and_unknown_ones_are_unsupported() {
    let ok = |kind: u32, data: &[u8]| reg_read_outcome(0, kind, data, "get_inet");
    assert_eq!(ok(1, &utf16_nul("a")).unwrap(), Some(RegValue::sz("a")));
    assert_eq!(
        ok(2, &utf16_nul("%USERPROFILE%\\x")).unwrap(),
        Some(RegValue::expand_sz("%USERPROFILE%\\x")),
        "REG_EXPAND_SZ stays unexpanded and keeps its type"
    );
    assert_eq!(
        ok(4, &1u32.to_le_bytes()).unwrap(),
        Some(RegValue::dword(1))
    );
    assert_eq!(
        ok(4, &0xdead_beefu32.to_le_bytes()).unwrap(),
        Some(RegValue::dword(0xdead_beef))
    );
    for (name, kind) in [
        ("REG_BINARY", 3u32),
        ("REG_DWORD_BIG_ENDIAN", 5),
        ("REG_LINK", 6),
        ("REG_MULTI_SZ", 7),
        ("REG_QWORD", 11),
        ("REG_NONE", 0),
    ] {
        assert_eq!(
            ok(kind, &[1, 2, 3, 4]),
            Err(PlatformError::Unsupported("get_inet")),
            "{name} must be Unsupported, never `no value`"
        );
    }
}

#[test]
fn a_failed_registry_read_is_an_error_and_only_not_found_means_absent() {
    let read = |status: u32| reg_read_outcome(status, 0, &[], "get_inet");
    assert_eq!(read(2).unwrap(), None, "ERROR_FILE_NOT_FOUND");
    assert_eq!(read(3).unwrap(), None, "ERROR_PATH_NOT_FOUND");
    for status in [5u32, 1450, 234, 1] {
        // ACCESS_DENIED, NO_SYSTEM_RESOURCES, MORE_DATA, INCORRECT_FUNCTION
        assert_eq!(
            read(status),
            Err(PlatformError::Failed("get_inet")),
            "status {status}"
        );
    }
}

#[test]
fn registry_strings_that_cannot_round_trip_are_refused_not_repaired() {
    // Unpaired surrogate, odd length, a DWORD of the wrong size.
    let lone = [0x00, 0xD8, 0x41, 0x00];
    assert_eq!(
        reg_read_outcome(0, 1, &lone, "get_user_env"),
        Err(PlatformError::Unsupported("get_user_env"))
    );
    assert_eq!(
        reg_read_outcome(0, 1, &[0x41, 0x00, 0x42], "get_user_env"),
        Err(PlatformError::Unsupported("get_user_env"))
    );
    assert_eq!(
        reg_read_outcome(0, 4, &[1, 0, 0], "get_user_env"),
        Err(PlatformError::Unsupported("get_user_env"))
    );
}

#[test]
fn an_empty_registry_string_is_a_value_and_differs_from_a_missing_one() {
    let empty = reg_read_outcome(0, 1, &utf16_nul(""), "get_inet").unwrap();
    assert_eq!(empty, Some(RegValue::sz("")));
    let no_terminator = reg_read_outcome(0, 1, &[], "get_inet").unwrap();
    assert_eq!(no_terminator, Some(RegValue::sz("")));
    assert_eq!(reg_read_outcome(2, 0, &[], "get_inet").unwrap(), None);
    // Extra trailing NULs of a stored value are dropped, inner text is kept.
    let two = [utf16("a"), vec![0, 0, 0, 0]].concat();
    assert_eq!(
        reg_read_outcome(0, 1, &two, "get_inet").unwrap(),
        Some(RegValue::sz("a"))
    );
}

#[test]
fn registry_debug_output_stays_redacted() {
    let v = reg_read_outcome(0, 1, &utf16_nul("secret-path"), "get_inet")
        .unwrap()
        .unwrap();
    assert!(!format!("{v:?}").contains("secret-path"));
}

// --- WP-28: service kind, connection list, effective proxy ------------------------------

/// The real shape of `scutil --nc list`, with invented names and identifiers.
const NC_LIST: &str = "Available network connection services in the current set (*=enabled):\n\
* (Disconnected)   11111111-AAAA-4BBB-8CCC-000000000001 VPN (com.example.Alpha) \"Alpha VPN\"   [VPN:com.example.Alpha]\n\
* (Connected)      11111111-AAAA-4BBB-8CCC-000000000002 VPN (com.example.Beta.Pro) \"Beta VPN Pro\"   [VPN:com.example.Beta.Pro]\n\
  (Connecting)     11111111-AAAA-4BBB-8CCC-000000000003 VPN (com.example.Gamma) \"Gamma\"   [VPN:com.example.Gamma]\n\
* (Disconnecting)  11111111-AAAA-4BBB-8CCC-000000000004 PPP --> en0 \"Office \\\"L2TP\\\"\"   [PPP:L2TP]\n\
\n";

#[test]
fn nc_list_reads_state_and_the_quoted_name() {
    let list = parse_nc_list(NC_LIST);
    let seen: Vec<(&str, bool)> = list
        .iter()
        .map(|c| (c.name.as_str(), c.connected))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("Alpha VPN", false),
            ("Beta VPN Pro", true),
            ("Gamma", true),
            ("Office \\\"L2TP\\\"", true),
        ],
        "only \"Disconnected\" is not connected; the header line is skipped"
    );
    assert!(parse_nc_list("").is_empty());
    assert!(parse_nc_list("No connection services are available.\n").is_empty());
}

fn svc(device: &str, name: &str) -> ServiceId {
    ServiceId::new(device, name, name)
}

#[test]
fn a_service_is_physical_vpn_or_unknown_by_the_connection_list_and_the_device() {
    let nc = parse_nc_list(NC_LIST);
    let kind = |s: &ServiceId, nc: Option<&[VpnConnection]>| classify_service(s, nc);
    // Listed: a VPN, whatever the device column says.
    assert_eq!(
        kind(&svc("", "Beta VPN Pro"), Some(&nc)),
        ServiceKind::Vpn { connected: true }
    );
    assert_eq!(
        kind(&svc("", "Alpha VPN"), Some(&nc)),
        ServiceKind::Vpn { connected: false }
    );
    assert_eq!(
        kind(&svc("utun4", "Gamma"), Some(&nc)),
        ServiceKind::Vpn { connected: true }
    );
    // Not listed, no device: still a VPN (state unknown, so connected).
    assert_eq!(
        kind(&svc("", "Mystery"), Some(&nc)),
        ServiceKind::Vpn { connected: true }
    );
    // Not listed, with a device: physical.
    assert_eq!(kind(&svc("en0", "Wi-Fi"), Some(&nc)), ServiceKind::Physical);
    assert_eq!(
        kind(&svc("bridge0", "Thunderbolt Bridge"), Some(&nc)),
        ServiceKind::Physical
    );
    // The list could not be read: a device alone does not vouch for a service.
    assert_eq!(kind(&svc("en0", "Wi-Fi"), None), ServiceKind::Unknown);
    assert_eq!(
        kind(&svc("", "Alpha VPN"), None),
        ServiceKind::Vpn { connected: true }
    );
    assert!(ServiceKind::Physical.is_physical());
    assert!(!ServiceKind::Unknown.is_physical());
    assert!(ServiceKind::Vpn { connected: false }.is_idle_vpn());
    assert!(!ServiceKind::Vpn { connected: true }.is_idle_vpn());
    assert!(!ServiceKind::Unknown.is_idle_vpn());
}

#[test]
fn service_kind_of_the_platform_follows_the_fake_connection_list() {
    let p = FakePlatform::new();
    let wifi = svc("en0", "Wi-Fi");
    p.add_service(wifi.clone());
    let vpn = p.add_vpn_service("Alpha VPN", true);
    assert_eq!(p.service_kind(&wifi), ServiceKind::Physical);
    assert_eq!(p.service_kind(&vpn), ServiceKind::Vpn { connected: true });
    p.set_vpn_connection("Alpha VPN", false);
    assert_eq!(p.service_kind(&vpn), ServiceKind::Vpn { connected: false });
    p.fail_next(PlatOp::VpnList);
    assert_eq!(p.service_kind(&wifi), ServiceKind::Unknown);
    assert_eq!(p.os_writes(), 0, "classification never writes");
}

#[test]
fn scutil_proxy_gives_the_pac_part_only() {
    let text = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  ExcludeSimpleHostnames : 1\n  FTPPassive : 1\n  ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://127.0.0.1:8899/proxy.pac\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      ProxyAutoConfigEnable : 0\n    }\n  }\n}\n";
    let e = parse_scutil_proxy(text);
    assert_eq!(
        e.pac_enabled,
        Some(true),
        "the scoped block does not override it"
    );
    assert_eq!(
        e.pac_url.as_deref(),
        Some("http://127.0.0.1:8899/proxy.pac")
    );
    let off = parse_scutil_proxy("<dictionary> {\n  ProxyAutoConfigEnable : 0\n}\n");
    assert_eq!(off.pac_enabled, Some(false));
    assert_eq!(off.pac_url, None);
    assert_eq!(parse_scutil_proxy("").pac_enabled, None);
    let shown = format!("{e:?}");
    assert!(!shown.contains("127.0.0.1"), "{shown}");
}

#[test]
fn virtual_tunnel_devices_are_classified_as_vpn_even_without_scutil_nc() {
    let nc = parse_nc_list(NC_LIST);
    for dev in ["utun0", "utun4", "tun0", "tap1", "ppp0", "ipsec0", "UTUN7"] {
        assert_eq!(
            classify_service(&svc(dev, "AmneziaVPN Tunnel"), Some(&nc)),
            ServiceKind::Vpn { connected: true },
            "{dev} with nc list"
        );
        assert_eq!(
            classify_service(&svc(dev, "AmneziaVPN Tunnel"), None),
            ServiceKind::Vpn { connected: true },
            "{dev} without nc list"
        );
    }
    assert!(!is_virtual_tunnel_device("en0"));
    assert!(!is_virtual_tunnel_device("bridge0"));
}

#[test]
fn admin_auth_error_detection_matches_macos_authorization_failures() {
    assert!(is_admin_auth_error(
        "",
        "Error: -60005 The user is not authorized."
    ));
    assert!(is_admin_auth_error(
        "",
        "This operation requires administrator privileges."
    ));
    assert!(is_admin_auth_error("", "errAuthorizationDenied"));
    assert!(is_admin_auth_error("Authorization failed.", ""));
    assert!(is_admin_auth_error("", "User is Not Authorized"));
    assert!(is_admin_auth_error(
        "",
        "Command requires admin privileges."
    ));
    assert!(is_admin_auth_error(
        "",
        "The networksetup tool requires at least admin privileges to change network settings."
    ));
    assert!(is_admin_auth_error(
        "",
        "AuthorizationCreate() failed: -60007"
    ));
    assert!(is_admin_auth_error(
        "",
        "An error occurred while authenticating."
    ));
    assert!(is_admin_auth_error("", "Operation not permitted"));
    assert!(is_admin_auth_error(
        "",
        "Error: -60031 errAuthorizationInternal"
    ));
    assert!(is_admin_auth_error("", "This tool must be run as root."));
    assert!(is_admin_auth_error(
        "",
        "Недостаточно прав администратора для изменения настроек."
    ));
    assert!(!is_admin_auth_error(
        "",
        "Wi-Fi is not a recognized network service."
    ));
    assert!(!is_admin_auth_error(
        "",
        "Corp Authentication is not a recognized network service."
    ));
    assert!(
        PlatformError::AdminAuthRequired("set_pac")
            .to_string()
            .contains("admin")
    );
}
