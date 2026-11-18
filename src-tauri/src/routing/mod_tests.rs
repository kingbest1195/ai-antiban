use super::*;

fn route(id: &str) -> Route {
    Route {
        id: id.to_string(),
        label: id.to_string(),
        country: Some("NL".into()),
        exit_ip: Some("185.10.10.1".into()),
        expires_at: None,
        entries: vec![Entry {
            proto: EntryProto::Socks5,
            host: "185.10.10.2".into(),
            port: 1080,
            username: Some("alice".into()),
            password: Some("s3cret".into()),
            sni: None,
        }],
        raw_key: "socks5://alice:s3cret@185.10.10.2:1080".into(),
        enabled: true,
        added_at: 1,
    }
}

#[test]
fn test_selection_priority_profile_provider_default() {
    let mut d = AppStateData {
        routes: vec![route("a"), route("b"), route("c")],
        ..Default::default()
    };
    assert_eq!(select_route(&d, "openai"), RouteSelection::Direct);

    d.default_route_id = Some("a".into());
    assert_eq!(select_route_id(&d, "openai").as_deref(), Some("a"));

    d.provider_routes.insert("anthropic".into(), "b".into());
    assert_eq!(select_route_id(&d, "anthropic").as_deref(), Some("b"));
    assert_eq!(select_route_id(&d, "gemini").as_deref(), Some("a"));

    d.profile_route_id = Some("c".into());
    assert_eq!(select_route_id(&d, "anthropic").as_deref(), Some("c"));
    // Profile override is Claude-only.
    assert_eq!(select_route_id(&d, "openai").as_deref(), Some("a"));

    d.provider_routes.insert("gemini".into(), "zzz".into());
    assert_eq!(
        select_route(&d, "gemini"),
        RouteSelection::Missing("zzz".into())
    );
}

#[test]
fn test_status_and_usability() {
    let mut r = route("a");
    let now = 1_000;
    assert_eq!(compute_status(&r, None, now), RouteStatus::Active);
    assert!(r.check_usable(now).is_ok());

    let h = RouteHealthRegistry::default();
    assert_eq!(
        h.record_exit("a", "185.10.10.9", "NL", r.exit_ip.as_deref()),
        Some(false)
    );
    assert_eq!(
        compute_status(&r, h.get("a").as_ref(), now),
        RouteStatus::ExitIpMismatch
    );
    h.mark_unreachable("a", "refused");
    assert_eq!(
        compute_status(&r, h.get("a").as_ref(), now),
        RouteStatus::Unreachable
    );

    r.expires_at = Some(now);
    assert_eq!(compute_status(&r, None, now), RouteStatus::Expired);
    assert_eq!(r.check_usable(now), Err(RouteDownReason::Expired));
    r.enabled = false;
    assert_eq!(compute_status(&r, None, now), RouteStatus::Disabled);
    assert_eq!(r.check_usable(now), Err(RouteDownReason::Disabled));
}

#[test]
fn test_view_and_debug_hide_secrets() {
    let d = AppStateData {
        routes: vec![route("a")],
        ..Default::default()
    };
    let snap = snapshot(&d, &RouteHealthRegistry::default(), 1);
    let json = serde_json::to_string(&snap).unwrap();
    assert!(!json.contains("s3cret"));
    assert!(!json.contains("alice"));
    assert!(!json.contains("raw_key"));
    assert!(json.contains("\"status\":\"active\""));
    let dbg = format!("{:?}", d.routes[0]);
    assert!(!dbg.contains("s3cret"));
}

#[test]
fn test_route_id_stable() {
    let a = route_id_for_raw_key("socks5://u:p@1.2.3.4:1080");
    assert_eq!(a, route_id_for_raw_key("  socks5://u:p@1.2.3.4:1080 "));
    assert_eq!(a.len(), 26);
    assert_ne!(a, route_id_for_raw_key("socks5://u:p@1.2.3.4:1081"));
}

#[test]
fn test_profile_route_does_not_leak_to_other_providers() {
    let mut d = AppStateData {
        routes: vec![route("p1"), route("oa")],
        profile_route_id: Some("p1".into()),
        ..Default::default()
    };
    // `default_route_id` is None: Claude uses the profile route, while OpenAI and Gemini
    // stay Direct unless explicitly bound via `provider_routes` or `default_route_id`.
    assert_eq!(select_route_id(&d, "anthropic").as_deref(), Some("p1"));
    assert_eq!(select_route_id(&d, "openai"), None);
    assert_eq!(select_route_id(&d, "gemini"), None);
    assert_eq!(select_route(&d, "openai"), RouteSelection::Direct);
    assert_eq!(select_route(&d, "gemini"), RouteSelection::Direct);

    // Even when profile route is invalid, other providers are unaffected.
    d.profile_route_invalid = Some("bad key".into());
    assert_eq!(
        select_route(&d, "anthropic"),
        RouteSelection::Invalid("bad key".into())
    );
    assert_eq!(select_route(&d, "openai"), RouteSelection::Direct);
    assert_eq!(select_route(&d, "gemini"), RouteSelection::Direct);

    // Explicit provider route or default route still works for OpenAI/Gemini.
    d.profile_route_invalid = None;
    d.provider_routes.insert("openai".into(), "oa".into());
    assert_eq!(select_route_id(&d, "openai").as_deref(), Some("oa"));
    assert_eq!(select_route_id(&d, "gemini"), None);
}

#[test]
fn test_explicit_direct_sentinel_overrides_default_without_dangling() {
    let mut d = AppStateData {
        routes: vec![route("a")],
        default_route_id: Some("a".into()),
        ..Default::default()
    };
    d.provider_routes
        .insert("gemini".into(), DIRECT_ROUTE_ID.into());

    // Gemini stays explicitly Direct while OpenAI/Anthropic inherit default "a".
    assert_eq!(select_route_id(&d, "gemini"), None);
    assert_eq!(select_route(&d, "gemini"), RouteSelection::Direct);
    assert_eq!(select_route_id(&d, "openai").as_deref(), Some("a"));
    assert_eq!(select_route_id(&d, "anthropic").as_deref(), Some("a"));

    // DIRECT_ROUTE_ID is not flagged as a dangling binding.
    let snap = snapshot(&d, &RouteHealthRegistry::default(), 1);
    assert!(
        snap.dangling.is_empty(),
        "unexpected dangling: {:?}",
        snap.dangling
    );
    assert_eq!(
        snap.effective.get("gemini").and_then(|v| v.as_deref()),
        None
    );
    assert_eq!(
        snap.effective.get("openai").and_then(|v| v.as_deref()),
        Some("a")
    );

    // Removing the explicit direct override returns Gemini to default "a".
    d.provider_routes.remove("gemini");
    assert_eq!(select_route_id(&d, "gemini").as_deref(), Some("a"));
}
