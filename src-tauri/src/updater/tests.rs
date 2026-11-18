use super::*;

#[test]
fn test_semver_comparison() {
    assert_eq!(CURRENT_VERSION, env!("CARGO_PKG_VERSION"));
    assert!(is_newer_version("1.0.3", "1.0.4"));
    assert!(is_newer_version("v1.0.3", "v1.0.4"));
    assert!(is_newer_version("1.0.3", "1.1.0"));
    assert!(is_newer_version("1.0.3", "2.0.0"));
    assert!(is_newer_version("2.0.0", "2.0.1"));
    assert!(is_newer_version("2.0.0", "2.1.0"));
    assert!(!is_newer_version("2.1.0", "2.0.0"));
    assert!(!is_newer_version("2.0.0", "2.0.0"));
    assert!(!is_newer_version("2.0.0", "1.3.1"));
    assert!(!is_newer_version("1.0.4", "1.0.4"));
    assert!(!is_newer_version("1.0.4", "1.0.3"));
    assert!(is_newer_version("1.0.3", "1.0.10"));
}

#[test]
fn a_trial_build_updates_to_its_final_release_and_never_the_other_way() {
    // The rc is built from the numeric pre-release 2.1.0-1 (MSI needs a number).
    assert!(is_newer_version("2.1.0-1", "2.1.0"));
    assert!(is_newer_version("v2.1.0-1", "v2.1.0"));
    assert!(is_newer_version("2.1.0-rc.1", "2.1.0"));
    assert!(!is_newer_version("2.1.0", "2.1.0-1"));
    assert!(!is_newer_version("2.1.0-1", "2.1.0-1"));
    // Between pre-releases the identifiers decide, numbers numerically.
    assert!(is_newer_version("2.1.0-1", "2.1.0-2"));
    assert!(is_newer_version("2.1.0-2", "2.1.0-10"));
    assert!(!is_newer_version("2.1.0-10", "2.1.0-2"));
    assert!(is_newer_version("2.1.0-rc.1", "2.1.0-rc.2"));
    assert!(
        is_newer_version("2.1.0-1", "2.1.0-rc.1"),
        "a number sorts before a word"
    );
    // A different numeric core always wins.
    assert!(is_newer_version("2.0.0", "2.1.0-1"));
    assert!(!is_newer_version("2.1.0-1", "2.0.9"));
    assert!(is_newer_version("2.1.0-5", "2.1.1"));
}

#[test]
fn map_error_network_is_failure_not_ok() {
    let err = tauri_plugin_updater::Error::Network("down".into());
    assert_eq!(map_error(&err), UpdateFailure::Network);
    let r: Result<UpdateCheckResult, UpdateFailure> = Err(map_error(&err));
    assert!(matches!(r, Err(UpdateFailure::Network)));
}

#[test]
fn map_error_classes() {
    use tauri_plugin_updater::Error as E;
    assert_eq!(map_error(&E::ReleaseNotFound), UpdateFailure::NoRelease);
    assert_eq!(
        map_error(&E::TargetNotFound("x".into())),
        UpdateFailure::NoRelease
    );
    assert_eq!(
        map_error(&E::SignatureUtf8("x".into())),
        UpdateFailure::Signature
    );
    assert_eq!(
        map_error(&E::MissingSignedVersion),
        UpdateFailure::Signature
    );
    assert!(matches!(
        map_error(&E::InvalidUpdaterFormat),
        UpdateFailure::Install(_)
    ));
}

#[test]
fn update_failure_serde_codes() {
    let v = |f: UpdateFailure| serde_json::to_value(f).unwrap();
    assert_eq!(
        v(UpdateFailure::Network),
        serde_json::json!({"kind": "network"})
    );
    assert_eq!(
        v(UpdateFailure::Signature),
        serde_json::json!({"kind": "signature"})
    );
    assert_eq!(
        v(UpdateFailure::NoRelease),
        serde_json::json!({"kind": "no-release"})
    );
    assert_eq!(
        v(UpdateFailure::Install("boom".into())),
        serde_json::json!({"kind": "install", "message": "boom"})
    );
    assert_eq!(
        v(UpdateFailure::InstallRestored("boom".into())),
        serde_json::json!({"kind": "install-restored", "message": "boom"})
    );
}

#[test]
fn update_check_result_has_no_download_fields() {
    let meta = UpdateMeta {
        version: "v2.1.0".into(),
        body: Some("notes".into()),
        date: None,
    };
    let value = serde_json::to_value(map_update(Some(meta))).unwrap();
    let mut keys: Vec<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "current_version",
            "latest_version",
            "published_at",
            "release_name",
            "release_notes",
            "release_url",
            "update_available"
        ]
    );
    assert_eq!(value["latest_version"], "2.1.0");
    assert_eq!(
        value["release_url"],
        "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.0"
    );
    assert!(value.get("download_url").is_none());
    assert!(value.get("asset_name").is_none());
    assert!(value.get("asset_size").is_none());
}

#[test]
fn map_update_none_points_to_latest_release_page() {
    let r = map_update(None);
    assert!(!r.update_available);
    assert_eq!(r.latest_version, CURRENT_VERSION);
    assert_eq!(
        r.release_url,
        "https://github.com/kingbest1195/ai-antiban/releases/latest"
    );
}

#[test]
fn test_normalize_semver_and_is_older_version() {
    assert_eq!(normalize_semver("2.1.0").as_deref(), Some("2.1.0"));
    assert_eq!(normalize_semver("v2.1.0").as_deref(), Some("2.1.0"));
    assert_eq!(normalize_semver(" V2.1.0 ").as_deref(), Some("2.1.0"));
    assert_eq!(
        normalize_semver("v2.1.0-rc.1").as_deref(),
        Some("2.1.0-rc.1")
    );

    // Reject malformed or URL-unsafe inputs.
    for bad in [
        "",
        "   ",
        "v",
        "vv2.1.0",
        "2.1",
        "2.1.0.4",
        "01.2.3",
        "2.1.0+build1",
        "2.1.0/../../evil",
        "2.1.0?foo=bar",
        "2.1.0-rc..1",
        "2.1.0-",
        "not-a-version",
    ] {
        assert_eq!(normalize_semver(bad), None, "should reject {bad:?}");
        assert!(!is_older_version("2.2.0", bad));
    }

    assert!(is_older_version("2.2.0", "2.1.2"));
    assert!(is_older_version("2.2.0", "v2.1.0"));
    assert!(is_older_version("2.2.0", "1.3.1"));
    assert!(is_older_version("2.2.0", "2.2.0-rc.1"));
    assert!(!is_older_version("2.2.0", "2.2.0"));
    assert!(!is_older_version("2.2.0", "v2.2.0"));
    assert!(!is_older_version("2.2.0", "2.2.1"));
    assert!(!is_older_version("2.2.0", "3.0.0"));
    assert!(!is_older_version("2.2.0-rc.1", "2.2.0"));
}

#[test]
fn test_parse_rollback_releases_filtering_and_sorting() {
    let payload = serde_json::json!([
        {
            "tag_name": "v2.3.0",
            "name": "Future",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-11-15T00:00:00Z",
            "html_url": "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.3.0",
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.2.0",
            "name": "Current",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-11-14T00:00:00Z",
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.1.9",
            "name": "Draft Release",
            "draft": true,
            "prerelease": false,
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.1.8-rc.1",
            "name": "Prerelease",
            "draft": false,
            "prerelease": true,
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.1.7",
            "name": "No Manifest",
            "draft": false,
            "prerelease": false,
            "assets": [{ "name": "Zastava_2.1.7_aarch64.dmg" }]
        },
        {
            "tag_name": "bad-tag",
            "name": "Bad Tag",
            "draft": false,
            "prerelease": false,
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.0.0",
            "name": "   ",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-09-01T00:00:00Z",
            "html_url": "https://evil.example.com/phish",
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.1.2",
            "name": "Zastava 2.1.2",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-10-10T00:00:00Z",
            "html_url": "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.2",
            "assets": [{ "name": "latest.json" }]
        },
        {
            "tag_name": "v2.1.0",
            "name": "Zastava 2.1.0",
            "draft": false,
            "prerelease": false,
            "published_at": "2026-10-01T00:00:00Z",
            "assets": [{ "name": "latest.json" }]
        }
    ])
    .to_string();

    let parsed = parse_rollback_releases(&payload, "2.2.0").unwrap();
    let versions: Vec<&str> = parsed.iter().map(|r| r.version.as_str()).collect();
    assert_eq!(versions, ["2.1.2", "2.1.0", "2.0.0"]);

    assert_eq!(parsed[0].tag, "v2.1.2");
    assert_eq!(parsed[0].name, "Zastava 2.1.2");
    assert_eq!(
        parsed[0].notes_url,
        "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.1.2"
    );

    // Fallback name and sanitized notes_url on untrusted html_url:
    assert_eq!(parsed[2].name, "Zastava v2.0.0");
    assert_eq!(
        parsed[2].notes_url,
        "https://github.com/kingbest1195/ai-antiban/releases/tag/v2.0.0"
    );
}

#[test]
fn test_parse_rollback_releases_caps_at_eight_newest_first() {
    let releases: Vec<serde_json::Value> = (1..=12)
        .map(|patch| {
            serde_json::json!({
                "tag_name": format!("v1.0.{patch}"),
                "draft": false,
                "prerelease": false,
                "assets": [{ "name": "latest.json" }]
            })
        })
        .collect();
    let payload = serde_json::Value::Array(releases).to_string();
    let parsed = parse_rollback_releases(&payload, "2.2.0").unwrap();
    assert_eq!(parsed.len(), ROLLBACK_MAX_RELEASES);
    let versions: Vec<&str> = parsed.iter().map(|r| r.version.as_str()).collect();
    assert_eq!(
        versions,
        [
            "1.0.12", "1.0.11", "1.0.10", "1.0.9", "1.0.8", "1.0.7", "1.0.6", "1.0.5"
        ]
    );
}

#[test]
fn test_rollback_manifest_url_validation() {
    assert_eq!(rollback_manifest_url(""), Err(UpdateFailure::NoRelease));
    assert_eq!(
        rollback_manifest_url("2.1.0/../../bad"),
        Err(UpdateFailure::NoRelease)
    );
    assert_eq!(
        rollback_manifest_url(CURRENT_VERSION),
        Err(UpdateFailure::NoRelease)
    );
    assert_eq!(
        rollback_manifest_url("99.0.0"),
        Err(UpdateFailure::NoRelease)
    );

    let (ver, url) = rollback_manifest_url("v2.1.0").unwrap();
    assert_eq!(ver, "2.1.0");
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("github.com"));
    assert_eq!(
        url.as_str(),
        "https://github.com/kingbest1195/ai-antiban/releases/download/v2.1.0/latest.json"
    );

    let (ver2, url2) = rollback_manifest_url("2.0.0").unwrap();
    assert_eq!(ver2, "2.0.0");
    assert_eq!(
        url2.as_str(),
        "https://github.com/kingbest1195/ai-antiban/releases/download/v2.0.0/latest.json"
    );
}
