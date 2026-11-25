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

#[test]
fn test_windows_install_classification_and_rollback_target() {
    use super::install::{
        WINDOWS_MSI_TARGET, WINDOWS_NSIS_TARGET, WindowsInstallKind, classify_windows_install,
        windows_rollback_target,
    };
    use std::path::Path;
    use tauri::utils::config::BundleType;

    // Explicit bundle_type() takes precedence.
    assert_eq!(
        classify_windows_install(Some(BundleType::Msi), None, false),
        WindowsInstallKind::Msi
    );
    assert_eq!(
        classify_windows_install(Some(BundleType::Nsis), None, false),
        WindowsInstallKind::Nsis
    );

    // SignPath builds pass --no-binary-patching so bundle_type() is None:
    // NSIS uninstaller wins even if installed into Program Files.
    assert_eq!(
        classify_windows_install(None, Some(Path::new(r"C:\Program Files\Zastava")), true),
        WindowsInstallKind::Nsis
    );
    // Program Files without NSIS uninstaller => MSI install.
    assert_eq!(
        classify_windows_install(None, Some(Path::new(r"C:\Program Files\Zastava")), false),
        WindowsInstallKind::Msi
    );
    assert_eq!(
        classify_windows_install(
            None,
            Some(Path::new(r"D:\Program Files (x86)\Zastava")),
            false
        ),
        WindowsInstallKind::Msi
    );
    // LocalAppData or unknown path without bundle_type() => NSIS fallback.
    assert_eq!(
        classify_windows_install(
            None,
            Some(Path::new(r"C:\Users\Ivan\AppData\Local\Zastava")),
            false
        ),
        WindowsInstallKind::Nsis
    );
    assert_eq!(
        classify_windows_install(None, None, false),
        WindowsInstallKind::Nsis
    );

    assert_eq!(
        windows_rollback_target(WindowsInstallKind::Nsis),
        WINDOWS_NSIS_TARGET
    );
    assert_eq!(
        windows_rollback_target(WindowsInstallKind::Msi),
        WINDOWS_MSI_TARGET
    );
}

#[test]
fn test_msi_pre_3_2_1_rollback_rejected_with_actionable_error() {
    use super::install::{WindowsInstallKind, validate_windows_rollback_compatibility};

    // NSIS installs can roll back to pre-3.2.1 (v3.1.1, v3.2.0) via -setup.exe.
    assert_eq!(
        validate_windows_rollback_compatibility(WindowsInstallKind::Nsis, "3.1.1"),
        Ok(())
    );
    assert_eq!(
        validate_windows_rollback_compatibility(WindowsInstallKind::Nsis, "3.2.0"),
        Ok(())
    );

    // MSI installs cannot downgrade to < 3.2.1 without hitting exit 1638 after exit(0).
    for legacy in ["3.1.1", "v3.2.0", "2.2.0", "3.2.1-rc.1"] {
        let err = validate_windows_rollback_compatibility(WindowsInstallKind::Msi, legacy)
            .expect_err("MSI rollback to pre-3.2.1 must fail before teardown");
        match err {
            UpdateFailure::Install(msg) => {
                assert!(
                    msg.contains("Защита не отключалась"),
                    "must reassure protection stayed active: {msg}"
                );
                assert!(
                    msg.contains("NSIS") && msg.contains("-setup.exe") && msg.contains("GitHub"),
                    "must instruct user to install NSIS -setup.exe from GitHub: {msg}"
                );
            }
            other => panic!("expected UpdateFailure::Install, got {other:?}"),
        }
    }

    // 3.2.1+ MSI rollbacks are permitted.
    assert_eq!(
        validate_windows_rollback_compatibility(WindowsInstallKind::Msi, "3.2.1"),
        Ok(())
    );
    assert_eq!(
        validate_windows_rollback_compatibility(WindowsInstallKind::Msi, "3.2.2"),
        Ok(())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_windows_rollback_builder_selects_nsis_target_and_blocks_msi_pre_3_2_1_before_teardown()
 {
    use super::install::{
        WindowsInstallKind, configure_rollback_builder, validate_windows_rollback_compatibility,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tauri::test::{mock_builder, mock_context, noop_assets};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let manifest = serde_json::json!({
        "version": "3.1.1",
        "notes": "legacy v3.1.1",
        "platforms": {
            "windows-x86_64": {
                "url": "http://127.0.0.1:1/Zastava_3.1.1_x64_en-US.msi",
                "signature": "sig-msi"
            },
            "windows-x86_64-msi": {
                "url": "http://127.0.0.1:1/Zastava_3.1.1_x64_en-US.msi",
                "signature": "sig-msi"
            },
            "windows-x86_64-nsis": {
                "url": "http://127.0.0.1:1/Zastava_3.1.1_x64-setup.exe",
                "signature": "sig-nsis"
            }
        }
    })
    .to_string();

    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                manifest.len(),
                manifest
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });

    let mut ctx = mock_context(noop_assets());
    ctx.config_mut().plugins.0.insert(
        "updater".to_string(),
        serde_json::json!({
            "pubkey": UPDATER_PUBKEY,
            "endpoints": [],
            "dangerousInsecureTransportProtocol": true
        }),
    );
    let app = mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(ctx)
        .unwrap();

    let url: url::Url = format!("http://{addr}/latest.json").parse().unwrap();
    let updater = configure_rollback_builder(
        app.handle(),
        url,
        "3.1.1".to_string(),
        Some(WindowsInstallKind::Nsis),
    )
    .unwrap()
    .build()
    .unwrap();
    let update = updater
        .check()
        .await
        .unwrap()
        .expect("v3.1.1 rollback must be resolved");
    assert_eq!(
        update.download_url.as_str(),
        "http://127.0.0.1:1/Zastava_3.1.1_x64-setup.exe"
    );

    // Simulate MSI pre-teardown guard before download_verify_install:
    // protection_off and install must never run.
    let teardown_calls = AtomicUsize::new(0);
    let install_calls = AtomicUsize::new(0);
    let pre_check =
        validate_windows_rollback_compatibility(WindowsInstallKind::Msi, &update.version);
    assert!(matches!(pre_check, Err(UpdateFailure::Install(_))));
    if pre_check.is_ok() {
        let _ = download_verify_install(
            &update,
            |_, _| {},
            || {
                teardown_calls.fetch_add(1, Ordering::SeqCst);
            },
            |_, _| {
                install_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || RestoreOutcome::NotNeeded,
        )
        .await;
    }
    assert_eq!(teardown_calls.load(Ordering::SeqCst), 0);
    assert_eq!(install_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn test_release_workflow_points_windows_x86_64_to_nsis_exe_entry() {
    let workflow = include_str!("../../../.github/workflows/release.yml");
    assert!(
        workflow.contains("\"windows-x86_64\": exeEntry"),
        "release.yml must point windows-x86_64 to exeEntry"
    );
    assert!(
        workflow.contains("\"windows-x86_64-nsis\": exeEntry"),
        "release.yml must keep windows-x86_64-nsis"
    );
    assert!(
        workflow.contains("\"windows-x86_64-msi\": msiEntry"),
        "release.yml must keep windows-x86_64-msi"
    );
}
