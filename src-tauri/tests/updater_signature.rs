//! Signature-gate tests for the native updater.
//!
//! A tiny HTTP server on 127.0.0.1 serves `latest.json` and package bytes. The updater is built
//! through the production `updater::updater_builder` and driven through the production
//! `updater::download_verify_install`; the "protection off" and "install" steps are replaced by
//! counters, so these tests never touch system proxy settings and never install anything.
//!
//! The keys below are throw-away test keys generated for this file (public parts only):
//! `SIG_A` is the minisign signature of `PAYLOAD_A` made with key A.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
use tauri_plugin_updater::Update;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use zastava_lib::updater::{
    RestoreOutcome, UpdateFailure, download_verify_install, map_error, updater_builder,
};

const PAYLOAD_A: &[u8] = b"zastava-test-update-payload-A";
const PAYLOAD_TAMPERED: &[u8] = b"zastava-test-update-payload-TAMPERED";
const PUBKEY_A: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDI2NUI3MTNCMDEyMkMyQ0YKUldUUHdpSUJPM0ZiSnRlWkRmMjBXdlRrc0pLWmx6SWJ6U0sxZ3hHUmpKMG9PZTVFbXNHbng3U2EK";
const PUBKEY_B: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDEzNkQ2REY1NEQyMTQyQTUKUldTbFFpRk45VzF0RXhJMkNVUzhEeDRWZ01SQnd4MGk2N29rSXhPTGU3VFN4aUt6TFdiZDN4VmUK";
const SIG_A: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUUHdpSUJPM0ZiSmpocXgxZUJONUxzL01vemtQOGZvNDVuMHVXRFlKR1pIRFNsZkY0bUZiWWdEa3JCMXNmMXR1Y3RjZ1NaWmdBY2lnalZhcWw5MFQ0V0pHZUJ3NVFTUFFJPQp0cnVzdGVkIGNvbW1lbnQ6IHRpbWVzdGFtcDoxNzk0NDc0MTE4CWZpbGU6cGF5bG9hZF9hLmJpbgpvM2o5ckloR05yRVpQM3Y4WWtUN2RoZThnT0tnaWRhTGNSTkVwaklqczJML3NXTU9FQTJBWHUrSklIUkNoaTNZRmtFSjBGeDI4NW9FWVpqUWpDN2tDdz09Cg==";
const TARGET: &str = "darwin-aarch64";

type Routes = HashMap<String, (u16, Vec<u8>)>;

/// Minimal HTTP/1.1 server: one response per connection, routes by exact path, 404 otherwise.
async fn serve(build_routes: impl FnOnce(u16) -> Routes) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = Arc::new(build_routes(addr.port()));
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let path = head
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .split('?')
                    .next()
                    .unwrap_or("/")
                    .to_string();
                let (status, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, b"not found".to_vec()));
                let reason = if status == 200 { "OK" } else { "ERR" };
                let header = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    addr
}

fn manifest(version: &str, port: u16, pkg_path: &str, signature: &str) -> Vec<u8> {
    serde_json::json!({
        "version": version,
        "notes": "test",
        "platforms": { TARGET: { "url": format!("http://127.0.0.1:{port}{pkg_path}"), "signature": signature } }
    })
    .to_string()
    .into_bytes()
}

/// Mock app (running version 0.1.0) with the updater plugin. The insecure-transport flag exists
/// only here, in the test configuration; `tauri.conf.json` never sets it.
fn mock_app_with_updater() -> tauri::App<MockRuntime> {
    let mut ctx = mock_context(noop_assets());
    ctx.config_mut().plugins.0.insert(
        "updater".to_string(),
        serde_json::json!({
            "pubkey": PUBKEY_A,
            "endpoints": [],
            "dangerousInsecureTransportProtocol": true
        }),
    );
    mock_builder()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .build(ctx)
        .unwrap()
}

async fn check(
    app: &tauri::App<MockRuntime>,
    addr: SocketAddr,
    pubkey: &str,
) -> Result<Option<Update>, UpdateFailure> {
    let url = format!("http://{addr}/latest.json").parse().unwrap();
    let updater = updater_builder(app.handle())
        .endpoints(vec![url])
        .unwrap()
        .pubkey(pubkey)
        .target(TARGET)
        .no_proxy()
        .build()
        .unwrap();
    updater.check().await.map_err(|e| map_error(&e))
}

#[derive(Default)]
struct Calls(Mutex<Vec<&'static str>>);

impl Calls {
    fn push(&self, what: &'static str) {
        self.0.lock().unwrap().push(what);
    }
    fn all(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().clone()
    }
}

/// Runs the production flow with counters instead of the real "protection off", "install" and
/// "protection restore". `install_result` is what the fake install step returns.
async fn run_flow_with(
    update: &Update,
    install_result: fn() -> tauri_plugin_updater::Result<()>,
    restore: RestoreOutcome,
) -> (Result<(), UpdateFailure>, Vec<&'static str>) {
    let calls = Arc::new(Calls::default());
    let (off, inst, rest) = (calls.clone(), calls.clone(), calls.clone());
    let res = download_verify_install(
        update,
        |_, _| {},
        move || off.push("protection_off"),
        move |_, _| {
            inst.push("install");
            install_result()
        },
        move || {
            rest.push("protection_restore");
            restore
        },
    )
    .await;
    (res, calls.all())
}

async fn run_flow(update: &Update) -> (Result<(), UpdateFailure>, Vec<&'static str>) {
    run_flow_with(update, || Ok(()), RestoreOutcome::Restored).await
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_signature_is_rejected_before_protection_off_and_install() {
    let addr = serve(|port| {
        Routes::from([
            (
                "/latest.json".into(),
                (200, manifest("99.0.0", port, "/pkg", SIG_A)),
            ),
            ("/pkg".into(), (200, PAYLOAD_TAMPERED.to_vec())),
        ])
    })
    .await;
    let app = mock_app_with_updater();
    let update = check(&app, addr, PUBKEY_A)
        .await
        .unwrap()
        .expect("update announced");
    let (res, calls) = run_flow(&update).await;
    assert_eq!(res, Err(UpdateFailure::Signature));
    assert!(
        calls.is_empty(),
        "protection_off/install must not run, got {calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_pubkey_is_rejected() {
    let addr = serve(|port| {
        Routes::from([
            (
                "/latest.json".into(),
                (200, manifest("99.0.0", port, "/pkg", SIG_A)),
            ),
            ("/pkg".into(), (200, PAYLOAD_A.to_vec())),
        ])
    })
    .await;
    let app = mock_app_with_updater();
    let update = check(&app, addr, PUBKEY_B)
        .await
        .unwrap()
        .expect("update announced");
    let (res, calls) = run_flow(&update).await;
    assert_eq!(res, Err(UpdateFailure::Signature));
    assert!(
        calls.is_empty(),
        "protection_off/install must not run, got {calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_pubkey_is_rejected() {
    let addr = serve(|port| {
        Routes::from([
            (
                "/latest.json".into(),
                (200, manifest("99.0.0", port, "/pkg", SIG_A)),
            ),
            ("/pkg".into(), (200, PAYLOAD_A.to_vec())),
        ])
    })
    .await;
    let app = mock_app_with_updater();
    let update = check(&app, addr, "not-a-valid-key")
        .await
        .unwrap()
        .expect("update announced");
    let (res, calls) = run_flow(&update).await;
    assert!(res.is_err(), "malformed pubkey must never verify");
    assert!(
        calls.is_empty(),
        "protection_off/install must not run, got {calls:?}"
    );
}

/// Positive control: proves the negative tests fail because of the signature, not because of
/// the harness. Protection is switched off strictly between verification and install.
#[tokio::test(flavor = "multi_thread")]
async fn valid_signature_turns_protection_off_then_installs_in_order() {
    let addr = serve(|port| {
        Routes::from([
            (
                "/latest.json".into(),
                (200, manifest("99.0.0", port, "/pkg", SIG_A)),
            ),
            ("/pkg".into(), (200, PAYLOAD_A.to_vec())),
        ])
    })
    .await;
    let app = mock_app_with_updater();
    let update = check(&app, addr, PUBKEY_A)
        .await
        .unwrap()
        .expect("update announced");
    let (res, calls) = run_flow(&update).await;
    assert_eq!(res, Ok(()));
    assert_eq!(calls, ["protection_off", "install"]);
}

fn install_fails() -> tauri_plugin_updater::Result<()> {
    Err(tauri_plugin_updater::Error::InvalidUpdaterFormat)
}

/// Install fails after protection was switched off: protection is restored, after install.
#[tokio::test(flavor = "multi_thread")]
async fn failed_install_restores_protection_after_install() {
    let addr = serve(|port| {
        Routes::from([
            (
                "/latest.json".into(),
                (200, manifest("99.0.0", port, "/pkg", SIG_A)),
            ),
            ("/pkg".into(), (200, PAYLOAD_A.to_vec())),
        ])
    })
    .await;
    let app = mock_app_with_updater();
    let update = check(&app, addr, PUBKEY_A)
        .await
        .unwrap()
        .expect("update announced");

    let (res, calls) = run_flow_with(&update, install_fails, RestoreOutcome::Restored).await;
    assert!(
        matches!(res, Err(UpdateFailure::InstallRestored(_))),
        "got {res:?}"
    );
    assert_eq!(calls, ["protection_off", "install", "protection_restore"]);

    // Protection was not on before the update (or could not be brought back): plain Install.
    for outcome in [RestoreOutcome::NotNeeded, RestoreOutcome::Failed] {
        let (res, calls) = run_flow_with(&update, install_fails, outcome).await;
        assert!(matches!(res, Err(UpdateFailure::Install(_))), "got {res:?}");
        assert_eq!(calls, ["protection_off", "install", "protection_restore"]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_latest_json_is_no_release() {
    let addr = serve(|_| Routes::new()).await; // every path -> 404
    let app = mock_app_with_updater();
    let res = check(&app, addr, PUBKEY_A).await;
    assert!(
        matches!(res, Err(UpdateFailure::NoRelease)),
        "got {:?}",
        res.map(|_| ())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_server_is_network() {
    // Bind and drop to obtain a port nobody listens on.
    let addr = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let app = mock_app_with_updater();
    let res = check(&app, addr, PUBKEY_A).await;
    assert!(
        matches!(res, Err(UpdateFailure::Network)),
        "got {:?}",
        res.map(|_| ())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn package_404_is_network_and_keeps_protection() {
    let addr = serve(|port| {
        Routes::from([(
            "/latest.json".into(),
            (200, manifest("99.0.0", port, "/pkg", SIG_A)),
        )])
    })
    .await;
    let app = mock_app_with_updater();
    let update = check(&app, addr, PUBKEY_A)
        .await
        .unwrap()
        .expect("update announced");
    let (res, calls) = run_flow(&update).await;
    assert_eq!(res, Err(UpdateFailure::Network));
    assert!(calls.is_empty());
}

/// Downgrade guard: the mock app runs 0.1.0; an older or equal version is not an update.
#[tokio::test(flavor = "multi_thread")]
async fn older_or_equal_version_is_not_an_update() {
    for version in ["0.0.9", "0.1.0"] {
        let addr = serve(|port| {
            Routes::from([(
                "/latest.json".into(),
                (200, manifest(version, port, "/pkg", SIG_A)),
            )])
        })
        .await;
        let app = mock_app_with_updater();
        let res = check(&app, addr, PUBKEY_A).await;
        assert!(
            matches!(res, Ok(None)),
            "version {version} must not be offered"
        );
    }
}
