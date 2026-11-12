//! Coverage tests: canned OS output, `FakePlatform`, `FakeFs`, a manual clock. No process is
//! started and no real user directory is read.

use super::*;
use crate::sysproxy::fs::{FakeFs, Fs, RealFs};
use crate::sysproxy::platform::{FakePlatform, PacState, PlatOp, RegValue, ServiceId};
use std::sync::atomic::{AtomicU64, Ordering};

// ----- doubles ---------------------------------------------------------------------------------

#[derive(Default)]
struct FakeProbe {
    calls: Mutex<Vec<String>>,
    /// Output for every call (`None` = the program "failed").
    output: Mutex<Option<String>>,
}

impl FakeProbe {
    fn answering(text: &str) -> Arc<Self> {
        let p = Self::default();
        *p.output.lock().unwrap() = Some(text.to_string());
        Arc::new(p)
    }
    fn failing() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl SystemProbe for FakeProbe {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{program} {}", args.join(" ")));
        self.output.lock().unwrap().clone()
    }
}

const LSOF_CLAUDE: &str = "p501\ncClaude\nn127.0.0.1:50000->127.0.0.1:8899\n";

fn clock_at(ms: u64) -> (Arc<AtomicU64>, Clock) {
    let t = Arc::new(AtomicU64::new(ms));
    let t2 = Arc::clone(&t);
    (t, Arc::new(move || t2.load(Ordering::SeqCst)))
}

fn tracker(probe: Arc<FakeProbe>) -> (Arc<AtomicU64>, CoverageTracker) {
    let (t, clock) = clock_at(10_000_000);
    (t, CoverageTracker::with_parts(clock, probe, Os::Macos))
}

fn gw(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().unwrap()
}

fn home() -> PathBuf {
    Path::new("home").join("user")
}

fn editor_root() -> PathBuf {
    home().join("support")
}

fn ctx_with(fs: &FakeFs) -> FileCtx {
    FileCtx::new(Arc::new(fs.clone()), home(), vec![editor_root()])
}

fn make_editor(fs: &FakeFs, folder: &str, settings: Option<&str>) {
    let user = editor_root().join(folder).join("User");
    fs.create_private_dir_all(&user).unwrap();
    if let Some(text) = settings {
        fs.put(&user.join("settings.json"), text.as_bytes(), 0o600);
    }
}

struct Rig {
    platform: FakePlatform,
    ctx: FileCtx,
    fs: FakeFs,
}

impl Rig {
    fn new() -> Self {
        let fs = FakeFs::new();
        Self {
            platform: FakePlatform::new(),
            ctx: ctx_with(&fs),
            fs,
        }
    }

    fn env(&self, source: PacSource, cli: bool) -> CoverageEnv<'_> {
        CoverageEnv {
            platform: &self.platform,
            files: Some(&self.ctx),
            pac_source: source,
            sysproxy_enabled: true,
            cli_protection_enabled: cli,
            chained_proxy: None,
            jetbrains_xml_confirmed: JETBRAINS_XML_CONFIRMED,
        }
    }

    fn wifi() -> ServiceId {
        ServiceId::new("en0", "Wi-Fi", "Wi-Fi")
    }

    fn seed_wifi_pac(&self, url: &str, enabled: bool) {
        let svc = Self::wifi();
        self.platform.add_service(svc.clone());
        self.platform.seed_pac(
            &svc,
            PacState {
                url: Some(url.to_string()),
                enabled: Some(enabled),
            },
        );
    }
}

fn app<'a>(snap: &'a CoverageSnapshot, id: &str) -> &'a AppCoverageItem {
    snap.apps.iter().find(|a| a.id == id).unwrap()
}

// ----- classification --------------------------------------------------------------------------

#[test]
fn classify_known_names() {
    assert_eq!(classify_process_name("Claude"), "claude-desktop");
    assert_eq!(classify_process_name("Claude Helper"), "claude-desktop");
    assert_eq!(classify_process_name("claude.exe"), "claude-desktop");
    assert_eq!(classify_process_name("ChatGPT"), "chatgpt-desktop");
    assert_eq!(classify_process_name("chatgpt.exe"), "chatgpt-desktop");
    assert_eq!(classify_process_name("Antigravity"), "antigravity");
    assert_eq!(classify_process_name("Cursor Helper"), "cursor");
    assert_eq!(classify_process_name("Code"), "vscode");
    assert_eq!(classify_process_name("Code Helper (Renderer)"), "vscode");
    assert_eq!(classify_process_name("vscode.exe"), "vscode");
    assert_eq!(classify_process_name("Visual Studio Code"), "vscode");
    assert_eq!(classify_process_name("windsurf.exe"), "windsurf");
    assert_eq!(classify_process_name("idea"), "jetbrains");
    assert_eq!(classify_process_name("idea64.exe"), "jetbrains");
    assert_eq!(classify_process_name("pycharm64.exe"), "jetbrains");
    assert_eq!(classify_process_name("WebStorm"), "jetbrains");
    assert_eq!(classify_process_name("Rider"), "jetbrains");
    assert_eq!(classify_process_name("rider64.exe"), "jetbrains");
    assert_eq!(classify_process_name("Android Studio"), "jetbrains");
    assert_eq!(classify_process_name("studio64.exe"), "jetbrains");
    assert_eq!(classify_process_name("Google Chrome Helper"), "browsers");
    assert_eq!(classify_process_name("Safari"), "browsers");
    assert_eq!(classify_process_name("Arc"), "browsers");
    assert_eq!(classify_process_name("Arc Helper"), "browsers");
    assert_eq!(classify_process_name("msedge.exe"), "browsers");
    assert_eq!(classify_process_name("Microsoft Edge Helper"), "browsers");
    assert_eq!(classify_process_name("Яндекс Браузер"), "browsers");
    assert_eq!(classify_process_name("YandexBrowser"), "browsers");
    assert_eq!(classify_process_name("Firefox"), "browsers");
    assert_eq!(classify_process_name("Brave Browser Helper"), "browsers");
    assert_eq!(classify_process_name("claude-code"), "claude-code");
    assert_eq!(classify_process_name("gemini"), "gemini-cli");
    assert_eq!(classify_process_name("node"), "node-cli");
    assert_eq!(classify_process_name("python3"), "python-cli");
    assert_eq!(classify_process_name("Python"), "python-cli");
    assert_eq!(classify_process_name("curl"), "curl");
    assert_eq!(classify_process_name("unknown-binary"), "other");
}

#[test]
fn classify_has_no_substring_false_positives() {
    // rider vs provider
    assert_eq!(classify_process_name("provider"), "other");
    assert_eq!(classify_process_name("providerd"), "other");
    assert_eq!(classify_process_name("ContentProviderHost.exe"), "other");
    // edge vs knowledge
    assert_eq!(classify_process_name("knowledge"), "other");
    assert_eq!(classify_process_name("knowledge-agent"), "other");
    assert_eq!(classify_process_name("KnowledgeBase.exe"), "other");
    // studio: only Android Studio is JetBrains, Visual Studio is not
    assert_eq!(classify_process_name("studio"), "other");
    assert_eq!(classify_process_name("Visual Studio"), "other");
    assert_eq!(classify_process_name("devenv"), "other");
    assert_eq!(classify_process_name("Studio Display Daemon"), "other");
    // idea / code / cursor / node embedded in other words
    assert_eq!(classify_process_name("ideal"), "other");
    assert_eq!(classify_process_name("codesign"), "other");
    assert_eq!(classify_process_name("cursorless"), "other");
    assert_eq!(classify_process_name("nodemon"), "other");
    assert_eq!(classify_process_name("claudette"), "other");
    assert_eq!(classify_process_name("pythonista"), "other");
}

// ----- OS output parsers -----------------------------------------------------------------------

#[test]
fn lsof_output_skips_the_gateway_itself() {
    let text = "p77645\nczastava\nn127.0.0.1:8899->127.0.0.1:50000\n\
                p501\ncGoogle\\x20Chrome\\x20Helper\nn127.0.0.1:50000->127.0.0.1:8899\n";
    assert_eq!(
        parse_lsof_owner(text, 77645).as_deref(),
        Some("Google Chrome Helper")
    );
    assert_eq!(parse_lsof_owner("", 1), None);
    // Only the gateway's own socket -> nobody.
    assert_eq!(
        parse_lsof_owner(
            "p77645\nczastava\nn127.0.0.1:8899->127.0.0.1:50000\n",
            77645
        ),
        None
    );
}

const NETSTAT_SAMPLE: &str = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1000
  TCP    127.0.0.1:18899        127.0.0.1:40000        ESTABLISHED     111
  TCP    127.0.0.1:88990        127.0.0.1:40001        ESTABLISHED     112
  TCP    127.0.0.1:8899         127.0.0.1:50000        ESTABLISHED     4242
  TCP    127.0.0.1:50000        127.0.0.1:8899         ESTABLISHED     222
  TCP    [::1]:58899            [::1]:40002            ESTABLISHED     333
";

#[test]
fn netstat_matches_the_port_exactly() {
    // 8899 must not hit 18899 / 88990 / 58899.
    let only_lookalikes = "\
  TCP    127.0.0.1:18899        127.0.0.1:40000        ESTABLISHED     111
  TCP    127.0.0.1:88990        127.0.0.1:40001        ESTABLISHED     112
  TCP    [::1]:58899            [::1]:40002            ESTABLISHED     333
";
    assert_eq!(parse_netstat_pid(only_lookalikes, 8899, 1), None);
    assert_eq!(parse_netstat_pid(only_lookalikes, 18899, 1), Some(111));
    assert_eq!(parse_netstat_pid(only_lookalikes, 5000, 1), None);
    // The client's socket (local port 50000) is found; the gateway's own row is skipped.
    assert_eq!(parse_netstat_pid(NETSTAT_SAMPLE, 50000, 4242), Some(222));
    // PID 0 is never an owner.
    let zero = "  TCP    127.0.0.1:50000        127.0.0.1:8899         TIME_WAIT       0\n";
    assert_eq!(parse_netstat_pid(zero, 50000, 1), None);
}

#[test]
fn tasklist_and_ss_samples() {
    assert_eq!(
        parse_tasklist_name("\"chrome.exe\",\"222\",\"Console\",\"1\",\"100,000 K\"\r\n")
            .as_deref(),
        Some("chrome.exe")
    );
    assert_eq!(parse_tasklist_name("INFO: No tasks are running\r\n"), None);

    let ss = "\
ESTAB 0 0 127.0.0.1:8899 127.0.0.1:50000 users:((\"zastava\",pid=4242,fd=9))
ESTAB 0 0 127.0.0.1:50000 127.0.0.1:8899 users:((\"curl\",pid=222,fd=5))
ESTAB 0 0 127.0.0.1:150000 127.0.0.1:18899 users:((\"other\",pid=7,fd=5))
";
    assert_eq!(parse_ss_owner(ss, 50000, 4242).as_deref(), Some("curl"));
    assert_eq!(parse_ss_owner(ss, 8899, 4242).as_deref(), Some("curl"));
    assert_eq!(parse_ss_owner(ss, 889, 4242), None);
}

#[test]
fn lookup_goes_through_the_probe_on_every_os() {
    let p = FakeProbe::answering(LSOF_CLAUDE);
    assert_eq!(
        lookup_process_with(&*p, Os::Macos, 50000, 1).as_deref(),
        Some("Claude")
    );
    assert!(p.calls.lock().unwrap()[0].starts_with("lsof "));
    assert!(p.calls.lock().unwrap()[0].contains("-iTCP:50000"));

    let p = FakeProbe::answering(NETSTAT_SAMPLE);
    // The same canned text answers `tasklist` too: its first quoted token is not present, so
    // the lookup ends with nothing, but both tools were asked.
    assert_eq!(lookup_process_with(&*p, Os::Windows, 50000, 4242), None);
    let calls = p.calls.lock().unwrap().clone();
    assert!(calls[0].starts_with("netstat "));
    assert!(calls[1].starts_with("tasklist ") && calls[1].contains("PID eq 222"));

    let p = FakeProbe::answering(
        "ESTAB 0 0 127.0.0.1:50000 127.0.0.1:8899 users:((\"node\",pid=9,fd=5))\n",
    );
    assert_eq!(
        lookup_process_with(&*p, Os::Linux, 50000, 1).as_deref(),
        Some("node")
    );

    // A failing tool means "unknown", not a panic.
    assert_eq!(
        lookup_process_with(&*FakeProbe::failing(), Os::Macos, 1, 1),
        None
    );
}

// ----- counting: PAC, direct, lsof storm -------------------------------------------------------

#[test]
fn pac_fetch_is_not_an_ai_request() {
    let (_, t) = tracker(FakeProbe::failing());
    t.record_incoming_blocking(50001, Some("curl/8.7.1"), TrafficKind::PacFetch);
    t.record_incoming_blocking(50002, Some("curl/8.7.1"), TrafficKind::PacFetch);
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let curl = app(&snap, "curl");
    assert_eq!(curl.pac_fetches, 2);
    assert_eq!(curl.ai_requests, 0);
    assert_eq!(curl.requests_seen, 0);
    assert_eq!(curl.last_seen_ms, None);
    assert_ne!(curl.status, CoverageStatus::Confirmed);
}

#[test]
fn pac_fetch_by_an_unknown_process_creates_no_app() {
    let probe = FakeProbe::answering("p9\ncpacrunner\nn127.0.0.1:50003->127.0.0.1:8899\n");
    let (_, t) = tracker(probe);
    t.record_incoming_blocking(50003, None, TrafficKind::PacFetch);
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(snap.apps.len(), KNOWN_IDS.len());
    assert!(snap.apps.iter().all(|a| a.ai_requests == 0));
}

#[test]
fn ai_request_counts_and_confirms() {
    let (_, t) = tracker(FakeProbe::failing());
    t.record_incoming_blocking(50010, Some("curl/8.7.1"), TrafficKind::AiRequest);
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let curl = app(&snap, "curl");
    assert_eq!(curl.ai_requests, 1);
    assert_eq!(curl.requests_seen, 1);
    assert_eq!(curl.status, CoverageStatus::Confirmed);
    assert!(curl.last_seen_ms.is_some());
    assert!(curl.manual_steps.is_empty());
}

#[test]
fn direct_traffic_never_reaches_the_lsof_seam() {
    let probe = FakeProbe::answering(LSOF_CLAUDE);
    let (_, t) = tracker(Arc::clone(&probe));
    for port in 40000..40200u16 {
        t.record_incoming_blocking(port, None, TrafficKind::Direct);
        t.record_incoming_blocking(port, Some("npm/10.0.0"), TrafficKind::Direct);
    }
    assert_eq!(probe.count(), 0, "lsof must not run for transit traffic");
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert!(
        snap.apps
            .iter()
            .all(|a| a.ai_requests == 0 && a.pac_fetches == 0)
    );
}

#[tokio::test]
async fn direct_through_the_async_entry_is_free_too() {
    let probe = FakeProbe::answering(LSOF_CLAUDE);
    let (_, t) = tracker(Arc::clone(&probe));
    let t = Arc::new(t);
    for port in 40000..40100u16 {
        t.record_incoming(port, None, TrafficKind::Direct);
    }
    tokio::task::yield_now().await;
    assert_eq!(probe.count(), 0);
}

#[test]
fn lookups_are_cached_per_port() {
    let probe = FakeProbe::answering(LSOF_CLAUDE);
    let (clock, t) = tracker(Arc::clone(&probe));
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    assert_eq!(probe.count(), 1);
    clock.fetch_add(LOOKUP_CACHE_TTL_MS + 1, Ordering::SeqCst);
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    assert_eq!(probe.count(), 2);

    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "claude-desktop").ai_requests, 4);
}

#[test]
fn failed_lookup_is_remembered_briefly() {
    let probe = FakeProbe::failing();
    let (clock, t) = tracker(Arc::clone(&probe));
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    assert_eq!(probe.count(), 1);
    clock.fetch_add(LOOKUP_NEGATIVE_TTL_MS + 1, Ordering::SeqCst);
    t.record_incoming_blocking(50000, None, TrafficKind::AiRequest);
    assert_eq!(probe.count(), 2);
}

#[test]
fn lookup_storm_is_rate_limited() {
    let probe = FakeProbe::answering(LSOF_CLAUDE);
    let (clock, t) = tracker(Arc::clone(&probe));
    for port in 40000..40100u16 {
        t.record_incoming_blocking(port, None, TrafficKind::AiRequest);
    }
    assert_eq!(probe.count(), LOOKUP_RATE_MAX);
    clock.fetch_add(LOOKUP_RATE_WINDOW_MS, Ordering::SeqCst);
    t.record_incoming_blocking(41000, None, TrafficKind::AiRequest);
    assert_eq!(probe.count(), LOOKUP_RATE_MAX + 1);
}

#[test]
fn rate_limited_connections_fall_back_to_user_agent() {
    let probe = FakeProbe::answering(LSOF_CLAUDE);
    let (_, t) = tracker(Arc::clone(&probe));
    for port in 40000..40000 + LOOKUP_RATE_MAX as u16 {
        t.record_incoming_blocking(port, None, TrafficKind::AiRequest);
    }
    // Over the limit: no process lookup, the UA still identifies the app.
    t.record_incoming_blocking(
        41000,
        Some("Mozilla/5.0 Chrome/120 Safari/537"),
        TrafficKind::AiRequest,
    );
    assert_eq!(probe.count(), LOOKUP_RATE_MAX);
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "browsers").ai_requests, 1);
}

#[test]
fn a_lookup_in_flight_is_not_started_twice() {
    let probe = FakeProbe::answering(LSOF_CLAUDE);
    let (_, t) = tracker(Arc::clone(&probe));
    assert!(matches!(
        t.prepare(50000, None, TrafficKind::AiRequest),
        Step::Lookup
    ));
    assert!(matches!(
        t.prepare(50000, None, TrafficKind::AiRequest),
        Step::Done
    ));
    assert_eq!(probe.count(), 0);
}

// ----- status transitions and TTL --------------------------------------------------------------

#[test]
fn confirmation_expires_after_the_ttl() {
    let (clock, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.seed_wifi_pac("http://127.0.0.1:8899/proxy.pac", true);
    t.record_hit("Google Chrome Helper", None);

    let status = |t: &CoverageTracker| {
        app(
            &t.snapshot(&rig.env(PacSource::Services, false), true),
            "browsers",
        )
        .status
    };
    assert_eq!(status(&t), CoverageStatus::Confirmed);
    clock.fetch_add(CONFIRM_TTL_MS - 60_000, Ordering::SeqCst);
    assert_eq!(status(&t), CoverageStatus::Confirmed);
    clock.fetch_add(120_000, Ordering::SeqCst);
    // The traffic is old; the OS still hands out our PAC.
    assert_eq!(status(&t), CoverageStatus::Configured);
    // A fresh request confirms again.
    t.record_hit("Google Chrome Helper", None);
    assert_eq!(status(&t), CoverageStatus::Confirmed);
}

#[test]
fn stale_confirmation_without_a_readable_fact_is_unknown() {
    let (clock, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    t.record_hit("Claude", None);
    clock.fetch_add(CONFIRM_TTL_MS + 1, Ordering::SeqCst);
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let claude = app(&snap, "claude-desktop");
    assert_eq!(claude.status, CoverageStatus::Unknown);
    assert!(claude.installed);
    assert_eq!(claude.ai_requests, 1);
}

#[test]
fn not_installed_app_is_reported_as_such() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let cursor = app(&snap, "cursor");
    assert_eq!(cursor.status, CoverageStatus::NotInstalled);
    assert!(!cursor.installed);
    assert!(cursor.manual_steps.is_empty());
    assert_eq!(
        app(&snap, "claude-code").status,
        CoverageStatus::NotInstalled
    );
}

// ----- browsers / desktop: PAC read from the OS ------------------------------------------------

#[test]
fn browser_is_configured_only_when_the_os_pac_is_ours() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.seed_wifi_pac("http://127.0.0.1:8899/proxy.pac", true);
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let b = app(&snap, "browsers");
    assert_eq!(b.status, CoverageStatus::Configured);
    assert!(b.manual_steps.is_empty());
    assert_eq!(b.ai_requests, 0);
}

#[test]
fn browser_with_a_foreign_or_disabled_pac_is_off() {
    for (url, enabled) in [
        ("http://corp.example/wpad.pac", true),
        ("http://127.0.0.1:18899/proxy.pac", true),
        ("http://127.0.0.1:8899/proxy.pac", false),
    ] {
        let (_, t) = tracker(FakeProbe::failing());
        t.set_gateway_addr(gw(8899));
        let rig = Rig::new();
        rig.seed_wifi_pac(url, enabled);
        let snap = t.snapshot(&rig.env(PacSource::Services, true), true);
        let b = app(&snap, "browsers");
        assert_eq!(b.status, CoverageStatus::Off, "{url} {enabled}");
        assert_eq!(b.manual_steps, vec!["enable_protection".to_string()]);
    }
}

#[test]
fn unreadable_pac_is_unknown_not_configured() {
    // The service list cannot be read.
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.seed_wifi_pac("http://127.0.0.1:8899/proxy.pac", true);
    rig.platform.fail_next(PlatOp::ListServices);
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let b = app(&snap, "browsers");
    assert_eq!(b.status, CoverageStatus::Unknown);
    assert!(b.manual_steps.contains(&"set_pac_url".to_string()));

    // One service cannot be read and the others do not match.
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.seed_wifi_pac("http://other/proxy.pac", true);
    rig.platform.fail_next(PlatOp::GetPac);
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Unknown);

    // No network service at all.
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Unknown);
}

#[test]
fn gateway_not_known_yet_is_unknown() {
    let (_, t) = tracker(FakeProbe::failing());
    let rig = Rig::new();
    rig.seed_wifi_pac("http://127.0.0.1:8899/proxy.pac", true);
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Unknown);
    assert_eq!(snap.gateway_addr, None);
    assert_eq!(snap.pac_url, None);
}

#[test]
fn windows_style_pac_is_read_from_inet() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8900));
    let rig = Rig::new();
    rig.platform.seed_inet(
        "AutoConfigURL",
        RegValue::sz("http://127.0.0.1:8900/proxy.pac"),
    );
    let snap = t.snapshot(&rig.env(PacSource::Inet, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Configured);

    let rig = Rig::new();
    rig.platform.seed_inet(
        "AutoConfigURL",
        RegValue::sz("http://127.0.0.1:8899/proxy.pac"),
    );
    let snap = t.snapshot(&rig.env(PacSource::Inet, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Off);

    let rig = Rig::new();
    rig.platform.fail_next(PlatOp::GetInet);
    let snap = t.snapshot(&rig.env(PacSource::Inet, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Unknown);

    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Inet, false), true);
    assert_eq!(app(&snap, "browsers").status, CoverageStatus::Off);
}

// ----- IDE: http.proxy and nothing else --------------------------------------------------------

#[test]
fn ide_without_http_proxy_is_not_configured_even_with_the_cli_layer_on() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    make_editor(&rig.fs, "Cursor", Some("{ \"editor.fontSize\": 14 }"));
    rig.seed_wifi_pac("http://127.0.0.1:8899/proxy.pac", true);
    // CLI layer on AND the system PAC is ours: still not a fact about the IDE.
    let snap = t.snapshot(&rig.env(PacSource::Services, true), true);
    let cursor = app(&snap, "cursor");
    assert_eq!(cursor.status, CoverageStatus::Off);
    assert!(cursor.installed);
    assert!(cursor.manual_steps.contains(&"set_http_proxy".to_string()));
}

#[test]
fn ide_settings_file_missing_is_off() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    make_editor(&rig.fs, "Cursor", None);
    let snap = t.snapshot(&rig.env(PacSource::Services, true), true);
    assert_eq!(app(&snap, "cursor").status, CoverageStatus::Off);
}

#[test]
fn ide_is_configured_when_http_proxy_points_at_the_gateway_port() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    make_editor(
        &rig.fs,
        "Code",
        Some(
            "// comment\n{\n  \"http.proxy\": \"http://127.0.0.1:8899\", /* x */\n  \"a\": 1,\n}\n",
        ),
    );
    make_editor(
        &rig.fs,
        "Windsurf",
        Some("{\"http.proxy\": \"http://127.0.0.1:7890\"}"),
    );
    make_editor(
        &rig.fs,
        "Antigravity",
        Some("{\"http.proxy\": \"http://127.0.0.1:18899\"}"),
    );
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "vscode").status, CoverageStatus::Configured);
    assert!(app(&snap, "vscode").manual_steps.is_empty());
    // Somebody else's proxy and a lookalike port are not ours.
    assert_eq!(app(&snap, "windsurf").status, CoverageStatus::Off);
    assert_eq!(app(&snap, "antigravity").status, CoverageStatus::Off);
}

#[test]
fn ide_port_follows_the_real_gateway_port() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8900));
    let rig = Rig::new();
    make_editor(
        &rig.fs,
        "Cursor",
        Some("{\"http.proxy\": \"http://127.0.0.1:8899\"}"),
    );
    make_editor(
        &rig.fs,
        "Code",
        Some("{\"http.proxy\": \"http://localhost:8900\"}"),
    );
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&snap, "cursor").status, CoverageStatus::Off);
    assert_eq!(app(&snap, "vscode").status, CoverageStatus::Configured);
}

#[test]
fn ide_with_a_broken_settings_file_is_unknown() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    make_editor(&rig.fs, "Cursor", Some("{ this is not json"));
    let snap = t.snapshot(&rig.env(PacSource::Services, true), true);
    assert_eq!(app(&snap, "cursor").status, CoverageStatus::Unknown);
}

#[test]
fn http_proxy_value_matching() {
    assert!(proxy_value_targets_gateway("http://127.0.0.1:8899", 8899));
    assert!(proxy_value_targets_gateway("http://127.0.0.1:8899/", 8899));
    assert!(proxy_value_targets_gateway("127.0.0.1:8899", 8899));
    assert!(proxy_value_targets_gateway("http://localhost:8899", 8899));
    assert!(!proxy_value_targets_gateway("http://127.0.0.1:18899", 8899));
    assert!(!proxy_value_targets_gateway("http://127.0.0.1:7890", 8899));
    assert!(!proxy_value_targets_gateway(
        "http://proxy.example:8899",
        8899
    ));
    assert!(!proxy_value_targets_gateway("", 8899));
    assert!(!proxy_value_targets_gateway("garbage", 8899));
}

// ----- JetBrains -------------------------------------------------------------------------------

const JB_XML: &str = "<application>\n  <component name=\"HttpConfigurable\">\n    \
    <option name=\"USE_HTTP_PROXY\" value=\"true\" />\n    \
    <option name=\"PROXY_HOST\" value=\"127.0.0.1\" />\n    \
    <option name=\"PROXY_PORT\" value=\"8899\" />\n  </component>\n</application>\n";

#[test]
fn jetbrains_is_unknown_by_default_with_manual_steps() {
    assert!(!JETBRAINS_XML_CONFIRMED);
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.fs
        .create_private_dir_all(&editor_root().join("JetBrains"))
        .unwrap();
    // Even a settings file that "looks right" is not trusted until the format is confirmed.
    rig.fs.put(
        &editor_root()
            .join("JetBrains")
            .join("PyCharm2025.1")
            .join("options")
            .join("proxy.settings.xml"),
        JB_XML.as_bytes(),
        0o600,
    );
    let snap = t.snapshot(&rig.env(PacSource::Services, true), true);
    let jb = app(&snap, "jetbrains");
    assert!(jb.installed);
    assert_eq!(jb.status, CoverageStatus::Unknown);
    assert_eq!(
        jb.manual_steps,
        vec![
            "jetbrains_proxy_settings".to_string(),
            "set_pac_url".to_string(),
            "set_http_proxy".to_string()
        ]
    );
}

#[test]
fn jetbrains_xml_is_read_only_when_the_format_is_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("support");
    let options = root.join("JetBrains").join("PyCharm2025.1").join("options");
    std::fs::create_dir_all(&options).unwrap();
    let ctx = FileCtx::new(Arc::new(RealFs), dir.path().join("home"), vec![root]);

    // No file: nothing to read -> unknown.
    let (st, _, _) = jetbrains_fact(Some(&ctx), Some(gw(8899)), true);
    assert_eq!(st, CoverageStatus::Unknown);

    std::fs::write(options.join("proxy.settings.xml"), JB_XML).unwrap();
    let (st, steps, _) = jetbrains_fact(Some(&ctx), Some(gw(8899)), true);
    assert_eq!(st, CoverageStatus::Configured);
    assert!(steps.is_empty());
    // Wrong port: off, with steps.
    let (st, steps, _) = jetbrains_fact(Some(&ctx), Some(gw(8900)), true);
    assert_eq!(st, CoverageStatus::Off);
    assert!(!steps.is_empty());
    // Flag off: the same file changes nothing.
    let (st, _, _) = jetbrains_fact(Some(&ctx), Some(gw(8899)), false);
    assert_eq!(st, CoverageStatus::Unknown);

    // PAC variant.
    let pac_xml = "<application><component name=\"HttpConfigurable\">\
        <option name=\"USE_PROXY_PAC\" value=\"true\" />\
        <option name=\"PAC_URL\" value=\"http://127.0.0.1:8899/proxy.pac\" />\
        </component></application>";
    std::fs::write(options.join("proxy.settings.xml"), pac_xml).unwrap();
    let (st, _, _) = jetbrains_fact(Some(&ctx), Some(gw(8899)), true);
    assert_eq!(st, CoverageStatus::Configured);
    let (st, _, _) = jetbrains_fact(Some(&ctx), Some(gw(8900)), true);
    assert_eq!(st, CoverageStatus::Off);
}

// ----- CLI -------------------------------------------------------------------------------------

#[test]
fn cli_follows_the_protection_layer_and_asks_for_a_new_terminal() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    let on = t.snapshot(&rig.env(PacSource::Services, true), true);
    let curl = app(&on, "curl");
    assert_eq!(curl.status, CoverageStatus::Configured);
    assert!(curl.manual_steps.contains(&"reopen_terminal".to_string()));
    let off = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(app(&off, "curl").status, CoverageStatus::Off);
}

// ----- snapshot shape --------------------------------------------------------------------------

#[test]
fn snapshot_carries_the_real_gateway_address() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8900));
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    assert_eq!(snap.gateway_addr.as_deref(), Some("127.0.0.1:8900"));
    assert_eq!(
        snap.pac_url.as_deref(),
        Some("http://127.0.0.1:8900/proxy.pac")
    );
    assert_eq!(snap.generated_at_ms, 10_000_000);
    assert!(snap.sysproxy_enabled);
}

#[test]
fn status_serializes_in_snake_case() {
    let all = [
        (CoverageStatus::Confirmed, "\"confirmed\""),
        (CoverageStatus::Configured, "\"configured\""),
        (CoverageStatus::Unknown, "\"unknown\""),
        (CoverageStatus::Off, "\"off\""),
        (CoverageStatus::NotInstalled, "\"not_installed\""),
    ];
    for (s, text) in all {
        assert_eq!(serde_json::to_string(&s).unwrap(), text);
    }
}

#[test]
fn item_json_has_the_contract_fields() {
    let (_, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    t.record_incoming_blocking(1, Some("curl/8"), TrafficKind::AiRequest);
    let rig = Rig::new();
    let snap = t.snapshot(&rig.env(PacSource::Services, false), true);
    let v = serde_json::to_value(&snap).unwrap();
    for key in ["apps", "gateway_addr", "pac_url", "generated_at_ms"] {
        assert!(v.get(key).is_some(), "{key}");
    }
    let curl = v["apps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "curl")
        .unwrap();
    for key in [
        "id",
        "name",
        "status",
        "last_seen_ms",
        "ai_requests",
        "pac_fetches",
        "manual_steps",
    ] {
        assert!(curl.get(key).is_some(), "{key}");
    }
    assert_eq!(curl["status"], "confirmed");
}

#[test]
fn facts_are_cached_briefly_and_a_recheck_bypasses_the_cache() {
    let (clock, t) = tracker(FakeProbe::failing());
    t.set_gateway_addr(gw(8899));
    let rig = Rig::new();
    rig.seed_wifi_pac("http://127.0.0.1:8899/proxy.pac", true);
    let env = rig.env(PacSource::Services, false);

    t.snapshot(&env, false);
    let after_first = rig.platform.calls().len();
    assert!(after_first > 0);
    t.snapshot(&env, false);
    assert_eq!(
        rig.platform.calls().len(),
        after_first,
        "served from the cache"
    );
    t.snapshot(&env, true);
    assert!(
        rig.platform.calls().len() > after_first,
        "forced re-check reads the OS"
    );
    let after_forced = rig.platform.calls().len();
    clock.fetch_add(FACTS_TTL_MS + 1, Ordering::SeqCst);
    t.snapshot(&env, false);
    assert!(rig.platform.calls().len() > after_forced, "cache expired");
}

#[test]
fn installed_check_uses_only_the_given_file_system() {
    let rig = Rig::new();
    assert!(!check_app_installed_in("claude-code", &rig.ctx));
    rig.fs
        .create_private_dir_all(&home().join(".claude"))
        .unwrap();
    assert!(check_app_installed_in("claude-code", &rig.ctx));
    assert!(!check_app_installed_in("cursor", &rig.ctx));
    make_editor(&rig.fs, "Cursor", None);
    assert!(check_app_installed_in("cursor", &rig.ctx));
    assert!(check_app_installed_in("browsers", &rig.ctx));
    assert!(!check_app_installed_in("no-such-app", &rig.ctx));
}
