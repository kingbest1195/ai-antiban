use super::super::*;
use super::*;
use std::sync::atomic::Ordering;

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
    assert_eq!(
        classify_process_name("Google Chrome Helper (Renderer)"),
        "browsers"
    );
    assert_eq!(classify_process_name("Safari"), "browsers");
    assert_eq!(classify_process_name("Arc"), "browsers");
    assert_eq!(classify_process_name("Arc Helper"), "browsers");
    assert_eq!(classify_process_name("msedge.exe"), "browsers");
    assert_eq!(classify_process_name("Microsoft Edge Helper"), "browsers");
    assert_eq!(classify_process_name("Яндекс Браузер"), "browsers");
    assert_eq!(classify_process_name("YandexBrowser"), "browsers");
    assert_eq!(classify_process_name("Yandex Helper"), "browsers");
    assert_eq!(classify_process_name("Firefox"), "browsers");
    assert_eq!(classify_process_name("Brave Browser Helper"), "browsers");
    assert_eq!(classify_process_name("Comet"), "browsers");
    assert_eq!(classify_process_name("Comet Helper"), "browsers");
    assert_eq!(classify_process_name("Comet Helper (Renderer)"), "browsers");
    assert_eq!(classify_process_name("comet.exe"), "browsers");
    assert_eq!(classify_process_name("Opera"), "browsers");
    assert_eq!(classify_process_name("Opera GX"), "browsers");
    assert_eq!(classify_process_name("Opera Helper"), "browsers");
    assert_eq!(classify_process_name("opera.exe"), "browsers");
    assert_eq!(classify_process_name("Dia"), "browsers");
    assert_eq!(classify_process_name("Dia Helper"), "browsers");
    assert_eq!(classify_process_name("ChatGPT Atlas"), "browsers");
    assert_eq!(classify_process_name("ChatGPT Atlas Helper"), "browsers");
    assert_eq!(classify_process_name("Atlas"), "browsers");
    assert_eq!(classify_process_name("Zen"), "browsers");
    assert_eq!(classify_process_name("Zen Browser"), "browsers");
    assert_eq!(classify_process_name("Zen Helper"), "browsers");
    assert_eq!(classify_process_name("Waterfox"), "browsers");
    assert_eq!(classify_process_name("waterfox.exe"), "browsers");
    assert_eq!(classify_process_name("Vivaldi"), "browsers");
    assert_eq!(classify_process_name("Vivaldi Helper"), "browsers");
    assert_eq!(classify_process_name("claude-code"), "claude-code");
    assert_eq!(classify_process_name("gemini"), "gemini-cli");
    assert_eq!(classify_process_name("opencode"), "opencode");
    assert_eq!(classify_process_name("opencode.exe"), "opencode");
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
    // new browser names must not match substrings inside unrelated processes
    assert_eq!(classify_process_name("media-daemon"), "other");
    assert_eq!(classify_process_name("diagram"), "other");
    assert_eq!(classify_process_name("operator"), "other");
    assert_eq!(classify_process_name("atlassian-helper"), "other");
    assert_eq!(classify_process_name("zenith"), "other");
    assert_eq!(classify_process_name("citizen"), "other");
    assert_eq!(classify_process_name("comets"), "other");
    assert_eq!(classify_process_name("archer"), "other");
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
