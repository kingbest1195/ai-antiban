use super::*;
use crate::auditor::geo_matrix::CheckStatus;
use port::{BinLookupError, BinLookupFuture, BinLookupPort, RawBinInfo};
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct MockLookupPort {
    calls: AtomicUsize,
    outcome: Result<RawBinInfo, BinLookupError>,
}

impl MockLookupPort {
    fn ok(info: RawBinInfo) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            outcome: Ok(info),
        })
    }

    fn err(err: BinLookupError) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            outcome: Err(err),
        })
    }
}

impl BinLookupPort for MockLookupPort {
    fn lookup<'a>(&'a self, _bin_prefix: &'a str) -> BinLookupFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let res = self.outcome.clone();
        Box::pin(async move { res })
    }
}

async fn spawn_http_once(status_line: &str, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status_line.to_string();
    let payload = body.to_string();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn overlay_takes_priority_over_external_api_for_curated_fintech_bins() {
    let port = MockLookupPort::err(BinLookupError::HttpStatus(500));
    let checker = BinChecker::with_port(port.clone());

    let redot = checker
        .check_bin_report_with_cache_dir("40403812", Some("US"), None)
        .await
        .unwrap();
    assert_eq!(redot.country_code.as_deref(), Some("HK"));
    assert_eq!(redot.source, BinSource::LocalOverlay);
    assert_eq!(redot.status, CheckStatus::Critical);
    assert_eq!(redot.claude_web_verdict, ClaudeWebVerdict::Blocked);
    assert_eq!(redot.is_prepaid, Some(true));

    let bybit_gb = checker
        .check_bin_report_with_cache_dir("485953", Some("GB"), None)
        .await
        .unwrap();
    assert_eq!(bybit_gb.country_code.as_deref(), Some("GB"));
    assert_eq!(bybit_gb.scheme.as_deref(), Some("MASTERCARD"));
    assert_eq!(bybit_gb.funding, CardFunding::Debit);
    assert_eq!(bybit_gb.status, CheckStatus::Ok);
    assert_eq!(bybit_gb.claude_web_verdict, ClaudeWebVerdict::SafeAligned);

    let etherfi = checker
        .check_bin_report_with_cache_dir("454924", Some("PR"), None)
        .await
        .unwrap();
    assert_eq!(etherfi.country_code.as_deref(), Some("PR"));
    assert_eq!(etherfi.funding, CardFunding::Credit);
    assert_eq!(etherfi.source, BinSource::LocalOverlay);

    let nium_sg = checker
        .check_bin_report_with_cache_dir("493724", Some("DE"), None)
        .await
        .unwrap();
    assert_eq!(nium_sg.country_code.as_deref(), Some("SG"));
    assert_eq!(nium_sg.is_prepaid, Some(true));
    assert_eq!(nium_sg.is_commercial, Some(true));
    assert_eq!(nium_sg.status, CheckStatus::Critical);
    assert_eq!(nium_sg.claude_web_verdict, ClaudeWebVerdict::HighKycRisk);

    let plati = checker
        .check_bin_report_with_cache_dir("446614", Some("US"), None)
        .await
        .unwrap();
    assert_eq!(plati.country_code.as_deref(), Some("US"));
    assert_eq!(plati.is_commercial, Some(true));
    assert_eq!(plati.status, CheckStatus::Warning);
    assert_eq!(
        plati.claude_web_verdict,
        ClaudeWebVerdict::NeedsMatchingIpBilling
    );

    let antarctic_mir = checker
        .check_bin_report_with_cache_dir("220441", Some("NL"), None)
        .await
        .unwrap();
    assert_eq!(antarctic_mir.country_code.as_deref(), Some("RU"));
    assert_eq!(antarctic_mir.claude_web_verdict, ClaudeWebVerdict::Blocked);
    assert!(
        antarctic_mir
            .known_fintech_label
            .as_deref()
            .unwrap_or("")
            .contains("Antarctic Wallet")
    );

    for (bin, expected_cc) in [
        ("440043", "KZ"),
        ("439087", "KZ"),
        ("422970", "KG"),
        ("416958", "KG"),
        ("409986", "AM"),
        ("426696", "GE"),
        ("424290", "GE"),
        ("406218", "UZ"),
        ("537349", "GB"),
        ("537872", "LT"),
        ("474447", "HK"),
        ("220012", "RU"),
        ("911234", "BY"),
    ] {
        let r = checker
            .check_bin_report_with_cache_dir(bin, Some(expected_cc), None)
            .await
            .unwrap();
        assert_eq!(r.country_code.as_deref(), Some(expected_cc), "BIN {bin}");
        assert_eq!(r.source, BinSource::LocalOverlay, "BIN {bin}");
    }

    // External API must NEVER be called for BINs present in overlay
    assert_eq!(port.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn overlay_priority_8_digit_beats_6_digit_beats_range() {
    let json = r#"{
      "prefixes": [
        {
          "prefix": "493724",
          "scheme": "VISA",
          "funding": "prepaid",
          "country_code": "SG",
          "issuer_name": "Generic 6",
          "claude_web_verdict": "highKycRisk"
        },
        {
          "prefix": "49372401",
          "scheme": "VISA",
          "funding": "debit",
          "country_code": "US",
          "issuer_name": "Specific 8",
          "claude_web_verdict": "safeAligned"
        }
      ],
      "ranges": [
        {
          "start": "4937",
          "end": "4938",
          "scheme": "VISA",
          "funding": "credit",
          "country_code": "GB",
          "issuer_name": "Range 4",
          "claude_web_verdict": "needsMatchingIpBilling"
        }
      ]
    }"#;
    let overlay = BinOverlay::from_json(json).unwrap();
    assert_eq!(
        overlay
            .lookup("49372401")
            .unwrap()
            .report
            .issuer_name
            .as_deref(),
        Some("Specific 8")
    );
    assert_eq!(
        overlay
            .lookup("49372499")
            .unwrap()
            .report
            .issuer_name
            .as_deref(),
        Some("Generic 6")
    );
    assert_eq!(
        overlay
            .lookup("493800")
            .unwrap()
            .report
            .issuer_name
            .as_deref(),
        Some("Range 4")
    );
}

#[test]
fn strict_prefix_validation_rejects_over_8_under_6_and_non_ascii_without_echo() {
    assert_eq!(validate_strict_bin_prefix("411111").unwrap(), "411111");
    assert_eq!(validate_strict_bin_prefix("41111122").unwrap(), "41111122");

    for bad in [
        "12345",
        "411111223",
        "4111 1122",
        "411111abc",
        "٤١١١١١",
        "4111222233334444",
    ] {
        let err = validate_strict_bin_prefix(bad).unwrap_err();
        assert!(!err.contains(bad), "error must not echo raw input");
        assert_clean_bin_validation_error(&err);
    }

    // sanitize_bin accepts space/hyphen formatting up to 8 digits and rejects >8 or letters
    assert_eq!(BinChecker::sanitize_bin("4111 1122").unwrap(), "41111122");
    assert_eq!(BinChecker::sanitize_bin("4111-112").unwrap(), "4111112");
    let bad_chars = BinChecker::sanitize_bin("411111abc").unwrap_err();
    assert_clean_bin_validation_error(&bad_chars);
    let over8 = BinChecker::sanitize_bin("4111 2222 3333 4444").unwrap_err();
    assert!(over8.contains("Для безопасности"));
    assert!(over8.contains("6–8"));
    assert!(!over8.contains("4444"));
    assert_clean_bin_validation_error(&over8);
}

fn assert_clean_bin_validation_error(err: &str) {
    for forbidden in ["!", "BIN", "ISO", "(For your privacy)", "НЕ "] {
        assert!(
            !err.contains(forbidden),
            "error must not contain '{forbidden}': {err}"
        );
    }
}

#[tokio::test]
async fn fail_closed_returns_unknown_on_network_timeout_429_and_not_found() {
    for err in [
        BinLookupError::Timeout,
        BinLookupError::Network("connection reset".into()),
        BinLookupError::HttpStatus(429),
        BinLookupError::HttpStatus(503),
        BinLookupError::NotFound,
        BinLookupError::InvalidPayload("eof".into()),
    ] {
        let port = MockLookupPort::err(err);
        let checker = BinChecker::with_port(port);
        let report = checker
            .check_bin_report_with_cache_dir("411111", Some("US"), None)
            .await
            .unwrap();
        assert_eq!(report.status, CheckStatus::Unknown);
        assert_ne!(report.status, CheckStatus::Ok);
        assert_eq!(report.source, BinSource::FallbackUnknown);
        assert_eq!(report.funding, CardFunding::Unknown);
        assert!(!report.warnings.is_empty());
        assert!(report.warnings[0].contains("Не удалось проверить первые цифры карты"));
        for w in &report.warnings {
            assert_no_banned_jargon(w);
        }
    }
}

#[tokio::test]
async fn seven_day_ttl_cache_reuses_and_expires_and_skips_unknown() {
    let tmp = TempDir::new().unwrap();
    let cache = cache::BinCache::in_dir(tmp.path());

    // FallbackUnknown must never be cached
    let unknown_report = fail_closed_report("411111".into(), BinLookupError::Timeout);
    cache.put_at(&unknown_report, 1_000_000);
    assert!(cache.get_at("411111", 1_000_010).is_none());

    // Valid ProxyApi lookup is cached for 7 days and re-evaluates VPN country
    let port = MockLookupPort::ok(RawBinInfo {
        scheme: Some("VISA".into()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: Some(false),
        card_category: Some("CLASSIC".into()),
        country_code: Some("US".into()),
        issuer_name: Some("JPMorgan Chase".into()),
        source: BinSource::ProxyApi,
    });
    let checker = BinChecker::with_port(port.clone());
    let first = checker
        .check_bin_report_with_cache_dir("411111", Some("US"), Some(tmp.path()))
        .await
        .unwrap();
    assert_eq!(first.source, BinSource::ProxyApi);
    assert_eq!(first.status, CheckStatus::Ok);
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);

    let second = checker
        .check_bin_report_with_cache_dir("411111", Some("DE"), Some(tmp.path()))
        .await
        .unwrap();
    assert_eq!(second.source, BinSource::Cache);
    assert_eq!(second.status, CheckStatus::Warning);
    assert_eq!(
        second.claude_web_verdict,
        ClaudeWebVerdict::NeedsMatchingIpBilling
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);

    // Expired after 7 days (604_800 seconds)
    let now = 2_000_000;
    let fresh_report = BinReport {
        bin_prefix: "512345".into(),
        status: CheckStatus::Ok,
        scheme: Some("MASTERCARD".into()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: None,
        card_category: None,
        country_code: Some("NL".into()),
        issuer_name: Some("ING".into()),
        known_fintech_label: None,
        source: BinSource::FallbackPublicApi,
        claude_web_verdict: ClaudeWebVerdict::SafeAligned,
        warnings: vec![],
    };
    cache.put_at(&fresh_report, now);
    assert!(
        cache
            .get_at("512345", now + cache::BIN_CACHE_TTL_SECS - 1)
            .is_some()
    );
    assert!(
        cache
            .get_at("512345", now + cache::BIN_CACHE_TTL_SECS)
            .is_none()
    );
}

#[tokio::test]
async fn http_adapter_supports_proxy_api_handy_fallback_and_429_fail_closed() {
    let proxy_url = spawn_http_once(
        "200 OK",
        r#"{"valid":true,"country-code":"US","card-brand":"VISA","card-type":"DEBIT","card-category":"CLASSIC","issuer":"Chase","is-prepaid":false,"is-commercial":false}"#,
    )
    .await;
    let proxy_adapter = Arc::new(http_adapter::HttpBinLookupAdapter::with_endpoints(
        Some(format!("{proxy_url}/{{bin}}")),
        "http://127.0.0.1:1".into(),
        1000,
    ));
    let checker_proxy = BinChecker::with_port(proxy_adapter);
    let r1 = checker_proxy
        .check_bin_report_with_cache_dir("411111", Some("US"), None)
        .await
        .unwrap();
    assert_eq!(r1.source, BinSource::ProxyApi);
    assert_eq!(r1.status, CheckStatus::Ok);
    assert_eq!(r1.country_code.as_deref(), Some("US"));

    let handy_url = spawn_http_once(
        "200 OK",
        r#"{"Status":"SUCCESS","Scheme":"VISA","Type":"DEBIT","Country":{"A2":"NL"},"Issuer":"Rabobank","CardTier":"CLASSIC"}"#,
    )
    .await;
    let handy_adapter = Arc::new(http_adapter::HttpBinLookupAdapter::with_endpoints(
        None, handy_url, 1000,
    ));
    let checker_handy = BinChecker::with_port(handy_adapter);
    let r2 = checker_handy
        .check_bin_report_with_cache_dir("411111", Some("NL"), None)
        .await
        .unwrap();
    assert_eq!(r2.source, BinSource::FallbackPublicApi);
    assert_eq!(r2.status, CheckStatus::Ok);

    let rate_limit_url =
        spawn_http_once("429 Too Many Requests", r#"{"error":"rate limit"}"#).await;
    let rl_adapter = Arc::new(http_adapter::HttpBinLookupAdapter::with_endpoints(
        None,
        rate_limit_url,
        1000,
    ));
    let checker_rl = BinChecker::with_port(rl_adapter);
    let r3 = checker_rl
        .check_bin_report_with_cache_dir("411111", Some("NL"), None)
        .await
        .unwrap();
    assert_eq!(r3.status, CheckStatus::Unknown);
    assert_eq!(r3.source, BinSource::FallbackUnknown);
}

#[test]
fn bin_report_serializes_as_camel_case() {
    let report = fail_closed_report("411111".into(), BinLookupError::NotFound);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["binPrefix"], "411111");
    assert_eq!(json["source"], "fallbackUnknown");
    assert_eq!(json["claudeWebVerdict"], "highKycRisk");
    assert_eq!(json["status"], "unknown");
    assert!(json.get("bin_prefix").is_none());
}

#[tokio::test]
async fn incomplete_handy_api_success_without_country_fails_closed_to_unknown() {
    for body in [
        r#"{"Status":"SUCCESS"}"#,
        r#"{"Status":"SUCCESS","Issuer":"Mystery Bank"}"#,
        r#"{"Status":"SUCCESS","Country":{"A2":""},"Type":""}"#,
    ] {
        let url = spawn_http_once("200 OK", body).await;
        let adapter = Arc::new(http_adapter::HttpBinLookupAdapter::with_endpoints(
            None, url, 1000,
        ));
        let checker = BinChecker::with_port(adapter);
        let report = checker
            .check_bin_report_with_cache_dir("411111", Some("US"), None)
            .await
            .unwrap();
        assert_eq!(report.status, CheckStatus::Unknown, "body={body}");
        assert_eq!(report.source, BinSource::FallbackUnknown, "body={body}");
        assert_eq!(report.is_prepaid, None, "body={body}");
        assert_ne!(
            report.claude_web_verdict,
            ClaudeWebVerdict::SafeAligned,
            "body={body}"
        );
    }
}

#[tokio::test]
async fn raw_info_without_country_never_evaluates_ok_or_safe_aligned() {
    let port = MockLookupPort::ok(RawBinInfo {
        scheme: Some("VISA".into()),
        funding: CardFunding::Debit,
        is_prepaid: Some(false),
        is_commercial: Some(false),
        is_reloadable: None,
        card_category: Some("CLASSIC".into()),
        country_code: None,
        issuer_name: Some("No Country Bank".into()),
        source: BinSource::FallbackPublicApi,
    });
    let checker = BinChecker::with_port(port);
    let report = checker
        .check_bin_report_with_cache_dir("411111", Some("US"), None)
        .await
        .unwrap();
    assert_eq!(report.status, CheckStatus::Unknown);
    assert_ne!(report.claude_web_verdict, ClaudeWebVerdict::SafeAligned);
}

fn assert_no_banned_jargon(text: &str) {
    let lower = text.to_lowercase();
    for term in [
        "payshield",
        "stripe",
        "bin-рентген",
        "финтех-bin",
        "fail-closed",
        "fallbackunknown",
        "persona",
        "kyc",
        "apple iap",
        "directcard",
        "биллинг",
        "чекаут",
        "split-ip",
        "is_pinned",
        "tainted",
        "webrtc",
        "stun",
        "пост-платёжный карантин",
        "vc.ru",
        "prepaid",
        "commercial",
        "business",
        "coworkvmservice",
    ] {
        assert!(!lower.contains(term), "banned term '{term}' in: {text}");
    }
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        assert!(
            !word.eq_ignore_ascii_case("bin") && !word.eq_ignore_ascii_case("asn"),
            "banned standalone acronym '{word}' in: {text}"
        );
    }
    for cc in [
        "SE", "DE", "SG", "US", "GB", "RU", "BY", "KZ", "HK", "KG", "AM", "GE", "UZ", "LT", "PR",
        "NL",
    ] {
        for (idx, _) in text.match_indices(cc) {
            let before_ok = idx == 0 || !text.as_bytes()[idx - 1].is_ascii_alphabetic();
            let after_ok = text
                .as_bytes()
                .get(idx + cc.len())
                .is_none_or(|b| !b.is_ascii_alphabetic());
            if before_ok && after_ok {
                let before = idx
                    .checked_sub(1)
                    .and_then(|i| text.as_bytes().get(i).copied());
                let after = text.as_bytes().get(idx + cc.len()).copied();
                assert!(
                    before == Some(b'(') && after == Some(b')'),
                    "bare country code '{cc}' outside parentheses in: {text}"
                );
            }
        }
    }
}

#[tokio::test]
async fn user_facing_warnings_and_advisory_contain_no_banned_jargon() {
    let checker = BinChecker::new();
    for (bin, vpn) in [
        ("220441", Some("DE")),
        ("40403812", Some("US")),
        ("493724", Some("DE")),
        ("446614", Some("DE")),
        ("485953", Some("SE")),
        ("537872", Some("NL")),
        ("454924", Some("US")),
        ("440043", Some("DE")),
        ("422970", Some("SG")),
        ("911234", Some("DE")),
    ] {
        let audit = checker.check_bin(bin, vpn).await.unwrap();
        assert_no_banned_jargon(&audit.advisory);
        for w in &audit.report.unwrap().warnings {
            assert_no_banned_jargon(w);
        }
    }
}
