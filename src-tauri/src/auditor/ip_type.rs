//! Kind of the exit address (hosting / residential / Tor / mass VPN / unknown) and the verdict of
//! the "address reputation" check built on it.
//!
//! Hosting is not a finding: a personal VPS is the normal setup of Zastava. Only a Tor exit and an
//! ASN of a mass-VPN pool give a warning. The Tor list is public data that is downloaded whole
//! (the exit address is never sent anywhere); when it cannot be loaded the check says so
//! (`Unknown`) instead of claiming "not Tor".

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::auditor::cache::TtlCache;
use crate::auditor::geo_matrix::{CheckResult, GUIDE_PERSONAL_VPN, UnknownReason};
use crate::auditor::rules::{DangerousAsns, NetworkKind};
use crate::auditor::seams::{HttpProbeOutcome, IpProbe};

/// Tor Project's list of the current exit addresses (one IPv4 per line, plain text).
pub const TOR_LIST_URL: &str = "https://check.torproject.org/torbulkexitlist";
/// Time limit of the list download.
pub const TOR_LIST_TIMEOUT: Duration = Duration::from_secs(3);
/// The list changes slowly; it is downloaded at most this often.
pub const TOR_LIST_TTL: Duration = Duration::from_secs(6 * 60 * 60);

/// What the interface reads from `CheckResult.detail.ip_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpType {
    Hosting,
    Residential,
    Tor,
    Vpn,
    Unknown,
}

impl IpType {
    /// Short Russian name for the texts of the check.
    pub fn label_ru(self) -> &'static str {
        match self {
            IpType::Hosting => "хостинг",
            IpType::Residential => "жилой или мобильный провайдер",
            IpType::Tor => "выход сети Tor",
            IpType::Vpn => "массовый VPN",
            IpType::Unknown => "не определён",
        }
    }
}

/// The set of Tor exit addresses (shared between audits).
pub type TorExitSet = Arc<HashSet<IpAddr>>;

/// The cached outcome of one list download.
pub type TorListCache = TtlCache<Result<TorExitSet, UnknownReason>>;

/// Whether the exit address is a Tor exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorLookup {
    Listed,
    NotListed,
    /// The list could not be loaded: nothing is known about Tor.
    Unavailable(UnknownReason),
    /// The list holds IPv4 addresses only.
    NotApplicable,
}

/// Addresses of a list body: blank lines, `#` comments and anything that is not an IP are skipped.
pub fn parse_tor_list(body: &str) -> HashSet<IpAddr> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.parse::<IpAddr>().ok())
        .collect()
}

/// Downloads and parses the list through `probe`.
pub async fn fetch_tor_list(probe: &dyn IpProbe) -> Result<TorExitSet, UnknownReason> {
    match probe.get(TOR_LIST_URL, TOR_LIST_TIMEOUT).await {
        HttpProbeOutcome::Response { status: 200, body } => {
            let set = parse_tor_list(&body);
            if set.is_empty() {
                // A captive portal or an error page: no list.
                Err(UnknownReason::EmptyResponse)
            } else {
                Ok(Arc::new(set))
            }
        }
        HttpProbeOutcome::Response { status: 403 | 429 | 451, .. } => Err(UnknownReason::SourceRefused),
        HttpProbeOutcome::Response { .. } | HttpProbeOutcome::ConnectFailed | HttpProbeOutcome::ReadFailed => {
            Err(UnknownReason::NetworkError)
        }
        HttpProbeOutcome::Timeout => Err(UnknownReason::Timeout),
        HttpProbeOutcome::ClientError => Err(UnknownReason::InternalError),
    }
}

/// Is `ip` a Tor exit? The list is cached for [`TOR_LIST_TTL`]; a failed download is retried
/// within seconds (see `TtlCache`), never remembered as "not Tor".
pub async fn lookup_tor(cache: &TorListCache, probe: &dyn IpProbe, ip: &str) -> TorLookup {
    let Ok(addr) = ip.trim().parse::<IpAddr>() else {
        return TorLookup::Unavailable(UnknownReason::NoData);
    };
    if addr.is_ipv6() {
        return TorLookup::NotApplicable;
    }
    let list = cache
        .get_or_compute("tor", TOR_LIST_TTL, |r| r.is_ok(), fetch_tor_list(probe))
        .await;
    match list {
        Ok(set) if set.contains(&addr) => TorLookup::Listed,
        Ok(_) => TorLookup::NotListed,
        Err(reason) => TorLookup::Unavailable(reason),
    }
}

/// What the check knows about the exit address.
pub struct ExitIdentity<'a> {
    pub ip: &'a str,
    /// Cloudflare marks Tor exits with the country code `T1`.
    pub country_code: &'a str,
    pub asn: Option<u32>,
    pub isp: Option<&'a str>,
    pub org: Option<&'a str>,
}

/// Kind of the exit address. Order of precedence: Tor, mass VPN, hosting, residential, unknown.
pub fn classify(asns: &DangerousAsns, id: &ExitIdentity, tor: TorLookup) -> IpType {
    if tor == TorLookup::Listed || id.country_code.trim().eq_ignore_ascii_case("T1") {
        return IpType::Tor;
    }
    let entry = id.asn.and_then(|n| asns.asn_entry(n));
    match entry.map(|e| e.kind) {
        Some(NetworkKind::Vpn) => return IpType::Vpn,
        Some(NetworkKind::Hosting) => return IpType::Hosting,
        _ => {}
    }
    // The names: hosting words are looked at first, so "Cloud Communications" is a hosting.
    for text in [id.isp, id.org].into_iter().flatten() {
        match asns.keyword_kind(text) {
            Some(NetworkKind::Vpn) => return IpType::Vpn,
            Some(NetworkKind::Hosting) => return IpType::Hosting,
            _ => {}
        }
    }
    for text in [id.isp, id.org].into_iter().flatten() {
        if asns.keyword_kind(text) == Some(NetworkKind::Residential) {
            return IpType::Residential;
        }
    }
    IpType::Unknown
}

/// Verdict of the address-reputation check (check number 5): who the address belongs to and what
/// kind of network it is.
pub fn evaluate_ip_reputation(
    id: &ExitIdentity,
    asns: &DangerousAsns,
    tor: TorLookup,
    is_pinned: bool,
) -> CheckResult {
    let isp_str = id.isp.unwrap_or_default();
    let org_str = id.org.unwrap_or_default();
    let ip_type = classify(asns, id, tor);
    let name = [isp_str.trim(), org_str.trim()].into_iter().find(|t| !t.is_empty());

    // 1. A domestic ISP of Russia: direct exit without a VPN.
    if let Some(matched_isp) = asns
        .matches_russian_isp(isp_str)
        .or_else(|| asns.matches_russian_isp(org_str))
    {
        return CheckResult::critical(
            "RUSSIAN_ISP_DETECTED",
            format!("Обнаружен домашний провайдер РФ ({matched_isp}). Прямой выход без VPN приведет к мгновенному бану аккаунта."),
            Some(GUIDE_PERSONAL_VPN.to_string()),
        )
        .with_ip_type(ip_type);
    }

    // 2. A Tor exit: pinning does not excuse it (a personal VPS is not a Tor exit).
    if ip_type == IpType::Tor {
        return CheckResult::warning(
            "IP_TYPE_TOR",
            "Адрес входит в список выходных узлов Tor. ИИ-сервисы часто блокируют такие адреса. Выберите свой сервер или другой VPN-адрес.",
            Some(GUIDE_PERSONAL_VPN.to_string()),
        )
        .with_ip_type(ip_type);
    }

    // 3. The user said this is their own server.
    if is_pinned {
        return CheckResult::ok(
            "ASN_VERIFIED_PINNED",
            "IP подтвержден и закреплен как ваш личный выделенный VPS.",
        )
        .with_ip_type(ip_type);
    }

    // 4. A pool of a mass VPN: many people share the address.
    if ip_type == IpType::Vpn {
        let (title, reason) = id
            .asn
            .and_then(|n| asns.asn_entry(n))
            .map(|e| (format!("«{}» (AS{})", e.name, e.asn), e.reason.clone()))
            .unwrap_or_else(|| (name.unwrap_or("сеть массового VPN").to_string(), String::new()));
        return CheckResult::warning(
            "HIGH_RISK_MASS_VPN_ASN",
            format!(
                "Адрес из пула, который часто используют многие люди: {title}. {reason} Если это ваш личный сервер, нажмите «Закрепить IP», чтобы убрать предупреждение."
            )
            .replace("  ", " "),
            Some(GUIDE_PERSONAL_VPN.to_string()),
        )
        .with_ip_type(ip_type);
    }

    // 5. Nothing to judge: the geolocation source gave neither ASN nor ISP/org.
    if id.asn.is_none() && name.is_none() {
        return CheckResult::unknown(
            "ASN_NO_DATA",
            "Тип адреса не определён: источник геолокации не передал ASN, провайдера и организацию.",
            UnknownReason::NoData,
        )
        .with_ip_type(IpType::Unknown);
    }

    let who = match (id.asn, name) {
        (Some(n), Some(name)) => format!("AS{n} ({name})"),
        (Some(n), None) => format!("AS{n}"),
        (None, Some(name)) => name.to_string(),
        (None, None) => unreachable!("handled above: no ASN and no name is Unknown"),
    };

    // 6. Not Tor can only be said with the list in hand.
    match tor {
        TorLookup::Unavailable(reason) => {
            return CheckResult::unknown(
                "TOR_LIST_UNAVAILABLE",
                format!(
                    "Не удалось проверить, не выход ли это сети Tor: список выходных узлов не загрузился. Тип адреса по провайдеру {who}: {}.",
                    ip_type.label_ru()
                ),
                reason,
            )
            .with_ip_type(ip_type);
        }
        TorLookup::NotApplicable => {
            return CheckResult::unknown(
                "IP_TYPE_IPV6_NOT_APPLICABLE",
                format!(
                    "Не применимо к IPv6: список выходных узлов Tor содержит только адреса IPv4, поэтому про Tor сказать нельзя. Тип адреса по провайдеру {who}: {}.",
                    ip_type.label_ru()
                ),
                UnknownReason::NotApplicable,
            )
            .with_ip_type(ip_type);
        }
        TorLookup::Listed | TorLookup::NotListed => {}
    }

    match ip_type {
        IpType::Hosting => CheckResult::ok(
            "IP_TYPE_HOSTING",
            format!(
                "Хостинг (ожидаемо для личного VPS): {who}. Это сервер, на котором работает ваш VPN; в списке выходов Tor и среди известных пулов массовых VPN адреса нет."
            ),
        ),
        IpType::Residential => CheckResult::ok(
            "IP_TYPE_RESIDENTIAL",
            format!(
                "Жилой или мобильный провайдер: {who} (определено по названию, это оценка). В списке выходов Tor и среди известных пулов массовых VPN адреса нет."
            ),
        ),
        _ => CheckResult::ok(
            "ASN_CLEAN",
            format!(
                "{who}: тип адреса определить не удалось. В списке выходов Tor и среди известных пулов массовых VPN адреса нет."
            ),
        ),
    }
    .with_ip_type(ip_type)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::geo_matrix::CheckStatus;
    use crate::auditor::seams::fakes::FakeProbe;

    const TOR_IP: &str = "203.0.113.50"; // TEST-NET-3, never a real address
    const OTHER_IP: &str = "203.0.113.9";
    const LIST: &str = "# exit list\n203.0.113.50\r\n\n203.0.113.51\nnot an ip\n";

    fn asns() -> DangerousAsns {
        DangerousAsns::load_bundled().unwrap()
    }

    fn id<'a>(ip: &'a str, asn: Option<u32>, isp: Option<&'a str>) -> ExitIdentity<'a> {
        ExitIdentity { ip, country_code: "NL", asn, isp, org: None }
    }

    fn list_probe() -> FakeProbe {
        FakeProbe::body(200, LIST)
    }

    async fn verdict(probe: &FakeProbe, ip: &str, asn: Option<u32>, isp: Option<&str>, pinned: bool) -> CheckResult {
        let cache = TorListCache::default();
        let tor = lookup_tor(&cache, probe, ip).await;
        evaluate_ip_reputation(&id(ip, asn, isp), &asns(), tor, pinned)
    }

    fn type_of(r: &CheckResult) -> Option<IpType> {
        r.detail.as_ref().and_then(|d| d.ip_type)
    }

    #[test]
    fn tor_list_parsing_skips_noise() {
        let set = parse_tor_list(LIST);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&TOR_IP.parse().unwrap()));
        assert!(parse_tor_list("<html>blocked</html>\n").is_empty());
    }

    #[tokio::test]
    async fn tor_exit_is_a_warning_even_on_a_hosting_asn_and_even_pinned() {
        let probe = list_probe();
        for pinned in [false, true] {
            let r = verdict(&probe, TOR_IP, Some(24940), Some("Hetzner Online GmbH"), pinned).await;
            assert_eq!((r.status, r.code.as_str()), (CheckStatus::Warning, "IP_TYPE_TOR"), "pinned={pinned}");
            assert_eq!(type_of(&r), Some(IpType::Tor));
        }
    }

    #[tokio::test]
    async fn cloudflare_t1_country_is_tor_too() {
        let tor = TorLookup::NotListed;
        let ident = ExitIdentity { ip: OTHER_IP, country_code: "t1", asn: Some(64500), isp: Some("Example Net"), org: None };
        assert_eq!(classify(&asns(), &ident, tor), IpType::Tor);
    }

    #[tokio::test]
    async fn hosting_is_ok_and_costs_nothing() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, Some(24940), Some("Hetzner Online GmbH"), false).await;
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "IP_TYPE_HOSTING"));
        assert!(r.message.starts_with("Хостинг (ожидаемо для личного VPS)"), "{}", r.message);
        assert_eq!(type_of(&r), Some(IpType::Hosting));
        let v = crate::auditor::score_checks(&[r], false);
        assert_eq!(v.trust_score, 100, "a hosting address is not penalised");
    }

    #[tokio::test]
    async fn hosting_is_recognised_by_the_name_when_the_asn_is_not_listed() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, Some(64500), Some("Example Cloud Hosting Ltd"), false).await;
        assert_eq!((r.status, type_of(&r)), (CheckStatus::Ok, Some(IpType::Hosting)));
    }

    #[tokio::test]
    async fn residential_is_ok() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, Some(64500), Some("Example Broadband Ltd"), false).await;
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "IP_TYPE_RESIDENTIAL"));
        assert_eq!(type_of(&r), Some(IpType::Residential));
    }

    #[tokio::test]
    async fn a_known_name_of_no_known_kind_is_ok_with_unknown_type() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, Some(64500), Some("Example Net"), false).await;
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "ASN_CLEAN"));
        assert_eq!(type_of(&r), Some(IpType::Unknown));
        assert!(r.message.contains("AS64500"), "{}", r.message);
    }

    #[tokio::test]
    async fn mass_vpn_pool_is_a_warning_and_pinning_excuses_it() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, Some(9009), Some("M247"), false).await;
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Warning, "HIGH_RISK_MASS_VPN_ASN"));
        assert_eq!(type_of(&r), Some(IpType::Vpn));
        assert!(r.message.contains("AS9009"), "{}", r.message);
        let r = verdict(&probe, OTHER_IP, Some(9009), Some("M247"), true).await;
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Ok, "ASN_VERIFIED_PINNED"));
    }

    #[tokio::test]
    async fn a_russian_isp_stays_critical() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, Some(12389), Some("PJSC Rostelecom"), false).await;
        assert_eq!((r.status, r.code.as_str()), (CheckStatus::Critical, "RUSSIAN_ISP_DETECTED"));
    }

    #[tokio::test]
    async fn without_any_data_the_check_is_unknown_no_data() {
        let probe = list_probe();
        let r = verdict(&probe, OTHER_IP, None, None, false).await;
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(UnknownReason::NoData)));
        assert_eq!(type_of(&r), Some(IpType::Unknown));
        // Blank names are no data either.
        let r = verdict(&probe, OTHER_IP, None, Some("  "), false).await;
        assert_eq!(r.status, CheckStatus::Unknown);
    }

    #[tokio::test]
    async fn an_unavailable_list_is_unknown_never_ok_and_never_a_block() {
        for (probe, reason) in [
            (FakeProbe::new(HttpProbeOutcome::Timeout), UnknownReason::Timeout),
            (FakeProbe::new(HttpProbeOutcome::ConnectFailed), UnknownReason::NetworkError),
            (FakeProbe::body(403, "denied"), UnknownReason::SourceRefused),
            (FakeProbe::body(200, "<html>portal</html>"), UnknownReason::EmptyResponse),
            (FakeProbe::body(500, ""), UnknownReason::NetworkError),
        ] {
            let r = verdict(&probe, OTHER_IP, Some(24940), Some("Hetzner Online GmbH"), false).await;
            assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(reason)));
            assert_eq!(r.code, "TOR_LIST_UNAVAILABLE");
            // The type is still shown from the provider data.
            assert_eq!(type_of(&r), Some(IpType::Hosting));
        }
        // A finding wins over a missing list.
        let probe = FakeProbe::new(HttpProbeOutcome::Timeout);
        let r = verdict(&probe, OTHER_IP, Some(9009), Some("M247"), false).await;
        assert_eq!(r.status, CheckStatus::Warning);
    }

    #[tokio::test]
    async fn an_ipv6_exit_is_not_applicable_and_the_list_is_not_downloaded() {
        let probe = list_probe();
        let r = verdict(&probe, "2001:db8::9", Some(24940), Some("Hetzner Online GmbH"), false).await;
        assert_eq!((r.status, r.reason), (CheckStatus::Unknown, Some(UnknownReason::NotApplicable)));
        assert!(r.is_not_applicable());
        assert!(r.message.starts_with("Не применимо к IPv6"), "{}", r.message);
        assert_eq!(type_of(&r), Some(IpType::Hosting));
        assert_eq!(probe.calls(), 0);
        // Not applicable costs nothing.
        assert_eq!(crate::auditor::score_checks(&[r], false).trust_score, 100);
    }

    #[tokio::test]
    async fn the_list_is_downloaded_once_per_ttl_and_a_failure_is_not_remembered_long() {
        let cache = TorListCache::default();
        let probe = list_probe();
        assert_eq!(lookup_tor(&cache, &probe, TOR_IP).await, TorLookup::Listed);
        assert_eq!(lookup_tor(&cache, &probe, OTHER_IP).await, TorLookup::NotListed);
        assert_eq!(probe.calls(), 1);

        let cache = TorListCache::default();
        let failing = FakeProbe::new(HttpProbeOutcome::Timeout);
        assert_eq!(
            lookup_tor(&cache, &failing, TOR_IP).await,
            TorLookup::Unavailable(UnknownReason::Timeout)
        );
        assert!(failing.calls() >= 1);
    }

    #[test]
    fn ip_type_wire_names_are_what_the_interface_reads() {
        let r = CheckResult::ok("A", "a").with_ip_type(IpType::Hosting);
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["detail"]["ip_type"], "hosting");
        for (t, s) in [
            (IpType::Hosting, "hosting"),
            (IpType::Residential, "residential"),
            (IpType::Tor, "tor"),
            (IpType::Vpn, "vpn"),
            (IpType::Unknown, "unknown"),
        ] {
            assert_eq!(serde_json::to_value(t).unwrap(), s);
        }
        // A result without a type carries no `detail` at all.
        assert!(serde_json::to_value(CheckResult::ok("A", "a")).unwrap().get("detail").is_none());
    }
}
