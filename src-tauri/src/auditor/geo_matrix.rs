use serde::{Deserialize, Serialize};
use crate::auditor::ip_type::IpType;
use crate::auditor::rules::ProviderMatrix;

pub const GUIDE_PERSONAL_VPN: &str = "01-personal-vpn-15min";
pub const GUIDE_PAYMENT_CARDS: &str = "02-safe-payment-cards";
pub const GUIDE_OS_PRIVACY: &str = "03-os-privacy-setup";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderId {
    Anthropic,
    Openai,
    Gemini,
}

impl ProviderId {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderId::Anthropic => "anthropic",
            ProviderId::Openai => "openai",
            ProviderId::Gemini => "gemini",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ProviderId::Anthropic => "Claude (Anthropic)",
            ProviderId::Openai => "ChatGPT (OpenAI)",
            ProviderId::Gemini => "Google Gemini / AI Studio",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        match id.to_lowercase().as_str() {
            "anthropic" | "claude" => Some(ProviderId::Anthropic),
            "openai" | "chatgpt" => Some(ProviderId::Openai),
            "gemini" | "google" => Some(ProviderId::Gemini),
            _ => None,
        }
    }

    /// Determines target AI provider from HTTP CONNECT or request hostname.
    /// Normalizes bracketed hosts and strips trailing DNS dots to prevent FQDN bypasses.
    pub fn from_host(raw_host: &str) -> Option<Self> {
        let without_port = if let Some(bracketed) = raw_host.strip_prefix('[') {
            bracketed.split(']').next().unwrap_or(raw_host)
        } else {
            raw_host.split(':').next().unwrap_or(raw_host)
        };

        let host = without_port
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_lowercase();

        if host.is_empty() {
            return None;
        }

        let matches_domain = |h: &str, d: &str| -> bool {
            h == d || (h.len() > d.len() && h.ends_with(d) && h.as_bytes()[h.len() - d.len() - 1] == b'.')
        };

        // 1. Anthropic / Claude / Cursor / OpenRouter / Perplexity
        const ANTHROPIC_DOMAINS: &[&str] = &[
            "canary-test.anthropic.zastava.local",
            "claude.ai",
            "claude.com",
            "anthropic.com",
            "claudeusercontent.com",
            "console.anthropic.com",
            "statsig.anthropic.com",
            "cursor.sh",
            "api2.cursor.sh",
            "api3.cursor.sh",
            "cursor.com",
            "cursor-cdn.com",
            "openrouter.ai",
            "poe.com",
            "perplexity.ai",
            "pplx.ai",
        ];
        for d in ANTHROPIC_DOMAINS {
            if matches_domain(&host, d) {
                return Some(ProviderId::Anthropic);
            }
        }

        // 2. OpenAI / ChatGPT / Microsoft Copilot / DeepSeek / Mistral / Grok
        const OPENAI_DOMAINS: &[&str] = &[
            "chatgpt.com",
            "openai.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "auth0.openai.com",
            "platform.openai.com",
            "chat.openai.com",
            "copilot.microsoft.com",
            "sydney.bing.com",
            "edgeservices.bing.com",
            "copilot.cloud.microsoft",
            "officecopilot.microsoft.com",
            "githubcopilot.com",
            "api.githubcopilot.com",
            "copilot-proxy.githubusercontent.com",
            "default.exp-tas.com",
            "codeium.com",
            "windsurf.com",
            "codeiumdata.com",
            "supermaven.com",
            "deepseek.com",
            "chat.deepseek.com",
            "api.deepseek.com",
            "grok.com",
            "x.ai",
            "api.x.ai",
            "mistral.ai",
            "chat.mistral.ai",
        ];
        for d in OPENAI_DOMAINS {
            if matches_domain(&host, d) {
                return Some(ProviderId::Openai);
            }
        }

        // 3. Google Gemini / AI Studio / Vertex AI / Cloud AI Companion (Antigravity, Orca, Cloud Code) / NotebookLM / Labs
        const GEMINI_DOMAINS: &[&str] = &[
            "gemini.google.com",
            "aistudio.google.com",
            "makersuite.google.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "cloudaicompanion.googleapis.com",
            "clients6.google.com",
            "alkalimakersuite-pa.clients6.google.com",
            "daily-cloudcode-pa.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.sandbox.googleapis.com",
            "autopush-cloudcode-pa.sandbox.googleapis.com",
            "preprod-daily-cloudcode-pa.sandbox.googleapis.com",
            "aicode.googleapis.com",
            "autopush-aicode.sandbox.googleapis.com",
            "preprod-aicode.sandbox.googleapis.com",
            "alkalimakersuiteapplets.pa.googleapis.com",
            "antigravity.google",
            "antigravity.google.com",
            "share.gemini.google",
            "gemini.google",
            "notebooklm.google",
            "notebooklm.google.com",
            "idx.google.com",
            "opal.google.com",
            "labs.google",
        ];
        for d in GEMINI_DOMAINS {
            if matches_domain(&host, d) {
                return Some(ProviderId::Gemini);
            }
        }

        None
    }

    /// Matches host against known providers AND user-added custom domains.
    /// Falls back to Some(ProviderId::Anthropic) if host matches any user-added custom domain.
    pub fn from_host_with_custom(raw_host: &str, custom_domains: &[String]) -> Option<Self> {
        if let Some(p) = Self::from_host(raw_host) {
            return Some(p);
        }

        let without_port = if let Some(bracketed) = raw_host.strip_prefix('[') {
            bracketed.split(']').next().unwrap_or(raw_host)
        } else {
            raw_host.split(':').next().unwrap_or(raw_host)
        };

        let host = without_port
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_lowercase();

        if host.is_empty() {
            return None;
        }

        for d in custom_domains {
            let clean = d.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
            if !clean.is_empty() && (host == clean || host.ends_with(&format!(".{clean}"))) {
                return Some(ProviderId::Anthropic);
            }
        }

        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Warning,
    Critical,
    /// The check could not be performed ("не удалось проверить"): never counted as clean.
    /// Any unrecognised status string also reads as `Unknown` (never as `Ok`).
    #[serde(other)]
    Unknown,
}

impl CheckStatus {
    pub fn is_critical(&self) -> bool {
        matches!(self, CheckStatus::Critical)
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, CheckStatus::Warning)
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, CheckStatus::Ok)
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, CheckStatus::Unknown)
    }
}

/// Why a check ended up `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    Timeout,
    NetworkError,
    EmptyResponse,
    NoData,
    UnsupportedOs,
    InternalError,
    /// The check makes no sense in the current setup: shown neutrally, never penalised.
    NotApplicable,
    SourceRefused,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CheckResult {
    pub status: CheckStatus,
    pub code: String,
    pub message: String,
    pub guide_ref: Option<String>,
    /// Set only together with `CheckStatus::Unknown`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<UnknownReason>,
    /// Unix seconds at which the check finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    /// Source the value was measured through (reference only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_via: Option<String>,
    /// What each independent source showed (only the DNS checks fill it): the interface lists it
    /// so that a disagreement is not a dead end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<CheckDetail>,
}

/// How one source of a multi-source check answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Answered,
    /// A service address (private, fake-IP...): the local DNS stub answered, not a resolver.
    Special,
    Empty,
    Timeout,
    Failed,
    Unsupported,
}

/// One source of a check: what it showed (address, its operator and country when known).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceView {
    /// "Akamai", "Google".
    pub source: String,
    pub state: SourceState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
    /// Public DNS service the address belongs to ("Cloudflare"), if it is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Structured facts behind a result (the text lives in `message`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CheckDetail {
    #[serde(default)]
    pub sources: Vec<SourceView>,
    /// Kind of the exit address (only the address-reputation check fills it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_type: Option<IpType>,
}

impl CheckResult {
    fn with_status(
        status: CheckStatus,
        code: impl Into<String>,
        message: impl Into<String>,
        guide_ref: Option<String>,
    ) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            guide_ref,
            reason: None,
            checked_at: None,
            measured_via: None,
            detail: None,
        }
    }

    pub fn ok(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::with_status(CheckStatus::Ok, code, message, None)
    }

    pub fn warning(
        code: impl Into<String>,
        message: impl Into<String>,
        guide_ref: Option<String>,
    ) -> Self {
        Self::with_status(CheckStatus::Warning, code, message, guide_ref)
    }

    pub fn critical(
        code: impl Into<String>,
        message: impl Into<String>,
        guide_ref: Option<String>,
    ) -> Self {
        Self::with_status(CheckStatus::Critical, code, message, guide_ref)
    }

    /// A check that could not be carried out; `message` states what exactly was not verified.
    pub fn unknown(
        code: impl Into<String>,
        message: impl Into<String>,
        reason: UnknownReason,
    ) -> Self {
        let mut r = Self::with_status(CheckStatus::Unknown, code, message, None);
        r.reason = Some(reason);
        r
    }

    pub fn is_unknown(&self) -> bool {
        self.status.is_unknown()
    }

    /// `Unknown` because the check does not apply (not penalised, not counted as applicable).
    pub fn is_not_applicable(&self) -> bool {
        self.is_unknown() && self.reason == Some(UnknownReason::NotApplicable)
    }

    pub fn with_measured_via(mut self, via: impl Into<String>) -> Self {
        self.measured_via = Some(via.into());
        self
    }

    /// Attaches what each source showed; an empty list attaches nothing.
    pub fn with_sources(mut self, sources: &[SourceView]) -> Self {
        if !sources.is_empty() {
            self.detail = Some(CheckDetail {
                sources: sources.to_vec(),
                ..CheckDetail::default()
            });
        }
        self
    }

    /// Attaches the kind of the exit address for the interface (`detail.ip_type`).
    pub fn with_ip_type(mut self, ip_type: IpType) -> Self {
        self.detail.get_or_insert_with(CheckDetail::default).ip_type = Some(ip_type);
        self
    }
}

/// Evaluates provider compatibility against country code according to the Provider Matrix.
pub fn evaluate_provider_geo(
    matrix: &ProviderMatrix,
    provider: ProviderId,
    country_code_raw: &str,
) -> CheckResult {
    let country_code = country_code_raw.trim().to_uppercase();

    // 0. Codes that are not a country: Cloudflare marks Tor exits as "T1", an unknown location is
    // "XX" (or empty). The first is a finding, the others mean nothing was verified.
    if country_code == "T1" {
        return CheckResult::critical(
            "TOR_EXIT_NODE",
            "Выходной узел определен как сеть Tor (код страны T1). Антифрод ИИ-сервисов блокирует Tor-адреса.",
            Some(GUIDE_PERSONAL_VPN.to_string()),
        );
    }
    let is_country_code = country_code.len() == 2
        && country_code.bytes().all(|b| b.is_ascii_uppercase())
        && !matches!(country_code.as_str(), "XX" | "ZZ");
    if !is_country_code {
        return CheckResult::unknown(
            "GEO_NO_COUNTRY",
            format!(
                "Страна выхода не определена (источник геолокации вернул «{}»): совместимость с {} не проверена.",
                country_code_raw.trim(),
                provider.display_name()
            ),
            UnknownReason::NoData,
        );
    }

    // 1. Check Global Sanctioned List (RU, BY, CN, HK, MO, IR, KP, SY, CU)
    if matrix.global_blocked_countries.contains(&country_code) {
        let msg = match country_code.as_str() {
            "HK" => match provider {
                ProviderId::Gemini => "Гонконг (HK) заблокирован для веб-версии Google Gemini (gemini.google.com) и ограничен для Google AI Studio API (в отличие от части платных проектов Vertex AI). Также HK глобально заблокирован в Claude и OpenAI. Переключитесь на NL, DE или US.",
                _ => "Гонконг (HK) глобально заблокирован в Claude, OpenAI и веб-версии Google Gemini (а для AI Studio API действуют строгие ограничения). Многие ставят HK как «быстрый узел», что ведет к мгновенному бану аккаунта. Переключитесь на NL, DE или US.",
            },
            "MO" => match provider {
                ProviderId::Gemini => "Макао (MO) заблокирован для веб-версии Google Gemini (gemini.google.com) и ограничен для Google AI Studio API. Переключитесь на NL, DE или US.",
                _ => "Макао (MO) глобально заблокирован в Claude, OpenAI и Google Gemini. Переключитесь на NL, DE или US.",
            },
            "CN" => match provider {
                ProviderId::Gemini => "Материковый Китай (CN) заблокирован как для веб-версии Google Gemini, так и для Google AI Studio API. Переключитесь на NL, DE или US.",
                _ => "Материковый Китай (CN) заблокирован всеми основными ИИ-провайдерами (включая Claude, OpenAI, Google Gemini web и AI Studio API). Соединение остановлено для защиты аккаунта.",
            },
            "RU" | "BY" => "Подключение идет из неподдерживаемого региона. Прямой доступ к сервису ограничен политиками платформы в этой юрисдикции. Переключитесь на доверенный рабочий шлюз (NL, DE, US).",
            _ => "Доступ из этой юрисдикции заблокирован всеми основными ИИ-провайдерами. Соединение остановлено для защиты аккаунта.",
        };

        return CheckResult::critical(
            "GLOBAL_SANCTIONED_COUNTRY",
            msg,
            Some(GUIDE_PERSONAL_VPN.to_string()),
        );
    }

    let rules = matrix.get_provider_rules(provider.as_str());

    // 2. Provider-specific blocked countries
    if let Some(r) = rules {
        if r.blocked_countries.contains(&country_code) {
            let reason = r
                .country_block_reasons
                .get(&country_code)
                .cloned()
                .unwrap_or_else(|| {
                    format!(
                        "Доступ к {} заблокирован для локации {}.",
                        provider.display_name(),
                        country_code
                    )
                });

            return CheckResult::critical(
                format!("{}_GEO_BLOCKED", provider.as_str().to_uppercase()),
                reason,
                Some(GUIDE_PERSONAL_VPN.to_string()),
            );
        }

        // 3. Provider-specific warning countries (includes transit hubs & partial restrictions from provider_matrix.json)
        if let Some(warn_msg) = r.warning_countries.get(&country_code) {
            return CheckResult::warning(
                format!("{}_GEO_WARNING", provider.as_str().to_uppercase()),
                warn_msg.clone(),
                Some(GUIDE_PERSONAL_VPN.to_string()),
            );
        }
    }

    CheckResult::ok(
        "GEO_ALLOWED",
        format!(
            "Страна выхода {} не входит в списки ограничений для {} (по данным геолокации выходного IP).",
            country_code,
            provider.display_name()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_geo_matrix_russia_blocked() {
        let matrix = ProviderMatrix::load_bundled().unwrap();
        for &provider in &[ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            let res = evaluate_provider_geo(&matrix, provider, "RU");
            assert_eq!(res.status, CheckStatus::Critical);
            assert_eq!(res.code, "GLOBAL_SANCTIONED_COUNTRY");
        }
    }

    #[test]
    fn test_provider_geo_non_country_codes_are_never_allowed() {
        let matrix = ProviderMatrix::load_bundled().unwrap();
        for &provider in &[ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            for raw in ["", "  ", "XX", "xx", "ZZ", "N", "NLD", "1A"] {
                let res = evaluate_provider_geo(&matrix, provider, raw);
                assert_eq!(res.status, CheckStatus::Unknown, "{raw:?}");
                assert_eq!(res.reason, Some(UnknownReason::NoData), "{raw:?}");
                assert_ne!(res.code, "GEO_ALLOWED");
            }
            // Cloudflare's marker of a Tor exit.
            for raw in ["T1", "t1"] {
                let res = evaluate_provider_geo(&matrix, provider, raw);
                assert_eq!(res.status, CheckStatus::Critical);
                assert_eq!(res.code, "TOR_EXIT_NODE");
            }
        }
    }

    #[test]
    fn test_provider_geo_ok_text_states_the_verified_fact() {
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let res = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "NL");
        assert_eq!(res.code, "GEO_ALLOWED");
        assert!(res.message.contains("не входит в списки ограничений"));
        assert!(!res.message.contains("полностью") && !res.message.contains("безопасна"));
    }

    #[test]
    fn test_provider_geo_matrix_hongkong_blocked() {
        let matrix = ProviderMatrix::load_bundled().unwrap();
        for &provider in &[ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            let res = evaluate_provider_geo(&matrix, provider, "HK");
            assert_eq!(res.status, CheckStatus::Critical);
            assert_eq!(res.code, "GLOBAL_SANCTIONED_COUNTRY");
            assert!(res.message.contains("HK") || res.message.contains("Гонконг"));
        }
    }

    #[test]
    fn test_provider_geo_matrix_turkey_gemini_allowed() {
        let matrix = ProviderMatrix::load_bundled().unwrap();

        // Gemini in Turkey -> Ok (Turkey is officially supported by Gemini web & API)
        let res_gemini = evaluate_provider_geo(&matrix, ProviderId::Gemini, "TR");
        assert_eq!(res_gemini.status, CheckStatus::Ok);
        assert_eq!(res_gemini.code, "GEO_ALLOWED");

        // Anthropic in Turkey -> Warning
        let res_anthropic = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "TR");
        assert_eq!(res_anthropic.status, CheckStatus::Warning);

        // OpenAI in Turkey -> Ok
        let res_openai = evaluate_provider_geo(&matrix, ProviderId::Openai, "TR");
        assert_eq!(res_openai.status, CheckStatus::Ok);
    }

    #[test]
    fn test_provider_geo_matrix_venezuela_and_anthropic_sanctioned_countries() {
        let matrix = ProviderMatrix::load_bundled().unwrap();

        // Venezuela (VE) blocked for Anthropic & OpenAI, allowed for Gemini
        let ve_anthropic = evaluate_provider_geo(&matrix, ProviderId::Anthropic, "VE");
        assert_eq!(ve_anthropic.status, CheckStatus::Critical);
        assert_eq!(ve_anthropic.code, "ANTHROPIC_GEO_BLOCKED");

        let ve_openai = evaluate_provider_geo(&matrix, ProviderId::Openai, "VE");
        assert_eq!(ve_openai.status, CheckStatus::Critical);
        assert_eq!(ve_openai.code, "OPENAI_GEO_BLOCKED");

        let ve_gemini = evaluate_provider_geo(&matrix, ProviderId::Gemini, "VE");
        assert_eq!(ve_gemini.status, CheckStatus::Ok);

        // AF, MM, SD, YE blocked for Anthropic
        for &country in &["AF", "MM", "SD", "YE"] {
            let res = evaluate_provider_geo(&matrix, ProviderId::Anthropic, country);
            assert_eq!(res.status, CheckStatus::Critical, "expected {country} blocked for Anthropic");
            assert_eq!(res.code, "ANTHROPIC_GEO_BLOCKED");
        }
    }

    #[test]
    fn test_provider_geo_matrix_global_sanctioned_and_regional_notes() {
        let matrix = ProviderMatrix::load_bundled().unwrap();

        for &country in &["RU", "BY", "CN", "IR", "HK", "MO"] {
            for &provider in &[ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
                let res = evaluate_provider_geo(&matrix, provider, country);
                assert_eq!(res.status, CheckStatus::Critical, "{country} for {provider:?}");
                assert_eq!(res.code, "GLOBAL_SANCTIONED_COUNTRY");
            }
        }

        // HK / MO / CN Gemini messages note Gemini web vs AI Studio API
        for &country in &["HK", "MO", "CN"] {
            let res = evaluate_provider_geo(&matrix, ProviderId::Gemini, country);
            assert!(res.message.contains("AI Studio API"), "{country}: {}", res.message);
            assert!(res.message.contains("Gemini"), "{country}: {}", res.message);
        }

        // UA has partial restriction warnings for all providers
        for &provider in &[ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
            let res = evaluate_provider_geo(&matrix, provider, "UA");
            assert_eq!(res.status, CheckStatus::Warning, "UA for {provider:?}");
            assert!(res.message.contains("оккупированных"), "UA: {}", res.message);
        }
    }

    #[test]
    fn test_provider_geo_matrix_transit_hubs_and_no_dead_warnings() {
        let matrix = ProviderMatrix::load_bundled().unwrap();

        // Single source of truth in provider_matrix.json: transit hubs warn for Anthropic & Gemini, Ok for OpenAI
        for &country in &["KZ", "AM", "GE", "UZ", "KG", "RS", "AE"] {
            let a = evaluate_provider_geo(&matrix, ProviderId::Anthropic, country);
            assert_eq!(a.status, CheckStatus::Warning, "Anthropic {country}");
            let g = evaluate_provider_geo(&matrix, ProviderId::Gemini, country);
            assert_eq!(g.status, CheckStatus::Warning, "Gemini {country}");
            let o = evaluate_provider_geo(&matrix, ProviderId::Openai, country);
            assert_eq!(o.status, CheckStatus::Ok, "OpenAI {country}");
        }

        // Dead warnings already covered by global_blocked_countries must not remain
        let openai = matrix.get_provider_rules("openai").unwrap();
        assert!(!openai.warning_countries.contains_key("IR"));
        assert!(!openai.warning_countries.contains_key("HK"));
        let gemini = matrix.get_provider_rules("gemini").unwrap();
        assert!(!gemini.warning_countries.contains_key("BY"));
        assert!(!gemini.blocked_countries.contains(&"TR".to_string()));
    }

    #[test]
    fn test_provider_geo_matrix_netherlands_allowed() {
        let matrix = ProviderMatrix::load_bundled().unwrap();
        for &country in &["NL", "DE", "US", "FI"] {
            for &provider in &[ProviderId::Anthropic, ProviderId::Openai, ProviderId::Gemini] {
                let res = evaluate_provider_geo(&matrix, provider, country);
                assert_eq!(res.status, CheckStatus::Ok);
                assert_eq!(res.code, "GEO_ALLOWED");
            }
        }
    }

    #[test]
    fn test_provider_from_host_matching() {
        assert_eq!(ProviderId::from_host("claude.ai:443"), Some(ProviderId::Anthropic));
        assert_eq!(ProviderId::from_host("api.anthropic.com"), Some(ProviderId::Anthropic));
        assert_eq!(ProviderId::from_host("chatgpt.com"), Some(ProviderId::Openai));
        assert_eq!(ProviderId::from_host("gemini.google.com:443"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("aistudio.google.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("example.com"), None);
    }

    #[test]
    fn test_antigravity_and_cloudcode_endpoints_match_gemini() {
        assert_eq!(ProviderId::from_host("daily-cloudcode-pa.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("cloudcode-pa.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("daily-cloudcode-pa.sandbox.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("autopush-cloudcode-pa.sandbox.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("preprod-daily-cloudcode-pa.sandbox.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("aicode.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("autopush-aicode.sandbox.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("preprod-aicode.sandbox.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("alkalimakersuiteapplets.pa.googleapis.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("antigravity.google"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("antigravity.google.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("share.gemini.google"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("notebooklm.google"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("notebooklm.google.com"), Some(ProviderId::Gemini));
        assert_eq!(ProviderId::from_host("idx.google.com"), Some(ProviderId::Gemini));
    }

    #[test]
    fn test_extended_domains_and_custom_domains_matching() {
        // Anthropic / Cursor / Perplexity
        assert_eq!(ProviderId::from_host("cursor.sh"), Some(ProviderId::Anthropic));
        assert_eq!(ProviderId::from_host("api2.cursor.sh:443"), Some(ProviderId::Anthropic));
        assert_eq!(ProviderId::from_host("perplexity.ai"), Some(ProviderId::Anthropic));
        assert_eq!(ProviderId::from_host("openrouter.ai"), Some(ProviderId::Anthropic));

        // OpenAI / Copilot / DeepSeek / Mistral
        assert_eq!(ProviderId::from_host("copilot.microsoft.com:443"), Some(ProviderId::Openai));
        assert_eq!(ProviderId::from_host("githubcopilot.com"), Some(ProviderId::Openai));
        assert_eq!(ProviderId::from_host("api.githubcopilot.com"), Some(ProviderId::Openai));
        assert_eq!(ProviderId::from_host("deepseek.com"), Some(ProviderId::Openai));
        assert_eq!(ProviderId::from_host("api.deepseek.com"), Some(ProviderId::Openai));
        assert_eq!(ProviderId::from_host("mistral.ai"), Some(ProviderId::Openai));

        // Custom domain matching
        let custom = vec!["internal-ai.corp".to_string(), "custom-agent.dev".to_string()];
        assert_eq!(
            ProviderId::from_host_with_custom("internal-ai.corp:8443", &custom),
            Some(ProviderId::Anthropic)
        );
        assert_eq!(
            ProviderId::from_host_with_custom("api.custom-agent.dev", &custom),
            Some(ProviderId::Anthropic)
        );
        assert_eq!(
            ProviderId::from_host_with_custom("unknown-service.com", &custom),
            None
        );
    }

    #[test]
    fn test_check_result_json_without_new_fields_reads() {
        let r: CheckResult =
            serde_json::from_str(r#"{"status":"ok","code":"X","message":"m","guide_ref":null}"#)
                .unwrap();
        assert_eq!(r.status, CheckStatus::Ok);
        assert!(r.reason.is_none() && r.checked_at.is_none() && r.measured_via.is_none());
        // Without optional guide_ref at all, too.
        let r: CheckResult =
            serde_json::from_str(r#"{"status":"warning","code":"X","message":"m"}"#).unwrap();
        assert_eq!(r.status, CheckStatus::Warning);
    }

    #[test]
    fn test_status_unknown_and_random_string_read_as_unknown() {
        let r: CheckResult = serde_json::from_str(
            r#"{"status":"unknown","code":"X","message":"m","guide_ref":null,"reason":"timeout"}"#,
        )
        .unwrap();
        assert_eq!(r.status, CheckStatus::Unknown);
        assert_eq!(r.reason, Some(UnknownReason::Timeout));

        let r: CheckResult = serde_json::from_str(
            r#"{"status":"definitely-not-a-status","code":"X","message":"m","guide_ref":null}"#,
        )
        .unwrap();
        assert_eq!(r.status, CheckStatus::Unknown);
        assert!(!r.status.is_ok());
    }

    #[test]
    fn test_unknown_constructor_and_serialization() {
        let r = CheckResult::unknown("C", "m", UnknownReason::NotApplicable);
        assert!(r.is_unknown() && r.is_not_applicable());
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "unknown");
        assert_eq!(v["reason"], "not_applicable");
        // Optional fields that are not set are omitted for ordinary results.
        let ok = serde_json::to_value(CheckResult::ok("C", "m")).unwrap();
        assert!(ok.get("reason").is_none() && ok.get("measured_via").is_none());
        let t = CheckResult::unknown("C", "m", UnknownReason::Timeout);
        assert!(t.is_unknown() && !t.is_not_applicable());
    }
}
