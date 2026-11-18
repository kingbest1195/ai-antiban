mod domains;

#[cfg(test)]
mod tests;

use crate::auditor::ip_type::IpType;
use crate::auditor::rules::ProviderMatrix;
use serde::{Deserialize, Serialize};

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
        domains::match_provider_host(raw_host)
    }

    /// Matches host against known providers AND user-added custom domains.
    /// Falls back to Some(ProviderId::Anthropic) if host matches any user-added custom domain.
    pub fn from_host_with_custom(raw_host: &str, custom_domains: &[String]) -> Option<Self> {
        domains::match_provider_host_with_custom(raw_host, custom_domains)
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
                ProviderId::Gemini => {
                    "Гонконг (HK) заблокирован для веб-версии Google Gemini (gemini.google.com) и ограничен для Google AI Studio API (в отличие от части платных проектов Vertex AI). Также HK глобально заблокирован в Claude и OpenAI. Переключитесь на NL, DE или US."
                }
                _ => {
                    "Гонконг (HK) глобально заблокирован в Claude, OpenAI и веб-версии Google Gemini (а для AI Studio API действуют строгие ограничения). Многие ставят HK как «быстрый узел», что ведет к мгновенному бану аккаунта. Переключитесь на NL, DE или US."
                }
            },
            "MO" => match provider {
                ProviderId::Gemini => {
                    "Макао (MO) заблокирован для веб-версии Google Gemini (gemini.google.com) и ограничен для Google AI Studio API. Переключитесь на NL, DE или US."
                }
                _ => {
                    "Макао (MO) глобально заблокирован в Claude, OpenAI и Google Gemini. Переключитесь на NL, DE или US."
                }
            },
            "CN" => match provider {
                ProviderId::Gemini => {
                    "Материковый Китай (CN) заблокирован как для веб-версии Google Gemini, так и для Google AI Studio API. Переключитесь на NL, DE или US."
                }
                _ => {
                    "Материковый Китай (CN) заблокирован всеми основными ИИ-провайдерами (включая Claude, OpenAI, Google Gemini web и AI Studio API). Соединение остановлено для защиты аккаунта."
                }
            },
            "RU" | "BY" => {
                "Подключение идет из неподдерживаемого региона. Прямой доступ к сервису ограничен политиками платформы в этой юрисдикции. Переключитесь на доверенный рабочий шлюз (NL, DE, US)."
            }
            _ => {
                "Доступ из этой юрисдикции заблокирован всеми основными ИИ-провайдерами. Соединение остановлено для защиты аккаунта."
            }
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
