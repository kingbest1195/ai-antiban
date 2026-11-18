use crate::auditor::geo_matrix::ProviderId;
use crate::auditor::rules::ProviderMatrix;
use std::collections::HashSet;

pub const DEFAULT_AI_DOMAINS: &[&str] = &[
    // Anthropic / Claude / Cursor / OpenRouter / Perplexity
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
    // OpenAI / ChatGPT / Microsoft Copilot / DeepSeek / Mistral / Grok
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
    // Google Gemini / AI Studio / Cloud Code / Antigravity / Labs
    "gemini.google.com",
    "gemini.google",
    "clients6.google.com",
    "aistudio.google.com",
    "makersuite.google.com",
    "generativelanguage.googleapis.com",
    "aisandbox-pa.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudaicompanion.googleapis.com",
    "alkalimakersuite-pa.clients6.google.com",
    "ai.google.dev",
    "bard.google.com",
    "deepmind.google",
    "jules.google.com",
    "accounts.google.com",
    "ogs.google.com",
    "apis.google.com",
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
    "notebooklm.google",
    "notebooklm.google.com",
    "idx.google.com",
    "opal.google.com",
    "labs.google",
    "www.google.com",
    "play.google.com",
    "footprints-pa.googleapis.com",
    "people-pa.googleapis.com",
    "signaler-pa.googleapis.com",
    "jnn-pa.googleapis.com",
    "oauth2.googleapis.com",
    "iamcredentials.googleapis.com",
    "myactivity.google.com",
    "myaccount.google.com",
];

/// Collects all configured AI domains from the matrix.
pub fn get_all_ai_domains(matrix: &ProviderMatrix) -> Vec<String> {
    let mut domains = Vec::new();
    for provider in matrix.providers.values() {
        for domain in &provider.domains {
            if !domains.contains(domain) {
                domains.push(domain.clone());
            }
        }
    }

    if domains.is_empty() {
        DEFAULT_AI_DOMAINS.iter().map(|s| s.to_string()).collect()
    } else {
        domains
    }
}

/// Collects all configured AI domains from the matrix merged with user-defined custom domains.
pub fn get_all_ai_domains_with_custom(
    matrix: &ProviderMatrix,
    custom_domains: &[String],
) -> Vec<String> {
    get_all_ai_domains_filtered(matrix, custom_domains, &HashSet::new())
}

/// Collects configured AI domains and custom domains, excluding any provider in `disabled_providers`
/// so disabled services (e.g., Gemini + general Google domains) go DIRECT cleanly.
pub fn get_all_ai_domains_filtered(
    matrix: &ProviderMatrix,
    custom_domains: &[String],
    disabled_providers: &HashSet<String>,
) -> Vec<String> {
    let disabled: HashSet<String> = disabled_providers
        .iter()
        .filter_map(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() {
                None
            } else if let Some(pid) = ProviderId::from_id(trimmed) {
                Some(pid.as_str().to_string())
            } else {
                Some(trimmed.to_ascii_lowercase())
            }
        })
        .collect();

    let mut domains = Vec::new();
    if matrix.providers.is_empty() {
        for &d in DEFAULT_AI_DOMAINS {
            let is_disabled = ProviderId::from_host(d)
                .map(|p| disabled.contains(p.as_str()))
                .unwrap_or(false);
            if !is_disabled {
                domains.push(d.to_string());
            }
        }
    } else {
        for (provider_id, provider) in &matrix.providers {
            let key = ProviderId::from_id(provider_id)
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| provider_id.trim().to_ascii_lowercase());
            if disabled.contains(&key) {
                continue;
            }
            for domain in &provider.domains {
                if !domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
                    domains.push(domain.clone());
                }
            }
        }
    }

    for cd in custom_domains {
        let clean = cd
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .to_lowercase();
        if clean.is_empty() {
            continue;
        }
        let owner_disabled = ProviderId::from_host_with_custom(&clean, std::slice::from_ref(&clean))
            .map(|p| disabled.contains(p.as_str()))
            .unwrap_or(false);
        if !owner_disabled && !domains.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
            domains.push(clean);
        }
    }
    domains
}

/// The first rule of every PAC script: the local network never goes through a proxy (printers
/// over AirPrint / IPP, the router, `*.local`, loopback). It comes before the chained upstream
/// and before the AI-domain matrix, so nothing can override it.
///
/// `isInNet()` resolves a host *name* through DNS before comparing, which would make the browser
/// look up every AI domain on its own before the gateway ever sees it (a DNS leak and extra
/// latency). It is therefore only applied to IPv4 literals; names are covered by the plain-host
/// and `*.local` checks.
const LOCAL_DIRECT_RULE: &str = r#"    // Local network first: printers (AirPrint / IPP), router, Bonjour, loopback.
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        host === "::1" || host === "[::1]") {
        return "DIRECT";
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) &&
        (isInNet(host, "10.0.0.0", "255.0.0.0") ||
         isInNet(host, "172.16.0.0", "255.240.0.0") ||
         isInNet(host, "192.168.0.0", "255.255.0.0") ||
         isInNet(host, "169.254.0.0", "255.255.0.0") ||
         isInNet(host, "127.0.0.0", "255.0.0.0"))) {
        return "DIRECT";
    }
"#;

/// Generates a standard Proxy Auto-Configuration (PAC) script routing AI domains to proxy.
/// Local-network addresses always return `DIRECT` first (see [`LOCAL_DIRECT_RULE`]).
/// If `chained_proxy` is specified, non-AI traffic falls back to `PROXY chained_proxy; DIRECT`.
/// Otherwise, non-AI traffic falls back directly to `DIRECT`.
pub fn generate_pac_script(
    domains: &[String],
    proxy_host_port: &str,
    chained_proxy: Option<&str>,
) -> String {
    let domains_json = serde_json::to_string_pretty(domains).unwrap_or_else(|_| "[]".to_string());
    let fallback = match chained_proxy.map(str::trim).filter(|s| !s.is_empty()) {
        Some(cp) => format!("PROXY {cp}; DIRECT"),
        None => "DIRECT".to_string(),
    };

    format!(
        r#"// Zastava Selective PAC Script
// Automatically routes known AI domains through local hold proxy, keeping everything else chained or DIRECT.
function FindProxyForURL(url, host) {{
    var aiDomains = {domains_json};
    host = (host || "").toLowerCase();
{LOCAL_DIRECT_RULE}
    for (var i = 0; i < aiDomains.length; i++) {{
        var d = aiDomains[i];
        if (host === d || shExpMatch(host, "*." + d)) {{
            return "PROXY {proxy_host_port}";
        }}
    }}
    return "{fallback}";
}}
"#
    )
}


#[cfg(test)]
#[path = "pac_tests.rs"]
mod tests;
