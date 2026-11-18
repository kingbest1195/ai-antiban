//! Provider domain-to-provider mapping (`from_host` / `from_host_with_custom`).

use super::ProviderId;

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

const GEMINI_DOMAINS: &[&str] = &[
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

fn normalize_host(raw_host: &str) -> String {
    let without_port = if let Some(bracketed) = raw_host.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(raw_host)
    } else {
        raw_host.split(':').next().unwrap_or(raw_host)
    };
    without_port
        .trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_lowercase()
}

fn matches_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

pub(super) fn match_provider_host(raw_host: &str) -> Option<ProviderId> {
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return None;
    }
    if ANTHROPIC_DOMAINS.iter().any(|d| matches_domain(&host, d)) {
        return Some(ProviderId::Anthropic);
    }
    if OPENAI_DOMAINS.iter().any(|d| matches_domain(&host, d)) {
        return Some(ProviderId::Openai);
    }
    if GEMINI_DOMAINS.iter().any(|d| matches_domain(&host, d)) {
        return Some(ProviderId::Gemini);
    }
    None
}

pub(super) fn match_provider_host_with_custom(
    raw_host: &str,
    custom_domains: &[String],
) -> Option<ProviderId> {
    if let Some(p) = match_provider_host(raw_host) {
        return Some(p);
    }
    let host = normalize_host(raw_host);
    if host.is_empty() {
        return None;
    }
    for d in custom_domains {
        let clean = d
            .trim()
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .to_lowercase();
        if !clean.is_empty() && matches_domain(&host, &clean) {
            return Some(ProviderId::Anthropic);
        }
    }
    None
}
