use crate::auditor::rules::ProviderMatrix;

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
    "aistudio.google.com",
    "makersuite.google.com",
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "cloudaicompanion.googleapis.com",
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
    "notebooklm.google",
    "notebooklm.google.com",
    "idx.google.com",
    "opal.google.com",
    "labs.google",
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
pub fn get_all_ai_domains_with_custom(matrix: &ProviderMatrix, custom_domains: &[String]) -> Vec<String> {
    let mut domains = get_all_ai_domains(matrix);
    for cd in custom_domains {
        let clean = cd.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
        if !clean.is_empty() && !domains.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
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
mod tests {
    use super::*;

    #[test]
    fn test_pac_file_generation() {
        let domains = vec![
            "claude.ai".to_string(),
            "chatgpt.com".to_string(),
            "gemini.google.com".to_string(),
        ];
        let pac = generate_pac_script(&domains, "127.0.0.1:8899", None);

        assert!(pac.contains("function FindProxyForURL(url, host)"));
        assert!(pac.contains("\"claude.ai\""));
        assert!(pac.contains("\"chatgpt.com\""));
        assert!(pac.contains("\"gemini.google.com\""));
        assert!(pac.contains("return \"PROXY 127.0.0.1:8899\";"));
        assert!(pac.contains("return \"DIRECT\";"));
        assert!(pac.contains("host = (host || \"\").toLowerCase();"));
    }

    #[test]
    fn test_pac_file_generation_with_chained_proxy() {
        let domains = vec![
            "claude.ai".to_string(),
            "chatgpt.com".to_string(),
        ];
        let pac = generate_pac_script(&domains, "127.0.0.1:8899", Some("127.0.0.1:10808"));

        assert!(pac.contains("function FindProxyForURL(url, host)"));
        assert!(pac.contains("return \"PROXY 127.0.0.1:8899\";"));
        assert!(pac.contains("return \"PROXY 127.0.0.1:10808; DIRECT\";"));
    }

    #[test]
    fn test_pac_with_custom_domains() {
        let matrix = ProviderMatrix::load_bundled().unwrap();
        let custom = vec!["custom-ai.company.org".to_string(), "claude.ai".to_string()];
        let merged = get_all_ai_domains_with_custom(&matrix, &custom);
        assert!(merged.contains(&"custom-ai.company.org".to_string()));
        assert!(merged.contains(&"claude.ai".to_string()));
    }

    fn pac_for(chained: Option<&str>) -> String {
        generate_pac_script(&["claude.ai".to_string()], "127.0.0.1:8899", chained)
    }

    #[test]
    fn local_direct_rule_comes_before_the_ai_matrix_and_the_chained_proxy() {
        let pac = pac_for(Some("127.0.0.1:10808"));
        let rule = pac.find("isPlainHostName(host)").expect("local rule");
        let first_direct = pac.find("return \"DIRECT\";").expect("DIRECT");
        let matrix = pac.find("var aiDomains").expect("matrix");
        let loop_at = pac.find("for (var i").expect("matrix loop");
        let chained = pac.find("PROXY 127.0.0.1:10808; DIRECT").expect("chained");
        assert!(rule < loop_at && rule < chained, "{pac}");
        assert!(first_direct < loop_at && first_direct < chained);
        assert!(matrix < rule, "the list is only declared before the rule");
        // Nothing but the host normalisation sits between the function head and the rule.
        let head = &pac[pac.find("FindProxyForURL").unwrap()..rule];
        assert!(!head.contains("return"), "{head}");
    }

    #[test]
    fn local_direct_rule_covers_every_private_range_and_local_names() {
        let pac = pac_for(None);
        for needle in [
            "isPlainHostName(host)",
            "shExpMatch(host, \"*.local\")",
            "isInNet(host, \"10.0.0.0\", \"255.0.0.0\")",
            "isInNet(host, \"172.16.0.0\", \"255.240.0.0\")",
            "isInNet(host, \"192.168.0.0\", \"255.255.0.0\")",
            "isInNet(host, \"169.254.0.0\", \"255.255.0.0\")",
            "isInNet(host, \"127.0.0.0\", \"255.0.0.0\")",
        ] {
            assert!(pac.contains(needle), "{needle}");
        }
    }

    #[test]
    fn is_in_net_is_only_reached_for_ipv4_literals_so_ai_names_are_never_resolved() {
        let pac = pac_for(None);
        let guard = pac.find(r"/^\d{1,3}").expect("IPv4 literal guard");
        let first_is_in_net = pac.find("isInNet(").expect("isInNet");
        assert!(guard < first_is_in_net, "{pac}");
        assert!(!pac.contains("dnsResolve"), "{pac}");
        // Every isInNet call sits behind the literal guard (one condition), none stands alone.
        assert_eq!(pac.matches("isInNet(").count(), 5);
    }

    #[test]
    fn local_direct_rule_is_the_same_with_and_without_a_chained_proxy() {
        let with = pac_for(Some("127.0.0.1:10808"));
        let without = pac_for(None);
        let cut = |s: &str| {
            let a = s.find("// Local network first").unwrap();
            let b = s.find("for (var i").unwrap();
            s[a..b].to_string()
        };
        assert_eq!(cut(&with), cut(&without));
        assert!(without.contains("return \"PROXY 127.0.0.1:8899\";"));
    }
}
