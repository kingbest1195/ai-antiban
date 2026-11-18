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
    let domains = vec!["claude.ai".to_string(), "chatgpt.com".to_string()];
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

#[test]
fn gemini_domains_match_across_matrix_and_pac_defaults() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let matrix_gemini = &matrix.providers["gemini"].domains;
    let all_domains = get_all_ai_domains(&matrix);
    let pac = generate_pac_script(&all_domains, "127.0.0.1:8899", None);

    let expected = [
        "gemini.google.com",
        "gemini.google",
        "clients6.google.com",
        "alkalimakersuite-pa.clients6.google.com",
        "generativelanguage.googleapis.com",
        "aisandbox-pa.googleapis.com",
        "aistudio.google.com",
        "makersuite.google.com",
        "ai.google.dev",
        "bard.google.com",
        "deepmind.google",
        "jules.google.com",
        "accounts.google.com",
        "ogs.google.com",
        "apis.google.com",
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

    for domain in expected {
        assert!(
            matrix_gemini.iter().any(|d| d == domain),
            "provider_matrix.json missing Gemini domain {domain}"
        );
        assert!(
            DEFAULT_AI_DOMAINS.contains(&domain),
            "DEFAULT_AI_DOMAINS missing Gemini domain {domain}"
        );
        assert!(
            all_domains.iter().any(|d| d == domain),
            "get_all_ai_domains missing {domain}"
        );
        assert!(
            pac.contains(&format!("\"{domain}\"")),
            "PAC missing {domain}"
        );
    }
    // Subdomains like waa-pa.clients6.google.com are matched via wildcard shExpMatch("*." + d).
    assert!(pac.contains(r#"if (host === d || shExpMatch(host, "*." + d))"#));
}

#[test]
fn browser_extension_ai_api_hosts_and_matrix_stay_in_sync() {
    use crate::auditor::geo_matrix::ProviderId;

    let matrix = ProviderMatrix::load_bundled().unwrap();
    let all_domains = get_all_ai_domains(&matrix);
    let pac = generate_pac_script(&all_domains, "127.0.0.1:8899", None);

    let pac_matches = |host: &str| -> bool {
        all_domains
            .iter()
            .any(|d| host == d || host.ends_with(&format!(".{d}")))
    };

    for host in [
        "api.anthropic.com",
        "claude.ai",
        "api.openai.com",
        "chatgpt.com",
        "gemini.google.com",
        "generativelanguage.googleapis.com",
        "clients6.google.com",
        "aistudio.google.com",
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
    ] {
        assert!(pac_matches(host), "PAC missing extension/AI host {host}");
        assert!(
            ProviderId::from_host(host).is_some(),
            "ProviderId::from_host missing {host}"
        );
    }

    // Every domain in bundled provider_matrix.json must be in DEFAULT_AI_DOMAINS and ProviderId::from_host.
    for (provider_id, rules) in &matrix.providers {
        for domain in &rules.domains {
            assert!(
                DEFAULT_AI_DOMAINS.contains(&domain.as_str()),
                "DEFAULT_AI_DOMAINS missing {provider_id} domain {domain}"
            );
            assert!(
                ProviderId::from_host(domain).is_some(),
                "ProviderId::from_host missing {provider_id} domain {domain}"
            );
            assert!(
                pac.contains(&format!("\"{domain}\"")),
                "PAC missing {provider_id} domain {domain}"
            );
        }
    }
}

#[test]
fn disabling_gemini_excludes_gemini_and_google_domains_from_pac() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let mut disabled = HashSet::new();
    disabled.insert("gemini".to_string());

    let domains = get_all_ai_domains_filtered(&matrix, &["custom-ai.org".to_string()], &disabled);
    let pac = generate_pac_script(&domains, "127.0.0.1:8899", None);

    for excluded in [
        "gemini.google.com",
        "aistudio.google.com",
        "www.google.com",
        "accounts.google.com",
        "generativelanguage.googleapis.com",
        "play.google.com",
    ] {
        assert!(
            !domains.iter().any(|d| d == excluded),
            "disabled gemini domain still in PAC: {excluded}"
        );
        assert!(
            !pac.contains(&format!("\"{excluded}\"")),
            "PAC script still contains disabled gemini domain: {excluded}"
        );
    }
    for kept in ["claude.ai", "anthropic.com", "chatgpt.com", "openai.com", "custom-ai.org"] {
        assert!(
            domains.iter().any(|d| d == kept),
            "enabled domain missing from PAC: {kept}"
        );
    }
}

#[test]
fn disabling_all_providers_produces_empty_ai_domains_in_pac() {
    let matrix = ProviderMatrix::load_bundled().unwrap();
    let disabled: HashSet<String> = ["anthropic", "openai", "gemini"]
        .into_iter()
        .map(String::from)
        .collect();
    let domains = get_all_ai_domains_filtered(&matrix, &["custom-ai.org".to_string()], &disabled);
    assert!(domains.is_empty(), "expected empty domains: {domains:?}");
    let pac = generate_pac_script(&domains, "127.0.0.1:8899", None);
    assert!(pac.contains("var aiDomains = [];"));
    assert!(pac.contains("return \"DIRECT\";"));
}
