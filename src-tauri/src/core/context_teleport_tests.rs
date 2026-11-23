use super::*;

#[test]
fn redacts_all_inline_secret_patterns_and_counts_them() {
    let raw = "key1=sk-ant-api03-SECRET123456\n\
               key2=sk-proj-1234567890abcdef\n\
               key3=AIzaSyDummyGoogleKey1234567890\n\
               key4=ghp_1234567890abcdef1234\n\
               key5=xoxb-1234567890-abcdef\n\
               Authorization: Bearer mySecretBearerToken123\n\
               oauth_token=oauth_secret_value_99\n\
               password=\"super_secret_pw\"";
    let (clean, count) = redact_inline_secrets_counting(raw);
    assert!(!clean.contains("SECRET123456"));
    assert!(!clean.contains("1234567890abcdef"));
    assert!(!clean.contains("AIzaSyDummy"));
    assert!(!clean.contains("ghp_123456"));
    assert!(!clean.contains("xoxb-123456"));
    assert!(!clean.contains("mySecretBearerToken123"));
    assert!(!clean.contains("oauth_secret_value_99"));
    assert!(!clean.contains("super_secret_pw"));
    assert!(count >= 8, "expected >= 8 redactions, got {count}");
}

#[test]
fn chatgpt_blocks_never_exceed_1500_chars() {
    let huge_rules = "Rule line with unicode кириллица и детали. ".repeat(150);
    let input = TeleportSourceInput {
        global_claude_md: Some(huge_rules.clone()),
        projects: (0..6)
            .map(|i| TeleportProjectInput {
                slug: format!("-Users-dev-proj-{i}"),
                decoded_path: format!("/Users/dev/proj-{i}"),
                sessions_count: 5,
                memory_md: Some(huge_rules.clone()),
                last_query: Some(huge_rules.clone()),
            })
            .collect(),
        mcp_servers: vec!["filesystem".into(), "github".into()],
        cursor_rules: vec![("global".into(), huge_rules)],
        web_summaries: vec![("Chat 1".into(), "Summary".into())],
        ..Default::default()
    };

    let bundle = format_teleport_bundle(TeleportTarget::Chatgpt, &input);
    let instructions = bundle
        .files
        .iter()
        .find(|(name, _)| name == "CHATGPT_CUSTOM_INSTRUCTIONS.txt")
        .map(|(_, body)| body.as_str())
        .unwrap();

    let blocks: Vec<&str> = instructions.split("\n\n=== Block ").collect();
    assert_eq!(blocks.len(), 2);
    for (idx, blk) in blocks.iter().enumerate() {
        let len = blk.chars().count();
        assert!(
            len <= CHATGPT_BLOCK_CHAR_LIMIT,
            "ChatGPT block {} exceeded 1500 chars: {len}",
            idx + 1
        );
    }

    let (b1, b2) = build_chatgpt_instruction_blocks(&input);
    assert!(b1.chars().count() <= CHATGPT_BLOCK_CHAR_LIMIT);
    assert!(b2.chars().count() <= CHATGPT_BLOCK_CHAR_LIMIT);
}

#[test]
fn formats_all_four_targets_deterministically_without_secrets() {
    let input = TeleportSourceInput {
        global_claude_md: Some("Never leak sk-ant-api03-SECRET123".into()),
        projects: vec![TeleportProjectInput {
            slug: "-Users-alice-app".into(),
            decoded_path: "/Users/alice/app".into(),
            sessions_count: 3,
            memory_md: Some("Memory note with AIzaSySecretGoogleKey1234567890".into()),
            last_query: Some("Fix router".into()),
        }],
        mcp_servers: vec!["filesystem".into()],
        ..Default::default()
    };

    let gem = format_teleport_bundle(TeleportTarget::GeminiAntigravity, &input);
    assert_eq!(gem.files[0].0, "GEMINI.md");
    assert_eq!(gem.files[1].0, "SYSTEM_INSTRUCTIONS_GEMINI.txt");
    assert!(gem.secrets_redacted_count >= 2);
    assert!(!gem.primary_paste_text.contains("SECRET123"));

    let cur = format_teleport_bundle(TeleportTarget::Cursor, &input);
    assert_eq!(cur.files[0].0, ".cursor/rules/migrated-context.mdc");
    assert!(cur.files[0].1.starts_with("---\n"));
    assert!(cur.files[0].1.contains("alwaysApply: true"));
    assert!(!cur.files[0].1.contains("SECRET123"));

    let uni = format_teleport_bundle(TeleportTarget::Universal, &input);
    assert_eq!(uni.files[0].0, "RESTORE_PROMPT.md");
    assert!(!uni.files[0].1.contains("AIzaSySecret"));
}
