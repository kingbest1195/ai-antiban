use super::*;

#[test]
fn env_files_are_excluded_case_insensitively() {
    assert!(is_excluded_secret_name(".env"));
    assert!(is_excluded_secret_name(".ENV"));
    assert!(is_excluded_secret_name(".env.local"));
    assert!(is_excluded_secret_name(".env.production"));
    assert!(!is_excluded_secret_name("notes.md"));
}

#[test]
fn sanitize_json_value_redacts_embedded_tokens() {
    let mut val = serde_json::json!({
        "note": "Use ANTHROPIC_API_KEY=sk-ant-api03-1234567890abcdef and Bearer eyJhbGciOiJIUzI1NiJ9.payload",
        "gh": "token ghp_1234567890abcdef123456 and AIzaSyDummyKey1234567890123",
        "slack": "bot xoxb-1234567890-abcdef",
        "safe": "normal disk-12345678901234567890 text"
    });
    sanitize_json_value(&mut val);
    let note = val["note"].as_str().unwrap();
    assert!(!note.contains("sk-ant-api03"), "{note}");
    assert!(!note.contains("eyJhbGci"), "{note}");
    let gh = val["gh"].as_str().unwrap();
    assert!(!gh.contains("ghp_1234"), "{gh}");
    assert!(!gh.contains("AIzaSy"), "{gh}");
    let slack = val["slack"].as_str().unwrap();
    assert!(!slack.contains("xoxb-1234"), "{slack}");
    assert_eq!(
        val["safe"].as_str().unwrap(),
        "normal disk-12345678901234567890 text"
    );
}

#[test]
fn copy_private_dir_filtered_excludes_env_and_redacts_jsonl_and_uppercase_json() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    fs::create_dir_all(&src).unwrap();

    fs::write(
        src.join(".env"),
        "ANTHROPIC_API_KEY=sk-ant-api03-secret12345",
    )
    .unwrap();
    fs::write(src.join(".env.local"), "OPENAI_API_KEY=sk-proj-secret12345").unwrap();
    fs::write(
        src.join("session.jsonl"),
        "{\"msg\":\"hello sk-ant-api03-secret99999\"}\n{\"api_key\":\"secret-val\"}\n",
    )
    .unwrap();
    fs::write(
        src.join("CONFIG.JSON"),
        "{\"note\":\"OPENAI_API_KEY=sk-proj-abc12345678\"}",
    )
    .unwrap();

    copy_private_dir_filtered(&src, &dst).unwrap();
    assert!(!dst.join(".env").exists());
    assert!(!dst.join(".env.local").exists());

    let jsonl = fs::read_to_string(dst.join("session.jsonl")).unwrap();
    assert!(!jsonl.contains("sk-ant-api03"), "{jsonl}");
    assert!(!jsonl.contains("secret-val"), "{jsonl}");
    assert!(jsonl.contains("[REDACTED]"), "{jsonl}");

    let cfg = fs::read_to_string(dst.join("CONFIG.JSON")).unwrap();
    assert!(!cfg.contains("sk-proj-abc"), "{cfg}");
    assert!(cfg.contains("[REDACTED]"), "{cfg}");
}
