use super::*;
use std::fs;
use std::path::Path;

#[test]
fn test_decode_project_slug() {
    let slug = "-Users-putiniye-Documents-my-project";
    let decoded = decode_project_slug(slug);
    assert!(decoded.starts_with("/Users/putiniye/"));
}

#[test]
fn test_scan_and_export_claude_data() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let base = temp_dir.path();
    let home_dir = base.join("mock_home");
    let claude_dir = home_dir.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();

    // 1. Create mock projects
    let p1 = claude_dir
        .join("projects")
        .join("-Users-test-projects-app1");
    fs::create_dir_all(&p1).unwrap();
    let mem1 = p1.join("memory");
    fs::create_dir_all(&mem1).unwrap();
    fs::write(
        mem1.join("MEMORY.md"),
        "# Architecture Notes\nPostgreSQL + Actix",
    )
    .unwrap();

    let s1 = p1.join("session-abc.jsonl");
    let sample_jsonl = r#"{"type":"cost-state","totalCostUSD":0.12}
{"type":"last-prompt","lastPrompt":"Проверь статус базы данных и добавь миграцию"}"#;
    fs::write(&s1, sample_jsonl).unwrap();

    // 2. Create mock plans
    let plans_dir = claude_dir.join("plans");
    fs::create_dir_all(&plans_dir).unwrap();
    fs::write(
        plans_dir.join("v1-release.md"),
        "# План релиза v1.1.3\n- Задача 1\n- Задача 2",
    )
    .unwrap();

    // 3. Create loose files
    fs::write(claude_dir.join("CLAUDE.md"), "# Guidelines\nStrict Rust").unwrap();
    fs::write(home_dir.join(".claude.json"), r#"{"theme":"dark"}"#).unwrap();

    // Test Scanning
    let summary = scan_claude_dir(&claude_dir, &home_dir);
    assert!(summary.exists);
    assert_eq!(summary.projects_count, 1);
    assert_eq!(summary.sessions_count, 1);
    assert_eq!(summary.plans_count, 1);
    assert_eq!(summary.memory_files_count, 1);
    assert!(summary.has_claude_md);
    assert!(summary.has_claude_json);
    assert_eq!(summary.projects[0].slug, "-Users-test-projects-app1");
    assert!(summary.projects[0].has_memory);

    // Test Export
    let desktop = base.join("mock_desktop");
    fs::create_dir_all(&desktop).unwrap();

    let export_res =
        export_claude_dir_to(&claude_dir, &home_dir, &desktop).expect("export success");
    assert_eq!(export_res.projects_exported, 1);
    assert_eq!(export_res.sessions_exported, 1);
    assert!(Path::new(&export_res.index_summary_path).is_file());
    assert!(Path::new(&export_res.restore_prompt_path).is_file());

    let index_content = fs::read_to_string(&export_res.index_summary_path).unwrap();
    assert!(index_content.contains("Инженерная карта проектов"));
    assert!(index_content.contains("Проверь статус базы данных и добавь миграцию"));
    assert!(index_content.contains("v1-release.md"));

    let prompt_content = fs::read_to_string(&export_res.restore_prompt_path).unwrap();
    assert!(prompt_content.contains("Системная директива переноса инженерного контекста"));
    assert!(prompt_content.contains(&export_res.export_dir_path));
}
