//! Generating index summaries, restore prompts, and exporting Claude context bundles.

use chrono::Local;
use std::fs;
use std::path::{Path, PathBuf};

use super::scan::{decode_project_slug, extract_last_user_query_from_jsonl, scan_claude_dir};
use super::{
    ClaudeExportResult, ClaudeLocalDataSummary, get_claude_desktop_config_path, get_desktop_dir,
    get_home_dir,
};

use crate::core::sanitize::{
    copy_private_dir_filtered, copy_private_file, copy_sanitized_json_file, is_excluded_secret_name,
};

/// Helper that copies a file safely if it exists and is not an excluded secret file,
/// redacting sensitive fields in `.json` files.
fn copy_if_exists(src: &Path, dst: &Path) -> Option<u64> {
    if !src.is_file() {
        return None;
    }
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if is_excluded_secret_name(&name) {
        return None;
    }
    if name.ends_with(".json") {
        copy_sanitized_json_file(src, dst).ok()
    } else {
        copy_private_file(src, dst).ok()
    }
}

/// Recursively copies a directory tree with secret filtering and JSON redaction.
fn copy_dir_all(src: &Path, dst: &Path) -> Result<(usize, u64), String> {
    copy_private_dir_filtered(src, dst)
}

/// Generates the INDEX_SUMMARY.md map for the export package.
pub fn generate_index_summary_md(
    export_dir: &Path,
    summary: &ClaudeLocalDataSummary,
    project_queries: &[(String, String, Option<String>)], // (slug, decoded_path, last_query)
    plans: &[(String, String)],                           // (filename, first_line)
) -> String {
    let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let total_mb = summary.total_size_bytes as f64 / (1024.0 * 1024.0);

    let mut md = String::new();
    md.push_str("# Инженерная карта проектов и контекста Claude\n\n");
    md.push_str(&format!("> **Дата экспорта**: {now}\n"));
    md.push_str(&format!(
        "> **Объем данных**: {:.2} МБ · **Проектов**: {} · **Сессий (.jsonl)**: {} · **Планов**: {}\n\n",
        total_mb, summary.projects_count, summary.sessions_count, summary.plans_count
    ));
    md.push_str("---\n\n");

    md.push_str("## 1. Реестр проектов и рабочих областей\n\n");
    if summary.projects.is_empty() {
        md.push_str("_Локальные проекты не обнаружены._\n\n");
    } else {
        for p in &summary.projects {
            md.push_str(&format!("### Проект: `{}`\n", p.slug));
            md.push_str(&format!("- **Рабочий каталог**: `{}`\n", p.decoded_path));
            md.push_str(&format!(
                "- **Сессий в транскриптах**: {} (всего {:.1} КБ)\n",
                p.sessions_count,
                p.total_bytes as f64 / 1024.0
            ));

            let mem_link = export_dir
                .join("projects")
                .join(&p.slug)
                .join("memory")
                .join("MEMORY.md");
            if mem_link.exists() {
                md.push_str(&format!(
                    "- **Долговременная память**: [projects/{}/memory/MEMORY.md](projects/{}/memory/MEMORY.md)\n",
                    p.slug, p.slug
                ));
            } else if p.has_memory {
                md.push_str(&format!(
                    "- **Папка памяти**: `projects/{}/memory/`\n",
                    p.slug
                ));
            } else {
                md.push_str("- **Долговременная память**: _отсутствует_\n");
            }

            if let Some((_, _, last_query)) =
                project_queries.iter().find(|(slug, _, _)| slug == &p.slug)
                && let Some(q) = last_query
            {
                md.push_str(&format!(
                    "- **Последний контекст сессии**:\n  > {}\n",
                    q.replace('\n', " ")
                ));
            }
            md.push('\n');
        }
    }

    md.push_str("## 2. Планы реализации и архитектурные решения\n\n");
    if plans.is_empty() {
        md.push_str("_Глобальные планы в `plans/` не обнаружены._\n\n");
    } else {
        for (file_name, first_line) in plans {
            md.push_str(&format!(
                "- [plans/{file_name}](plans/{file_name}) — {}\n",
                first_line.trim_start_matches(['#', ' '])
            ));
        }
        md.push('\n');
    }

    md.push_str("## 3. Файлы конфигурации и окружения\n\n");
    md.push_str("- `configs/claude_desktop_config.json` — конфигурация MCP серверов (десктоп)\n");
    md.push_str("- `configs/claude_cli_config.json` — глобальные настройки CLI (~/.claude.json)\n");
    md.push_str("- `history.jsonl` — глобальная хронология команд\n");
    md.push_str("- `CLAUDE.md` — глобальные правила и гайдлайны разработки\n\n");

    md.push_str("---\n");
    md.push_str("_Сгенерировано Zastava v1.1.3 · Сетевой шлюз и защитник сессий ИИ_\n");
    md
}

/// Generates the RESTORE_PROMPT.md ready for copy-paste into any AI assistant.
pub fn generate_restore_prompt_md(export_dir_path: &str) -> String {
    format!(
        r#"# Системная директива переноса инженерного контекста

Ты — ведущий инженер-архитектор. Пользователь подключил архив полного рабочего контекста из предыдущей сессии разработки.

Корень архива контекста:
`{export_dir_path}`

Ключевые точки входа:
1. Инженерная карта проектов: `{export_dir_path}/INDEX_SUMMARY.md`
2. Директории проектов и сессий: `{export_dir_path}/projects/`
3. Директория планов: `{export_dir_path}/plans/`
4. Конфигурации MCP и CLI: `{export_dir_path}/configs/claude_desktop_config.json`, `{export_dir_path}/configs/claude_cli_config.json`

Контекст Cursor IDE и MCP:
- Проверь подключённые MCP-серверы в `{export_dir_path}/configs/claude_desktop_config.json` (Claude Desktop) и локальной конфигурации Cursor IDE (`~/.cursor/mcp.json`, настройки редактора и правила `.cursorrules`), если работа продолжается в Cursor IDE.
- Для полного резервного копирования Cursor IDE, MCP и санитизации секретов используй Data Bunker в Zastava.

Инструкция по развертыванию контекста:
1. Перед началом работы по любому проекту открой `{export_dir_path}/INDEX_SUMMARY.md`, найди нужный проект по имени или пути и прочитай его файл долговременной памяти `projects/<slug>/memory/MEMORY.md` (если существует) и последний транскрипт сессии `projects/<slug>/*.jsonl`.
2. Сохраняй стиль кодовой базы, архитектурные решения, стек технологий, правила `CLAUDE.md` / `.cursorrules`, настройки MCP-серверов и ограничения, зафиксированные в планах `plans/*.md`.
3. Не предлагай писать проект с нуля или переделывать рабочие модули без явного запроса. Продолжай разработку с точки, зафиксированной в последних запросах сессий.
"#
    )
}

/// Internal exporter that takes explicit source and destination folders.
pub fn export_claude_dir_to(
    claude_dir: &Path,
    home_dir: &Path,
    target_base: &Path,
) -> Result<ClaudeExportResult, String> {
    if !claude_dir.is_dir() {
        return Err(format!(
            "Директория Claude не найдена по пути: {}",
            claude_dir.display()
        ));
    }

    let timestamp = Local::now().format("%Y-%m-%d_%H%M%S").to_string();
    let export_dir_name = format!("Claude_Context_Backup_{timestamp}");
    let export_dir = target_base.join(&export_dir_name);

    fs::create_dir_all(&export_dir)
        .map_err(|e| format!("Не удалось создать директорию экспорта: {e}"))?;

    let mut total_bytes = 0u64;
    let mut projects_exported = 0;
    let mut sessions_exported = 0;

    // 1. Copy projects/
    let src_projects = claude_dir.join("projects");
    let dst_projects = export_dir.join("projects");
    let mut project_queries = Vec::new();

    if src_projects.is_dir() {
        fs::create_dir_all(&dst_projects)
            .map_err(|e| format!("Ошибка создания папки projects: {e}"))?;

        if let Ok(entries) = fs::read_dir(&src_projects) {
            for entry in entries.flatten() {
                let sp = entry.path();
                if sp.is_dir() {
                    let slug = sp
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let decoded_path = decode_project_slug(&slug);
                    let dp = dst_projects.join(&slug);

                    if let Ok((_cnt, b)) = copy_dir_all(&sp, &dp) {
                        total_bytes += b;
                        projects_exported += 1;
                    }

                    // Find latest session and extract last query
                    let mut latest_session_file: Option<PathBuf> = None;
                    let mut latest_mod = 0u64;

                    if let Ok(sub_entries) = fs::read_dir(&sp) {
                        for se in sub_entries.flatten() {
                            let s_path = se.path();
                            if s_path
                                .extension()
                                .map(|e| e.eq_ignore_ascii_case("jsonl"))
                                .unwrap_or(false)
                            {
                                sessions_exported += 1;
                                if let Ok(meta) = s_path.metadata()
                                    && let Ok(mod_time) = meta.modified()
                                    && let Ok(dur) = mod_time.duration_since(std::time::UNIX_EPOCH)
                                {
                                    let s = dur.as_secs();
                                    if s >= latest_mod {
                                        latest_mod = s;
                                        latest_session_file = Some(s_path);
                                    }
                                }
                            }
                        }
                    }

                    let last_q = latest_session_file
                        .as_deref()
                        .and_then(extract_last_user_query_from_jsonl);
                    project_queries.push((slug, decoded_path, last_q));
                }
            }
        }
    }

    // 2. Copy plans/
    let src_plans = claude_dir.join("plans");
    let dst_plans = export_dir.join("plans");
    let mut plans = Vec::new();

    if src_plans.is_dir() {
        fs::create_dir_all(&dst_plans).map_err(|e| format!("Ошибка создания папки plans: {e}"))?;
        if let Ok(entries) = fs::read_dir(&src_plans) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    let fname = p
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let target_plan = dst_plans.join(&fname);
                    if let Some(b) = copy_if_exists(&p, &target_plan) {
                        total_bytes += b;
                    }
                    let first_line = fs::read_to_string(&p)
                        .ok()
                        .and_then(|t| {
                            t.lines()
                                .find(|l| !l.trim().is_empty())
                                .map(|l| l.trim().to_string())
                        })
                        .unwrap_or_else(|| fname.clone());
                    plans.push((fname, first_line));
                }
            }
        }
    }

    // 3. Copy skills/ (if present)
    let src_skills = claude_dir.join("skills");
    let dst_skills = export_dir.join("skills");
    if src_skills.is_dir()
        && let Ok((_cnt, b)) = copy_dir_all(&src_skills, &dst_skills)
    {
        total_bytes += b;
    }

    // 4. Copy loose root artifacts
    for item in &["history.jsonl", "CLAUDE.md", "settings.json"] {
        let src = claude_dir.join(item);
        let dst = export_dir.join(item);
        if let Some(b) = copy_if_exists(&src, &dst) {
            total_bytes += b;
        }
    }

    // 5. Copy configs
    let dst_configs = export_dir.join("configs");
    let _ = fs::create_dir_all(&dst_configs);

    if let Some(desktop_cfg) = get_claude_desktop_config_path(home_dir) {
        let dst = dst_configs.join("claude_desktop_config.json");
        if let Some(b) = copy_if_exists(&desktop_cfg, &dst) {
            total_bytes += b;
        }
    }
    let cli_cfg = home_dir.join(".claude.json");
    if cli_cfg.is_file() {
        let dst = dst_configs.join("claude_cli_config.json");
        if let Some(b) = copy_if_exists(&cli_cfg, &dst) {
            total_bytes += b;
        }
    }

    // 6. Generate INDEX_SUMMARY.md & RESTORE_PROMPT.md
    let summary = scan_claude_dir(claude_dir, home_dir);
    let index_summary_content =
        generate_index_summary_md(&export_dir, &summary, &project_queries, &plans);
    let index_summary_path = export_dir.join("INDEX_SUMMARY.md");
    fs::write(&index_summary_path, &index_summary_content)
        .map_err(|e| format!("Ошибка создания INDEX_SUMMARY.md: {e}"))?;
    total_bytes += index_summary_content.len() as u64;

    let export_dir_str = export_dir.to_string_lossy().to_string();
    let restore_prompt_text = generate_restore_prompt_md(&export_dir_str);
    let restore_prompt_path = export_dir.join("RESTORE_PROMPT.md");
    fs::write(&restore_prompt_path, &restore_prompt_text)
        .map_err(|e| format!("Ошибка создания RESTORE_PROMPT.md: {e}"))?;
    total_bytes += restore_prompt_text.len() as u64;

    // 7. Zip packing (safe fallback if archiver is unavailable)
    let zip_filename = format!("{export_dir_name}.zip");
    let zip_path = target_base.join(&zip_filename);
    let zip_res = pack_directory_to_zip(&export_dir, &zip_path);

    let zip_archive_path = if zip_res.is_ok() && zip_path.is_file() {
        Some(zip_path.to_string_lossy().to_string())
    } else {
        None
    };

    Ok(ClaudeExportResult {
        export_dir_path: export_dir_str,
        zip_archive_path,
        index_summary_path: index_summary_path.to_string_lossy().to_string(),
        restore_prompt_path: restore_prompt_path.to_string_lossy().to_string(),
        restore_prompt_text,
        projects_exported,
        sessions_exported,
        total_bytes,
    })
}

/// Packs export directory into `.zip` in-process using the `zip` crate (zero child processes).
pub(super) fn pack_directory_to_zip(dir: &Path, zip_file: &Path) -> Result<(), String> {
    if !dir.is_dir() {
        return Err(format!(
            "Директория для упаковки не найдена: {}",
            dir.display()
        ));
    }
    let root_name = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("Некорректное имя директории: {}", dir.display()))?;

    let file =
        fs::File::create(zip_file).map_err(|e| format!("Не удалось создать ZIP-файл: {e}"))?;
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    if let Err(err) = write_dir_to_zip(&mut writer, dir, &root_name, options) {
        drop(writer);
        let _ = fs::remove_file(zip_file);
        return Err(err);
    }

    writer
        .finish()
        .map_err(|e| format!("Не удалось финализировать ZIP-архив: {e}"))?;
    Ok(())
}

fn write_dir_to_zip(
    writer: &mut zip::ZipWriter<fs::File>,
    dir: &Path,
    rel_prefix: &str,
    options: zip::write::SimpleFileOptions,
) -> Result<(), String> {
    writer
        .add_directory(format!("{rel_prefix}/"), options)
        .map_err(|e| format!("Ошибка добавления каталога в ZIP ({rel_prefix}): {e}"))?;

    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("Ошибка чтения каталога {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() {
            continue;
        }
        let entry_zip_path = format!("{rel_prefix}/{name}");
        let path = entry.path();
        if ft.is_dir() {
            write_dir_to_zip(writer, &path, &entry_zip_path, options)?;
        } else if ft.is_file() {
            writer
                .start_file(&entry_zip_path, options)
                .map_err(|e| format!("Ошибка записи файла в ZIP ({entry_zip_path}): {e}"))?;
            let mut src = fs::File::open(&path)
                .map_err(|e| format!("Не удалось открыть файл {}: {e}", path.display()))?;
            std::io::copy(&mut src, writer)
                .map_err(|e| format!("Ошибка сжатия файла {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// Public API to export local Claude data onto the user's Desktop.
pub fn export_claude_local_data() -> Result<ClaudeExportResult, String> {
    let home =
        get_home_dir().ok_or_else(|| "Домашняя директория пользователя не найдена.".to_string())?;
    let claude_dir = home.join(".claude");
    let desktop = get_desktop_dir(&home);
    export_claude_dir_to(&claude_dir, &home, &desktop)
}
