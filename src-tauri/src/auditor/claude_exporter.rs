use chrono::Local;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Brief summary of a single project detected in ~/.claude/projects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeProjectBrief {
    pub slug: String,
    pub decoded_path: String,
    pub sessions_count: usize,
    pub has_memory: bool,
    pub total_bytes: u64,
    pub last_modified: Option<u64>,
}

/// Comprehensive scan result of local Claude Code and Claude Desktop artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaudeLocalDataSummary {
    pub exists: bool,
    pub claude_dir_path: String,
    pub projects_count: usize,
    pub sessions_count: usize,
    pub plans_count: usize,
    pub memory_files_count: usize,
    pub total_size_bytes: u64,
    pub projects: Vec<ClaudeProjectBrief>,
    pub has_claude_md: bool,
    pub has_history: bool,
    pub has_settings: bool,
    pub has_desktop_config: bool,
    pub has_claude_json: bool,
}

/// Result returned after exporting local Claude artifacts to Desktop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaudeExportResult {
    pub export_dir_path: String,
    pub zip_archive_path: Option<String>,
    pub index_summary_path: String,
    pub restore_prompt_path: String,
    pub restore_prompt_text: String,
    pub projects_exported: usize,
    pub sessions_exported: usize,
    pub total_bytes: u64,
}

pub fn get_home_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERPROFILE")
            .ok()
            .map(PathBuf::from)
            .or_else(|| std::env::var("HOME").ok().map(PathBuf::from))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
}

pub fn get_desktop_dir(home: &Path) -> PathBuf {
    let desktop = home.join("Desktop");
    if desktop.is_dir() {
        desktop
    } else {
        home.to_path_buf()
    }
}

pub fn get_claude_desktop_config_path(home: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let p = home
            .join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json");
        if p.exists() {
            return Some(p);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let p = PathBuf::from(appdata)
                .join("Claude")
                .join("claude_desktop_config.json");
            if p.exists() {
                return Some(p);
            }
        }
        let fallback = home
            .join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude_desktop_config.json");
        if fallback.exists() {
            return Some(fallback);
        }
    }
    None
}

/// Decodes Claude project slug (e.g. `-Users-putiniye-local-projects-cf-scanner`) into a clean path.
pub fn decode_project_slug(slug: &str) -> String {
    if slug.starts_with('-') {
        let parts: Vec<&str> = slug.trim_start_matches('-').split('-').collect();
        let mut resolved = PathBuf::from("/");
        let mut idx = 0;
        let mut found_on_fs = true;

        while idx < parts.len() {
            let mut matched = false;
            for end in (idx + 1..=parts.len()).rev() {
                let candidate_name = parts[idx..end].join("-");
                let candidate_path = resolved.join(&candidate_name);
                if candidate_path.exists() {
                    resolved = candidate_path;
                    idx = end;
                    matched = true;
                    break;
                }
            }
            if !matched {
                found_on_fs = false;
                break;
            }
        }

        if found_on_fs && resolved != Path::new("/") {
            return resolved.to_string_lossy().to_string();
        }

        format!("/{}", slug.trim_start_matches('-').replace('-', "/"))
    } else if slug.len() > 2
        && slug.chars().nth(1) == Some('-')
        && slug.chars().next().unwrap().is_ascii_alphabetic()
    {
        let drive = slug.chars().next().unwrap();
        let rest = &slug[2..];
        format!("{drive}:\\{}", rest.replace('-', "\\"))
    } else {
        slug.to_string()
    }
}

/// Scans the given directory tree to compute total bytes and file count.
fn dir_size_and_count(dir: &Path) -> (u64, usize) {
    let mut total_bytes = 0;
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let (b, c) = dir_size_and_count(&p);
                total_bytes += b;
                count += c;
            } else if p.is_file()
                && let Ok(meta) = fs::metadata(&p)
            {
                total_bytes += meta.len();
                count += 1;
            }
        }
    }
    (total_bytes, count)
}

/// Safely extracts the last user prompt / topic from a .jsonl session transcript.
/// Reads only the trailing 64KB to avoid loading multi-megabyte files into memory.
pub fn extract_last_user_query_from_jsonl(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let file_len = metadata.len();
    if file_len == 0 {
        return None;
    }

    let read_size = file_len.min(65536) as usize;
    let seek_offset = file_len.saturating_sub(read_size as u64);
    file.seek(SeekFrom::Start(seek_offset)).ok()?;

    let mut buf = vec![0u8; read_size];
    file.read_exact(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);

    let lines: Vec<&str> = text.lines().collect();
    for line in lines.into_iter().rev() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(prompt) = val.get("lastPrompt").and_then(|p| p.as_str()) {
                let clean = prompt.trim();
                if !clean.is_empty() {
                    return Some(clean.chars().take(240).collect());
                }
            }
            if let Some(summary) = val.get("content").and_then(|c| c.as_str()) {
                let clean = summary.trim();
                if !clean.is_empty() {
                    return Some(clean.chars().take(240).collect());
                }
            }
            if let Some(msg) = val.get("message")
                && let Some(c) = msg.get("content").and_then(|c| c.as_str())
            {
                let clean = c.trim();
                if !clean.is_empty() {
                    return Some(clean.chars().take(240).collect());
                }
            }
        }
    }
    None
}

/// Scans a target Claude folder. Used by public scan and tests.
pub fn scan_claude_dir(claude_dir: &Path, home_dir: &Path) -> ClaudeLocalDataSummary {
    if !claude_dir.is_dir() {
        return ClaudeLocalDataSummary {
            exists: false,
            claude_dir_path: claude_dir.to_string_lossy().to_string(),
            projects_count: 0,
            sessions_count: 0,
            plans_count: 0,
            memory_files_count: 0,
            total_size_bytes: 0,
            projects: Vec::new(),
            has_claude_md: false,
            has_history: false,
            has_settings: false,
            has_desktop_config: false,
            has_claude_json: false,
        };
    }

    let mut projects = Vec::new();
    let mut total_sessions = 0;
    let mut total_memory_files = 0;

    let projects_dir = claude_dir.join("projects");
    if projects_dir.is_dir()
        && let Ok(entries) = fs::read_dir(&projects_dir)
    {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                let slug = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let decoded_path = decode_project_slug(&slug);

                let mut sessions_count = 0;
                let mut proj_bytes = 0;
                let mut latest_mod: Option<u64> = None;
                let mut has_mem = false;

                if let Ok(p_entries) = fs::read_dir(&p) {
                    for sub_entry in p_entries.flatten() {
                        let sp = sub_entry.path();
                        if sp.is_file() {
                            if let Ok(meta) = sp.metadata() {
                                proj_bytes += meta.len();
                                if let Ok(mod_time) = meta.modified()
                                    && let Ok(dur) = mod_time.duration_since(std::time::UNIX_EPOCH)
                                {
                                    let s = dur.as_secs();
                                    latest_mod = Some(latest_mod.map_or(s, |m| m.max(s)));
                                }
                            }
                            if sp
                                .extension()
                                .map(|e| e.eq_ignore_ascii_case("jsonl"))
                                .unwrap_or(false)
                            {
                                sessions_count += 1;
                            }
                        } else if sp.is_dir()
                            && sp.file_name().map(|n| n == "memory").unwrap_or(false)
                        {
                            has_mem = true;
                            if let Ok(mem_entries) = fs::read_dir(&sp) {
                                for me in mem_entries.flatten() {
                                    if me.path().is_file() {
                                        total_memory_files += 1;
                                        if let Ok(meta) = me.metadata() {
                                            proj_bytes += meta.len();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                total_sessions += sessions_count;
                projects.push(ClaudeProjectBrief {
                    slug,
                    decoded_path,
                    sessions_count,
                    has_memory: has_mem,
                    total_bytes: proj_bytes,
                    last_modified: latest_mod,
                });
            }
        }
    }

    // Sort projects: descending by session count, then descending by bytes
    projects.sort_by(|a, b| {
        b.sessions_count
            .cmp(&a.sessions_count)
            .then_with(|| b.total_bytes.cmp(&a.total_bytes))
    });

    let plans_dir = claude_dir.join("plans");
    let mut plans_count = 0;
    if plans_dir.is_dir()
        && let Ok(entries) = fs::read_dir(&plans_dir)
    {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                plans_count += 1;
            }
        }
    }

    let has_claude_md = claude_dir.join("CLAUDE.md").is_file();
    let has_history = claude_dir.join("history.jsonl").is_file();
    let has_settings = claude_dir.join("settings.json").is_file();
    let has_claude_json = home_dir.join(".claude.json").is_file();
    let has_desktop_config = get_claude_desktop_config_path(home_dir).is_some();

    let (total_size_bytes, _) = dir_size_and_count(claude_dir);

    ClaudeLocalDataSummary {
        exists: true,
        claude_dir_path: claude_dir.to_string_lossy().to_string(),
        projects_count: projects.len(),
        sessions_count: total_sessions,
        plans_count,
        memory_files_count: total_memory_files,
        total_size_bytes,
        projects,
        has_claude_md,
        has_history,
        has_settings,
        has_desktop_config,
        has_claude_json,
    }
}

/// Public scanner that inspects the current user's ~/.claude folder.
pub fn scan_claude_local_data() -> ClaudeLocalDataSummary {
    let home = match get_home_dir() {
        Some(h) => h,
        None => {
            return ClaudeLocalDataSummary {
                exists: false,
                claude_dir_path: String::new(),
                projects_count: 0,
                sessions_count: 0,
                plans_count: 0,
                memory_files_count: 0,
                total_size_bytes: 0,
                projects: Vec::new(),
                has_claude_md: false,
                has_history: false,
                has_settings: false,
                has_desktop_config: false,
                has_claude_json: false,
            };
        }
    };

    let claude_dir = home.join(".claude");
    scan_claude_dir(&claude_dir, &home)
}

/// Helper that copies a file if it exists, creating parent folders.
fn copy_if_exists(src: &Path, dst: &Path) -> Option<u64> {
    if src.is_file() {
        if let Some(parent) = dst.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::copy(src, dst).is_ok() {
            return fs::metadata(dst).ok().map(|m| m.len());
        }
    }
    None
}

/// Recursively copies a directory tree.
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<(usize, u64)> {
    fs::create_dir_all(dst)?;
    let mut files = 0;
    let mut bytes = 0;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            let (f, b) = copy_dir_all(&from, &to)?;
            files += f;
            bytes += b;
        } else if ty.is_file() {
            fs::copy(&from, &to)?;
            if let Ok(meta) = fs::metadata(&to) {
                bytes += meta.len();
            }
            files += 1;
        }
    }
    Ok((files, bytes))
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

Инструкция по развертыванию контекста:
1. Перед началом работы по любому проекту открой `{export_dir_path}/INDEX_SUMMARY.md`, найди нужный проект по имени или пути и прочитай его файл долговременной памяти `projects/<slug>/memory/MEMORY.md` (если существует) и последний транскрипт сессии `projects/<slug>/*.jsonl`.
2. Сохраняй стиль кодовой базы, архитектурные решения, стек технологий и ограничения, зафиксированные в планах `plans/*.md`.
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

/// Packs export directory into .zip using native platform tools.
fn pack_directory_to_zip(dir: &Path, zip_file: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Use macOS native ditto for cleanest zip preservation
        let status = crate::sysproxy::silent_command("ditto")
            .args([
                "-c",
                "-k",
                "--sequesterRsrc",
                "--keepParent",
                &dir.to_string_lossy(),
                &zip_file.to_string_lossy(),
            ])
            .status()
            .map_err(|e| format!("ditto error: {e}"))?;
        if status.success() {
            return Ok(());
        }
        // Fallback to zip
        let status2 = crate::sysproxy::silent_command("zip")
            .args([
                "-r",
                "-q",
                &zip_file.to_string_lossy(),
                &dir.file_name().unwrap().to_string_lossy(),
            ])
            .current_dir(dir.parent().unwrap())
            .status()
            .map_err(|e| format!("zip error: {e}"))?;
        if status2.success() {
            return Ok(());
        }
        Err("macOS zip command failed".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        let cmd = format!(
            "Compress-Archive -Path '{}' -DestinationPath '{}' -Force",
            dir.display(),
            zip_file.display()
        );
        let status = crate::sysproxy::silent_command("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .status()
            .map_err(|e| format!("PowerShell Compress-Archive error: {e}"))?;
        if status.success() {
            return Ok(());
        }
        return Err("Windows zip compression failed".to_string());
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let status = crate::sysproxy::silent_command("zip")
            .args([
                "-r",
                "-q",
                &zip_file.to_string_lossy(),
                &dir.file_name().unwrap().to_string_lossy(),
            ])
            .current_dir(dir.parent().unwrap())
            .status()
            .map_err(|e| format!("zip error: {e}"))?;
        if status.success() {
            return Ok(());
        }
        Err("Linux zip compression failed".to_string())
    }
}

/// Public API to export local Claude data onto the user's Desktop.
pub fn export_claude_local_data() -> Result<ClaudeExportResult, String> {
    let home =
        get_home_dir().ok_or_else(|| "Домашняя директория пользователя не найдена.".to_string())?;
    let claude_dir = home.join(".claude");
    let desktop = get_desktop_dir(&home);
    export_claude_dir_to(&claude_dir, &home, &desktop)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
