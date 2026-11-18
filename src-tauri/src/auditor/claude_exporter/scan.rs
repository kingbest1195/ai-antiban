//! Scanning local ~/.claude projects, session transcripts, and plans.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::{
    ClaudeLocalDataSummary, ClaudeProjectBrief, get_claude_desktop_config_path, get_home_dir,
};

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
