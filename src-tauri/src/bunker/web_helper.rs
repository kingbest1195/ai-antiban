//! Local Web Export converter for Claude (`claude.ai`) and ChatGPT (`chatgpt.com`)
//! `conversations.json` and `export.zip` archives -> readable Markdown + `RESTORE_PROMPT.md`.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path};

use serde_json::Value;

use super::WebExportConvertResult;
use super::sanitize::{ensure_private_dir, write_private_file};
use super::web_parsers::{build_web_restore_prompt, parse_conversations, render_conversation_md};

pub const MAX_ZIP_ENTRIES: usize = 2000;
pub const MAX_ZIP_UNCOMPRESSED_BYTES: u64 = 100 * 1024 * 1024; // 100 MiB
const MAX_CONVERSATION_FILES: usize = 250;

/// Converts a Claude or ChatGPT `conversations.json` or `export.zip` into readable Markdown files
/// plus `RESTORE_PROMPT.md` inside `output_dir`.
pub fn convert_web_export_to(
    source_path: &Path,
    output_dir: &Path,
) -> Result<WebExportConvertResult, String> {
    if !source_path.is_file() {
        return Err(format!(
            "Файл экспорта не найден: {}",
            source_path.display()
        ));
    }

    let raw_json = load_conversations_json(source_path)?;
    let root: Value = serde_json::from_str(&raw_json)
        .map_err(|e| format!("Некорректный JSON в файле экспорта: {e}"))?;

    let (provider, conversations) = parse_conversations(&root)?;
    if conversations.is_empty() {
        return Err("В экспорте не найдено ни одного диалога.".to_string());
    }

    ensure_private_dir(output_dir)?;

    let mut markdown_files = Vec::new();
    let mut used_names = HashSet::new();
    for (idx, conv) in conversations
        .iter()
        .take(MAX_CONVERSATION_FILES)
        .enumerate()
    {
        let slug = sanitize_filename(&conv.title);
        let mut fname = format!("{:03}-{slug}.md", idx + 1);
        if !used_names.insert(fname.clone()) {
            fname = format!("{:03}-{slug}-{}.md", idx + 1, idx + 1);
            used_names.insert(fname.clone());
        }
        let target = output_dir.join(&fname);
        let md = render_conversation_md(conv, &provider);
        write_private_file(&target, md.as_bytes())?;
        markdown_files.push(target.to_string_lossy().to_string());
    }

    let restore_prompt = build_web_restore_prompt(&provider, &conversations, &markdown_files);
    let restore_prompt_path = output_dir.join("RESTORE_PROMPT.md");
    write_private_file(&restore_prompt_path, restore_prompt.as_bytes())?;

    Ok(WebExportConvertResult {
        source_path: source_path.to_string_lossy().to_string(),
        detected_provider: provider,
        output_dir: output_dir.to_string_lossy().to_string(),
        markdown_files,
        conversations_count: conversations.len(),
        restore_prompt_path: restore_prompt_path.to_string_lossy().to_string(),
        restore_prompt_preview: restore_prompt.chars().take(1500).collect(),
    })
}

fn is_zip_file(path: &Path) -> Result<bool, String> {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
    {
        return Ok(true);
    }
    let mut f = File::open(path).map_err(|e| format!("Не удалось открыть файл: {e}"))?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic).unwrap_or(0);
    Ok(n >= 2 && magic[0] == b'P' && magic[1] == b'K')
}

fn validate_zip_entry_name(name: &str) -> Result<(), String> {
    if name.contains('\0') || name.contains('\\') || name.starts_with('/') {
        return Err(format!("Небезопасный путь внутри ZIP-архива: {name}"));
    }
    let bytes = name.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(format!("Путь с буквой диска в ZIP-архиве запрещён: {name}"));
    }
    for comp in Path::new(name).components() {
        if matches!(
            comp,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(format!("Path traversal в ZIP-архиве запрещён: {name}"));
        }
    }
    Ok(())
}

fn load_conversations_json(source_path: &Path) -> Result<String, String> {
    if !is_zip_file(source_path)? {
        let meta =
            fs::metadata(source_path).map_err(|e| format!("Ошибка чтения метаданных: {e}"))?;
        if meta.len() > MAX_ZIP_UNCOMPRESSED_BYTES {
            return Err("Файл JSON превышает лимит 100 МБ.".to_string());
        }
        return fs::read_to_string(source_path)
            .map_err(|e| format!("Не удалось прочитать JSON: {e}"));
    }

    let file = File::open(source_path).map_err(|e| format!("Не удалось открыть ZIP-архив: {e}"))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("Не удалось разобрать ZIP-архив: {e}"))?;

    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(format!(
            "ZIP-архив отклонён: слишком много записей ({} > {MAX_ZIP_ENTRIES}).",
            archive.len()
        ));
    }

    let mut declared_total: u64 = 0;
    let mut target_index: Option<usize> = None;

    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| format!("Ошибка чтения записи #{i} в ZIP: {e}"))?;
        let name = entry.name().to_string();
        validate_zip_entry_name(&name)?;
        if entry.enclosed_name().is_none() {
            return Err(format!("Небезопасное имя записи в ZIP-архиве: {name}"));
        }
        declared_total = declared_total
            .checked_add(entry.size())
            .ok_or_else(|| "Переполнение размера ZIP-архива.".to_string())?;
        if declared_total > MAX_ZIP_UNCOMPRESSED_BYTES {
            return Err(
                "ZIP-архив отклонён: суммарный распакованный размер превышает 100 МБ.".to_string(),
            );
        }

        if !entry.is_dir() {
            let file_name = Path::new(&name)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if file_name.eq_ignore_ascii_case("conversations.json")
                && (target_index.is_none() || !name.contains('/'))
            {
                target_index = Some(i);
            }
        }
    }

    let idx = target_index.ok_or_else(|| {
        "В ZIP-архиве не найден файл conversations.json (поддерживаются официальные экспорты Claude и ChatGPT).".to_string()
    })?;

    let entry = archive
        .by_index(idx)
        .map_err(|e| format!("Не удалось открыть conversations.json в ZIP: {e}"))?;
    let mut buf = Vec::new();
    entry
        .take(MAX_ZIP_UNCOMPRESSED_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Ошибка распаковки conversations.json: {e}"))?;
    if buf.len() as u64 > MAX_ZIP_UNCOMPRESSED_BYTES {
        return Err(
            "ZIP-архив отклонён: фактический размер conversations.json превышает 100 МБ."
                .to_string(),
        );
    }

    String::from_utf8(buf).map_err(|e| format!("conversations.json не является UTF-8: {e}"))
}

fn sanitize_filename(title: &str) -> String {
    let mut out = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            out.push(c.to_ascii_lowercase());
        } else if (c.is_whitespace() || c == '.') && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= 48 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "conversation".to_string()
    } else {
        trimmed
    }
}
