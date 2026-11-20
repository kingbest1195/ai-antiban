//! Secret sanitization and private file/directory permission helpers for Data Bunker.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

const SECRET_EXACT_FILENAMES: &[&str] = &[
    ".credentials.json",
    "credentials.json",
    "cookies",
    "cookies-journal",
    "ant-device-registry.json",
    "ccd-ids.json",
    "dispatch-footprint-census.json",
    "state.vscdb",
    "state.vscdb.backup",
];

const SECRET_JSON_KEY_SUBSTRINGS: &[&str] = &[
    "oauth",
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "sessionkey",
    "session_key",
    "private_key",
    "auth_cookie",
    "bearer",
];

/// Ensures `dir` exists and has `0o700` permissions on Unix.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Applies `0o600` permissions to an existing file on Unix (no-op on Windows).
pub fn restrict_file_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Writes `bytes` to `path` with `0o600` permissions on Unix.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("Failed to write {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("Failed to write bytes to {}: {e}", path.display()))?;
    restrict_file_to_owner(path);
    Ok(())
}

/// Copies a single file privately (`0o600` on Unix) and returns its byte size.
pub fn copy_private_file(src: &Path, dst: &Path) -> Result<u64, String> {
    if let Some(parent) = dst.parent() {
        ensure_private_dir(parent)?;
    }
    let mut input =
        File::open(src).map_err(|e| format!("Failed to open {}: {e}", src.display()))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut output = opts
        .open(dst)
        .map_err(|e| format!("Failed to create {}: {e}", dst.display()))?;
    let bytes = std::io::copy(&mut input, &mut output)
        .map_err(|e| format!("Failed to copy {} -> {}: {e}", src.display(), dst.display()))?;
    restrict_file_to_owner(dst);
    Ok(bytes)
}

/// Returns `true` for credential/auth/session files that must NEVER enter a Bunker snapshot.
pub fn is_excluded_secret_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    if SECRET_EXACT_FILENAMES.contains(&lower.as_str()) {
        return true;
    }
    if lower.starts_with(".credentials")
        || lower.starts_with("state.vscdb")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "local storage" | "session storage" | "network" | "cache" | "code cache" | "gpucache"
    )
}

fn is_sensitive_json_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_JSON_KEY_SUBSTRINGS
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Recursively redacts OAuth, API key, token, password, and credential values in JSON.
pub fn sanitize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if is_sensitive_json_key(k) {
                    *v = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    sanitize_json_value(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                sanitize_json_value(item);
            }
        }
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.starts_with("sk-ant-")
                || trimmed.starts_with("sk-proj-")
                || trimmed.starts_with("sk-or-v1-")
                || (trimmed.starts_with("sk-") && trimmed.len() >= 24)
            {
                *s = "[REDACTED]".to_string();
            }
        }
        _ => {}
    }
}

/// Copies a JSON config file while redacting secret fields, falling back to private copy if non-JSON.
pub fn copy_sanitized_json_file(src: &Path, dst: &Path) -> Result<u64, String> {
    let raw =
        fs::read_to_string(src).map_err(|e| format!("Failed to read {}: {e}", src.display()))?;
    if let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
        sanitize_json_value(&mut parsed);
        let serialized = serde_json::to_vec_pretty(&parsed)
            .map_err(|e| format!("Failed to serialize sanitized JSON {}: {e}", dst.display()))?;
        write_private_file(dst, &serialized)?;
        return Ok(serialized.len() as u64);
    }
    write_private_file(dst, raw.as_bytes())?;
    Ok(raw.len() as u64)
}

/// Recursively copies a directory tree privately (`0o700` dirs / `0o600` files), skipping any
/// entry whose filename matches `is_excluded_secret_name`.
pub fn copy_private_dir_filtered(src: &Path, dst: &Path) -> Result<(usize, u64), String> {
    ensure_private_dir(dst)?;
    let mut files_count = 0usize;
    let mut total_bytes = 0u64;

    let entries =
        fs::read_dir(src).map_err(|e| format!("Failed to read {}: {e}", src.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if is_excluded_secret_name(&name) {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let (sub_files, sub_bytes) = copy_private_dir_filtered(&from, &to)?;
            files_count += sub_files;
            total_bytes += sub_bytes;
        } else if ft.is_file() {
            let bytes = if name.ends_with(".json") {
                copy_sanitized_json_file(&from, &to)?
            } else {
                copy_private_file(&from, &to)?
            };
            files_count += 1;
            total_bytes += bytes;
        }
    }

    Ok((files_count, total_bytes))
}

/// Extracts `mcpServers` keys from a Claude Desktop or Cursor `mcp.json` file.
pub fn extract_mcp_server_names(path: &Path) -> Vec<String> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let mut names: Vec<String> = val
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}
