//! VS Code / Cursor / Windsurf / VSCodium / Antigravity `settings.json` handling (JSONC-safe).

#[cfg(not(target_os = "windows"))]
use super::user_home_dir;
use super::{is_zastava_local_proxy_val, NO_PROXY_VALUE};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Strips `//` and `/* */` comments outside JSON string literals and removes trailing commas
/// so VS Code `settings.json` (JSONC) can be safely parsed by `serde_json`.
pub fn sanitize_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut in_string = false;

    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                i += 1;
                out.push(chars[i]);
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
            continue;
        }

        // Line comment //
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            i += 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }

        // Block comment /* ... */
        if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            continue;
        }

        out.push(c);
        i += 1;
    }

    // Remove trailing commas before `}` or `]` outside strings
    let chars2: Vec<char> = out.chars().collect();
    let mut final_out = String::with_capacity(out.len());
    let mut j = 0;
    let mut in_str = false;
    while j < chars2.len() {
        let c = chars2[j];
        if in_str {
            final_out.push(c);
            if c == '\\' && j + 1 < chars2.len() {
                j += 1;
                final_out.push(chars2[j]);
            } else if c == '"' {
                in_str = false;
            }
            j += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            final_out.push(c);
            j += 1;
            continue;
        }
        if c == ',' {
            let mut k = j + 1;
            while k < chars2.len() && chars2[k].is_whitespace() {
                k += 1;
            }
            if k < chars2.len() && (chars2[k] == '}' || chars2[k] == ']') {
                j += 1;
                continue;
            }
        }
        final_out.push(c);
        j += 1;
    }

    final_out
}

fn ide_env_key() -> &'static str {
    if cfg!(target_os = "macos") {
        "terminal.integrated.env.osx"
    } else if cfg!(target_os = "windows") {
        "terminal.integrated.env.windows"
    } else {
        "terminal.integrated.env.linux"
    }
}

/// Applies Zastava proxy configuration to a VS Code / Cursor / Windsurf `settings.json` file.
pub fn apply_ide_settings_file(settings_path: &Path, proxy_url: &str) -> Result<bool, String> {
    apply_ide_settings_file_with_tz(settings_path, proxy_url, None)
}

/// Applies Zastava proxy and optional timezone/locale configuration to a VS Code / Cursor / Windsurf `settings.json` file.
pub fn apply_ide_settings_file_with_tz(
    settings_path: &Path,
    proxy_url: &str,
    tz: Option<&str>,
) -> Result<bool, String> {
    let raw = if settings_path.exists() {
        fs::read_to_string(settings_path).map_err(|e| e.to_string())?
    } else {
        "{}".to_string()
    };

    let clean = if raw.trim().is_empty() {
        "{}".to_string()
    } else {
        sanitize_jsonc(&raw)
    };

    let mut root: Value = serde_json::from_str(&clean).map_err(|e| e.to_string())?;
    let Some(obj) = root.as_object_mut() else {
        return Ok(false);
    };

    obj.insert("http.proxy".to_string(), Value::String(proxy_url.to_string()));
    obj.insert(
        "http.proxySupport".to_string(),
        Value::String("override".to_string()),
    );

    let env_key = ide_env_key();
    let env_entry = obj
        .entry(env_key.to_string())
        .or_insert_with(|| json!({}));
    if !env_entry.is_object() {
        *env_entry = json!({});
    }
    if let Some(env_map) = env_entry.as_object_mut() {
        env_map.insert("HTTP_PROXY".to_string(), Value::String(proxy_url.to_string()));
        env_map.insert("HTTPS_PROXY".to_string(), Value::String(proxy_url.to_string()));
        env_map.insert("ALL_PROXY".to_string(), Value::String(proxy_url.to_string()));
        env_map.insert(
            "NO_PROXY".to_string(),
            Value::String(NO_PROXY_VALUE.to_string()),
        );
        if let Some(timezone) = tz.and_then(super::shell_rc::sanitize_timezone) {
            env_map.insert("TZ".to_string(), Value::String(timezone));
            env_map.insert("LANG".to_string(), Value::String("en_US.UTF-8".to_string()));
            env_map.insert("LC_TIME".to_string(), Value::String("en_US.UTF-8".to_string()));
            env_map.insert("LC_ALL".to_string(), Value::String("en_US.UTF-8".to_string()));
        }
    }

    let formatted = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    fs::write(settings_path, format!("{formatted}\n")).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Removes Zastava local proxy keys from a VS Code / Cursor / Windsurf `settings.json` file
/// when Zastava exits or when protection is turned off, preserving all other user settings.
pub fn cleanup_ide_settings_file(settings_path: &Path) -> Result<bool, String> {
    if !settings_path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(settings_path).map_err(|e| e.to_string())?;
    let clean = sanitize_jsonc(&raw);
    let mut root: Value = serde_json::from_str(&clean).map_err(|e| e.to_string())?;
    let Some(obj) = root.as_object_mut() else {
        return Ok(false);
    };

    let mut changed = false;
    if let Some(val) = obj.get("http.proxy").and_then(|v| v.as_str()) {
        if is_zastava_local_proxy_val(val) {
            obj.remove("http.proxy");
            obj.remove("http.proxySupport");
            changed = true;
        }
    }

    for env_key in [
        "terminal.integrated.env.osx",
        "terminal.integrated.env.windows",
        "terminal.integrated.env.linux",
    ] {
        let mut remove_entire_env_obj = false;
        if let Some(env_map) = obj.get_mut(env_key).and_then(|v| v.as_object_mut()) {
            let matches_zastava = env_map
                .get("HTTPS_PROXY")
                .or_else(|| env_map.get("HTTP_PROXY"))
                .and_then(|v| v.as_str())
                .map(is_zastava_local_proxy_val)
                .unwrap_or(false);

            if matches_zastava {
                env_map.remove("HTTP_PROXY");
                env_map.remove("HTTPS_PROXY");
                env_map.remove("ALL_PROXY");
                env_map.remove("NO_PROXY");
                env_map.remove("TZ");
                env_map.remove("LANG");
                env_map.remove("LC_TIME");
                env_map.remove("LC_ALL");
                changed = true;
            }
            if env_map.is_empty() {
                remove_entire_env_obj = true;
            }
        }
        if remove_entire_env_obj {
            obj.remove(env_key);
        }
    }

    if changed {
        let formatted = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
        fs::write(settings_path, format!("{formatted}\n")).map_err(|e| e.to_string())?;
    }
    Ok(changed)
}

pub fn candidate_ide_settings_paths() -> Vec<(&'static str, PathBuf)> {
    let mut result = Vec::new();
    let ides = [
        ("VS Code", "Code"),
        ("Cursor", "Cursor"),
        ("Windsurf", "Windsurf"),
        ("VSCodium", "VSCodium"),
        ("Antigravity", "Antigravity"),
    ];

    #[cfg(target_os = "macos")]
    if let Some(home) = user_home_dir() {
        let base = home.join("Library").join("Application Support");
        for (label, folder) in ides {
            let user_dir = base.join(folder).join("User");
            if user_dir.is_dir() {
                result.push((label, user_dir.join("settings.json")));
            }
        }
    }

    #[cfg(target_os = "windows")]
    if let Some(appdata) = super::user_appdata_dir() {
        for (label, folder) in ides {
            let user_dir = appdata.join(folder).join("User");
            if user_dir.is_dir() {
                result.push((label, user_dir.join("settings.json")));
            }
        }
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(home) = user_home_dir() {
        let base = home.join(".config");
        for (label, folder) in ides {
            let user_dir = base.join(folder).join("User");
            if user_dir.is_dir() {
                result.push((label, user_dir.join("settings.json")));
            }
        }
    }

    result
}
