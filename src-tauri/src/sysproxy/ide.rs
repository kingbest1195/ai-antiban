//! VS Code / Cursor / Windsurf / VSCodium / Antigravity `settings.json` handling (JSONC-safe).
//!
//! Zastava owns individual keys of the file, nothing else: every key goes through the ownership
//! journal (baseline -> intent -> point edit), the rest of the file is never rewritten. See
//! [`apply_settings_keys`] for the shared machinery that Claude Code / Gemini CLI settings use too.

use super::fs::Fs;
use super::journal::{Journal, Resource, Value};
use super::jsonc;
use super::platform::Platform;
use super::{FileCtx, NO_PROXY_VALUE};
use std::path::Path;

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

/// The key of the integrated terminal environment on this OS.
pub(super) fn ide_env_key() -> &'static str {
    if cfg!(target_os = "macos") {
        "terminal.integrated.env.osx"
    } else if cfg!(target_os = "windows") {
        "terminal.integrated.env.windows"
    } else {
        "terminal.integrated.env.linux"
    }
}

/// All three terminal environment keys (the file may be shared between machines).
pub(super) const IDE_ENV_KEYS: [&str; 3] = [
    "terminal.integrated.env.osx",
    "terminal.integrated.env.windows",
    "terminal.integrated.env.linux",
];

/// Names of the timezone / locale variables, written only when a timezone is synced.
pub(super) const TZ_VARS: [&str; 4] = ["TZ", "LANG", "LC_TIME", "LC_ALL"];

/// JSON text of a string value, exactly as it is written into the file.
pub(super) fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

/// One key Zastava owns: its path inside the file (outermost key first) and the JSON text.
pub(super) struct KeySpec {
    pub path: Vec<String>,
    pub raw: String,
}

impl KeySpec {
    pub fn new(path: &[&str], value: &str) -> Self {
        Self {
            path: path.iter().map(|s| s.to_string()).collect(),
            raw: json_str(value),
        }
    }
}

/// The bare file Zastava creates when a settings file does not exist yet.
const NEW_JSON_FILE: &str = "{}\n";

fn key_res(file: &str, path: &[String]) -> Resource {
    Resource::JsonKey {
        file: file.to_string(),
        path: path.to_vec(),
    }
}

fn object_res(file: &str, path: &[String]) -> Resource {
    Resource::JsonObject {
        file: file.to_string(),
        path: path.to_vec(),
    }
}

/// Writes `keys` into the settings file `file` through the journal and gives up the keys in
/// `retire` that Zastava owns but no longer wants (e.g. the timezone keys once no timezone is
/// synced).
///
/// Nothing is written when the file is damaged or ambiguous (syntax error anywhere, root that is
/// not an object, a repeated key among the ones touched, a path that crosses a non-object), when
/// it is not UTF-8, or when it cannot be read: the journal and the file stay as they were. A file
/// that does not exist yet is created (and removed again on restore while it is still bare).
/// Errors name an operation, never a value.
pub(super) fn apply_settings_keys(
    j: &mut Journal,
    p: &dyn Platform,
    fs: &dyn Fs,
    file: &Path,
    keys: &[KeySpec],
    retire: &[Vec<String>],
) -> Result<(), String> {
    let name = file.to_string_lossy().into_owned();
    let text = match fs.read(file) {
        Ok(None) => None,
        Ok(Some(b)) => Some(String::from_utf8(b).map_err(|_| "settings file is not UTF-8")?),
        Err(_) => return Err("settings file cannot be read".to_string()),
    };
    if let Some(t) = text.as_deref().filter(|t| !jsonc::is_blank(t)) {
        // Check everything first, so that a refusal leaves no half-applied state behind.
        jsonc::validate(t).map_err(|e| e.to_string())?;
        for k in keys {
            jsonc::get(t, &k.path.iter().map(String::as_str).collect::<Vec<_>>())
                .map_err(|e| e.to_string())?;
            if k.path.len() > 1 {
                let c: Vec<&str> = k.path[..k.path.len() - 1]
                    .iter()
                    .map(String::as_str)
                    .collect();
                jsonc::get(t, &c).map_err(|e| e.to_string())?;
            }
        }
    }
    let io = |e: super::journal::JournalError| e.to_string();
    if text.is_none() {
        let res = Resource::File {
            file: name.clone(),
            skeleton: NEW_JSON_FILE.to_string(),
        };
        j.apply(p, &res, Value::Present(true)).map_err(io)?;
    }
    // Objects first (created empty when missing), then the keys inside them.
    let mut done: Vec<&[String]> = Vec::new();
    for k in keys.iter().filter(|k| k.path.len() > 1) {
        let c = &k.path[..k.path.len() - 1];
        if !done.contains(&c) {
            done.push(c);
            j.apply(p, &object_res(&name, c), Value::Present(true))
                .map_err(io)?;
        }
    }
    for k in keys {
        j.apply(
            p,
            &key_res(&name, &k.path),
            Value::Json(Some(k.raw.clone())),
        )
        .map_err(io)?;
    }
    for path in retire {
        let res = key_res(&name, path);
        if j.entry(&res).is_some() {
            j.restore_one(p, &res);
        }
    }
    Ok(())
}

/// Keys Zastava writes into an IDE `settings.json`.
pub(super) fn ide_keys(proxy_url: &str, tz: Option<&str>) -> (Vec<KeySpec>, Vec<Vec<String>>) {
    let env = ide_env_key();
    let mut keys = vec![
        KeySpec::new(&["http.proxy"], proxy_url),
        KeySpec::new(&["http.proxySupport"], "override"),
        KeySpec::new(&[env, "HTTP_PROXY"], proxy_url),
        KeySpec::new(&[env, "HTTPS_PROXY"], proxy_url),
        KeySpec::new(&[env, "ALL_PROXY"], proxy_url),
        KeySpec::new(&[env, "NO_PROXY"], NO_PROXY_VALUE),
    ];
    let mut retire = Vec::new();
    match tz.and_then(super::shell_rc::sanitize_timezone) {
        Some(timezone) => {
            keys.push(KeySpec::new(&[env, "TZ"], &timezone));
            for v in &TZ_VARS[1..] {
                keys.push(KeySpec::new(&[env, v], "en_US.UTF-8"));
            }
        }
        None => retire.extend(TZ_VARS.iter().map(|v| vec![env.to_string(), v.to_string()])),
    }
    (keys, retire)
}

/// Points an IDE `settings.json` at the Zastava proxy (and optionally syncs timezone / locale).
pub(super) fn apply_ide_settings(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    settings_path: &Path,
    proxy_url: &str,
    tz: Option<&str>,
) -> Result<(), String> {
    let (keys, retire) = ide_keys(proxy_url, tz);
    apply_settings_keys(j, p, &*ctx.fs, settings_path, &keys, &retire)
}

/// The editors Zastava knows: label and the folder under the per-user application-data root.
pub(super) const IDES: [(&str, &str); 5] = [
    ("VS Code", "Code"),
    ("Cursor", "Cursor"),
    ("Windsurf", "Windsurf"),
    ("VSCodium", "VSCodium"),
    ("Antigravity", "Antigravity"),
];

/// Settings files of the installed editors (the `User` directory exists), under the roots of
/// the context.
pub(super) fn ide_candidates(ctx: &FileCtx) -> Vec<(&'static str, std::path::PathBuf)> {
    let mut result = Vec::new();
    for root in &ctx.ide_roots {
        for (label, folder) in IDES {
            let user_dir = root.join(folder).join("User");
            if ctx.fs.exists(&user_dir) {
                result.push((label, user_dir.join("settings.json")));
            }
        }
    }
    result
}

/// Settings files of the installed editors on this machine (real home / application data).
pub fn candidate_ide_settings_paths() -> Vec<(&'static str, std::path::PathBuf)> {
    FileCtx::real()
        .map(|c| ide_candidates(&c))
        .unwrap_or_default()
}
