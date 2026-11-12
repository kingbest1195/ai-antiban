//! VS Code / Cursor / Windsurf / VSCodium / Antigravity `settings.json` handling (JSONC-safe).
//!
//! Zastava owns individual keys of the file, nothing else: every key goes through the ownership
//! journal (baseline -> intent -> point edit), the rest of the file is never rewritten. See
//! [`apply_settings_keys`] for the shared machinery that Claude Code / Gemini CLI settings use too.

use super::fs::Fs;
use super::journal::{Journal, ReportItem, Resource, Value};
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

/// Names of the proxy variables Zastava writes into an `env` object.
pub(super) const PROXY_VARS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

/// Names of the timezone / locale variables, written only while a timezone is synced. `LC_ALL` is
/// never among them: it overrides every other `LC_*` and breaks Ruby / Homebrew.
pub(super) const TZ_VARS: [&str; 3] = ["TZ", "LANG", "LC_TIME"];

/// Leftovers that may be removed: [`TZ_VARS`] plus the `LC_ALL` that 2.0.0 (and early 2.1 builds)
/// wrote. Only ever used to give a recorded key back or to clean by signature, never to write.
pub(super) const TZ_VARS_REMOVABLE: [&str; 4] = ["TZ", "LANG", "LC_TIME", "LC_ALL"];

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
) -> Result<Vec<ReportItem>, String> {
    let name = file.to_string_lossy().into_owned();
    if keys.is_empty() {
        // Nothing to write: only give back what Zastava recorded (no file is read or created).
        return Ok(retire_keys(j, p, &name, retire));
    }
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
    Ok(retire_keys(j, p, &name, retire))
}

/// Gives back the keys in `retire` that the journal records, then the objects (and the file)
/// Zastava created while nothing it owns is left in them. Returns what each step came to.
fn retire_keys(
    j: &mut Journal,
    p: &dyn Platform,
    name: &str,
    retire: &[Vec<String>],
) -> Vec<ReportItem> {
    let mut items = Vec::new();
    for path in retire {
        let res = key_res(name, path);
        if j.entry(&res).is_some() {
            items.extend(j.restore_one(p, &res));
        }
    }
    items.extend(release_unused_containers(j, p, name));
    items
}

/// A recorded object loses its record (and is removed when empty) once no recorded key is left
/// inside it; the same for a file Zastava created.
fn release_unused_containers(j: &mut Journal, p: &dyn Platform, name: &str) -> Vec<ReportItem> {
    let mut items = Vec::new();
    let objects: Vec<Resource> = j
        .entries()
        .iter()
        .filter(|e| matches!(&e.resource, Resource::JsonObject { file, .. } if file == name))
        .map(|e| e.resource.clone())
        .collect();
    for obj in objects {
        let Resource::JsonObject { path: inside, .. } = &obj else {
            continue;
        };
        let has_keys = j.entries().iter().any(|e| {
            matches!(&e.resource, Resource::JsonKey { file, path }
                if file == name && path.len() > inside.len() && path.starts_with(inside))
        });
        if !has_keys {
            items.extend(j.restore_one(p, &obj));
        }
    }
    let created: Vec<Resource> = j
        .entries()
        .iter()
        .filter(|e| matches!(&e.resource, Resource::File { file, .. } if file == name))
        .map(|e| e.resource.clone())
        .collect();
    let anything_left = j.entries().iter().any(|e| {
        matches!(&e.resource, Resource::JsonKey { file, .. } | Resource::JsonObject { file, .. }
            if file == name)
    });
    if !anything_left {
        for f in created {
            items.extend(j.restore_one(p, &f));
        }
    }
    items
}

/// Keys Zastava writes into an IDE `settings.json`, and the keys it gives back. The proxy keys
/// (`http.proxy`, `http.proxySupport`, the proxy variables of the integrated terminal) follow
/// `proxy_url`; the time zone / locale variables follow `tz`. The two are independent.
pub(super) fn ide_keys(
    proxy_url: Option<&str>,
    tz: Option<&str>,
) -> (Vec<KeySpec>, Vec<Vec<String>>) {
    let env = ide_env_key();
    let mut keys = Vec::new();
    let mut retire = Vec::new();
    match proxy_url {
        Some(url) => {
            keys.push(KeySpec::new(&["http.proxy"], url));
            keys.push(KeySpec::new(&["http.proxySupport"], "override"));
            keys.extend(proxy_env_keys(env, url));
        }
        None => {
            retire.push(vec!["http.proxy".to_string()]);
            retire.push(vec!["http.proxySupport".to_string()]);
            retire.extend(
                PROXY_VARS
                    .iter()
                    .map(|v| vec![env.to_string(), v.to_string()]),
            );
        }
    }
    let (tz_keys, tz_retire) = tz_key_specs(env, tz);
    keys.extend(tz_keys);
    retire.extend(tz_retire);
    (keys, retire)
}

/// The proxy variables of one `env` object: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`.
pub(super) fn proxy_env_keys(container: &str, proxy_url: &str) -> Vec<KeySpec> {
    PROXY_VARS
        .iter()
        .map(|v| {
            let value = if *v == "NO_PROXY" {
                NO_PROXY_VALUE
            } else {
                proxy_url
            };
            KeySpec::new(&[container, v], value)
        })
        .collect()
}

/// The time zone / locale variables of one `env` object (`TZ`, `LANG`, `LC_TIME`) when a zone is
/// given; otherwise they are all given back, `LC_ALL` of older builds included.
pub(super) fn tz_key_specs(container: &str, tz: Option<&str>) -> (Vec<KeySpec>, Vec<Vec<String>>) {
    let mut keys = Vec::new();
    let mut retire = Vec::new();
    match tz.and_then(super::shell_rc::sanitize_timezone) {
        Some(timezone) => {
            keys.push(KeySpec::new(&[container, "TZ"], &timezone));
            for v in &TZ_VARS[1..] {
                keys.push(KeySpec::new(&[container, v], super::shell_rc::SAFE_LOCALE));
            }
            retire.push(vec![container.to_string(), "LC_ALL".to_string()]);
        }
        None => retire.extend(
            TZ_VARS_REMOVABLE
                .iter()
                .map(|v| vec![container.to_string(), v.to_string()]),
        ),
    }
    (keys, retire)
}

/// Points an IDE `settings.json` at the Zastava proxy and / or syncs the time zone / locale.
pub(super) fn apply_ide_settings(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    settings_path: &Path,
    proxy_url: Option<&str>,
    tz: Option<&str>,
) -> Result<Vec<ReportItem>, String> {
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
