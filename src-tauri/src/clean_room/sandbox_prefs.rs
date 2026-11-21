//! Fail-closed Chromium `Preferences`, `First Run` sentinel, country->`Accept-Language`
//! mapping, and `.zastava-sandbox.json` PID/port metadata persistence.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

pub const SANDBOX_META_FILENAME: &str = ".zastava-sandbox.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxMeta {
    pub pid: u32,
    pub alias_port: u16,
}

/// Maps an exit ISO country code to an HTTP `Accept-Language` / `navigator.languages` string.
pub fn accept_languages_for_country(country: Option<&str>) -> &'static str {
    let code = country.map(str::trim).unwrap_or("").to_ascii_uppercase();
    match code.as_str() {
        "US" => "en-US,en",
        "GB" | "UK" => "en-GB,en",
        "CA" => "en-CA,en",
        "AU" => "en-AU,en",
        "SG" => "en-SG,en",
        "IN" => "en-IN,en",
        "DE" => "de-DE,de,en",
        "AT" => "de-AT,de,en",
        "CH" => "de-CH,de,fr,en",
        "NL" => "nl-NL,nl,en",
        "FR" => "fr-FR,fr,en",
        "ES" => "es-ES,es,en",
        "IT" => "it-IT,it,en",
        "PL" => "pl-PL,pl,en",
        "FI" => "fi-FI,fi,en",
        "SE" => "sv-SE,sv,en",
        "NO" => "nb-NO,no,en",
        "TR" => "tr-TR,tr,en",
        "BR" => "pt-BR,pt,en",
        "JP" => "ja-JP,ja,en",
        "KR" => "ko-KR,ko,en",
        _ => "en-US,en",
    }
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("Не удалось создать папку профиля {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(dir, perms).map_err(|e| {
            format!(
                "Не удалось ограничить права доступа к {}: {e}",
                dir.display()
            )
        })?;
    }
    Ok(())
}

/// Creates the empty `First Run` sentinel in `profile_dir` so Chrome/Edge/Brave suppress
/// first-run welcome and sign-in popups on fresh sandbox profiles.
pub fn write_first_run_sentinel(profile_dir: &Path) -> Result<PathBuf, String> {
    ensure_private_dir(profile_dir)?;
    let sentinel = profile_dir.join("First Run");
    if !sentinel.exists() {
        let f = fs::File::create(&sentinel).map_err(|e| {
            format!(
                "Не удалось создать маркер первого запуска {}: {e}",
                sentinel.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
    }
    Ok(sentinel)
}

fn merge_object_fields(root: &mut Map<String, Value>, key: &str, updates: Vec<(&str, Value)>) {
    let mut obj = match root.remove(key) {
        Some(Value::Object(existing)) => existing,
        _ => Map::new(),
    };
    for (field, val) in updates {
        obj.insert(field.to_string(), val);
    }
    root.insert(key.to_string(), Value::Object(obj));
}

pub fn write_fail_closed_preferences(
    profile_dir: &Path,
    alias_port: u16,
) -> Result<PathBuf, String> {
    write_fail_closed_preferences_with_country(profile_dir, alias_port, None)
}

/// Atomically writes `<profile_dir>/Default/Preferences` with fail-closed proxy, DoH=off,
/// WebRTC UDP restriction, exit-matched `intl.accept_languages`, and first-run/sign-in suppression,
/// plus the `<profile_dir>/First Run` sentinel file.
pub fn write_fail_closed_preferences_with_country(
    profile_dir: &Path,
    alias_port: u16,
    exit_country: Option<&str>,
) -> Result<PathBuf, String> {
    if alias_port == 0 {
        return Err("Внутренняя ошибка: порт локального прокси-алиаса не задан.".to_string());
    }
    write_first_run_sentinel(profile_dir)?;
    let default_dir = profile_dir.join("Default");
    ensure_private_dir(&default_dir)?;

    let prefs_path = default_dir.join("Preferences");
    let mut root = match fs::read_to_string(&prefs_path) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        },
        Err(_) => Map::new(),
    };

    root.insert(
        "proxy".to_string(),
        json!({
            "mode": "fixed_servers",
            "server": format!("http://127.0.0.1:{alias_port}")
        }),
    );
    root.insert("dns_over_https".to_string(), json!({ "mode": "off" }));

    let accept_languages = accept_languages_for_country(exit_country);
    merge_object_fields(
        &mut root,
        "intl",
        vec![("accept_languages", json!(accept_languages))],
    );
    merge_object_fields(
        &mut root,
        "webrtc",
        vec![
            ("ip_handling_policy", json!("disable_non_proxied_udp")),
            ("multiple_routes_enabled", json!(false)),
        ],
    );
    merge_object_fields(&mut root, "signin", vec![("allowed", json!(false))]);
    merge_object_fields(&mut root, "sync", vec![("requested", json!(false))]);
    merge_object_fields(
        &mut root,
        "browser",
        vec![
            ("has_seen_welcome_page", json!(true)),
            ("edge_first_run_complete", json!(true)),
        ],
    );

    let serialized = serde_json::to_string_pretty(&Value::Object(root))
        .map_err(|e| format!("Не удалось подготовить настройки браузера: {e}"))?;

    let tmp_path = default_dir.join(format!("Preferences.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp_path).map_err(|e| {
            format!(
                "Не удалось создать временный файл настроек {}: {e}",
                tmp_path.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        f.write_all(serialized.as_bytes())
            .map_err(|e| format!("Не удалось записать настройки браузера: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("Не удалось сохранить настройки браузера на диск: {e}"))?;
    }
    fs::rename(&tmp_path, &prefs_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "Не удалось применить настройки браузера {}: {e}",
            prefs_path.display()
        )
    })?;
    Ok(prefs_path)
}

pub fn read_sandbox_meta(profile_dir: &Path) -> Option<SandboxMeta> {
    let raw = fs::read_to_string(profile_dir.join(SANDBOX_META_FILENAME)).ok()?;
    serde_json::from_str::<SandboxMeta>(&raw).ok()
}

pub fn write_sandbox_meta(profile_dir: &Path, meta: SandboxMeta) -> Result<(), String> {
    ensure_private_dir(profile_dir)?;
    let path = profile_dir.join(SANDBOX_META_FILENAME);
    let data = serde_json::to_string(&meta)
        .map_err(|e| format!("Не удалось сохранить метаданные песочницы: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("Не удалось записать метаданные песочницы: {e}"))?;
    Ok(())
}

/// Removes Chromium `SingletonLock`/`SingletonSocket`/`SingletonCookie` files after terminating
/// a stale sandbox process whose proxy port no longer matches.
pub fn cleanup_stale_singleton_files(profile_dir: &Path) {
    for name in ["SingletonLock", "SingletonSocket", "SingletonCookie"] {
        let p = profile_dir.join(name);
        let _ = fs::remove_file(&p);
    }
}
