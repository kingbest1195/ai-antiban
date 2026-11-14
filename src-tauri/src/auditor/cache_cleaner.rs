use crate::auditor::geo_matrix::ProviderId;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanResult {
    pub provider: ProviderId,
    pub cleaned_targets: Vec<String>,
    pub files_removed: usize,
    pub bytes_freed: u64,
    pub success: bool,
    pub message: String,
}

pub fn get_ai_app_data_dir(provider: ProviderId) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").ok()?;
        let app_support = PathBuf::from(home)
            .join("Library")
            .join("Application Support");
        match provider {
            ProviderId::Anthropic => Some(app_support.join("Claude")),
            ProviderId::Openai => Some(app_support.join("ChatGPT")),
            ProviderId::Gemini => None, // Google does not provide a desktop app
        }
    }

    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA").ok()?;
        let base = PathBuf::from(appdata);
        match provider {
            ProviderId::Anthropic => Some(base.join("Claude")),
            ProviderId::Openai => Some(base.join("ChatGPT")),
            ProviderId::Gemini => None,
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

pub fn clean_ai_app_cache(provider: ProviderId) -> CleanResult {
    let app_dir = match get_ai_app_data_dir(provider) {
        Some(d) => d,
        None => {
            return CleanResult {
                provider,
                cleaned_targets: Vec::new(),
                files_removed: 0,
                bytes_freed: 0,
                success: true,
                message: format!(
                    "Папка настольного клиента {} не найдена на этой ОС.",
                    provider.display_name()
                ),
            };
        }
    };

    clean_ai_app_cache_in_dir(provider, &app_dir)
}

fn is_strictly_whitelisted(target: &str, path: &std::path::Path) -> bool {
    let t_lower = target.to_ascii_lowercase();
    if t_lower.contains("claude_desktop_config") || t_lower.contains(".claude") {
        return true;
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_ascii_lowercase();
        if name_lower == "claude_desktop_config.json"
            || name_lower.starts_with(".claude")
            || name_lower.ends_with(".claude.json")
        {
            return true;
        }
    }
    false
}

pub fn clean_ai_app_cache_in_dir(provider: ProviderId, app_dir: &std::path::Path) -> CleanResult {
    if !app_dir.exists() {
        return CleanResult {
            provider,
            cleaned_targets: Vec::new(),
            files_removed: 0,
            bytes_freed: 0,
            success: true,
            message: format!(
                "Кэш десктопного клиента {} уже чист (директория отсутствует).",
                provider.display_name()
            ),
        };
    }

    // Comprehensive list of telemetry, session tokens, network cache and fingerprint targets
    // across Chromium / Electron implementations of Claude & ChatGPT Desktop.
    let target_names = [
        // Root browser / session caches
        "Cookies",
        "Cookies-journal",
        "IndexedDB",
        "Local Storage",
        "Session Storage",
        "Cache",
        "Code Cache",
        "GPUCache",
        "DawnGraphiteCache",
        "DawnWebGPUCache",
        "Network Action Predictor",
        "TransportSecurity",
        // Nested Chromium Network Service state
        "Network/Cookies",
        "Network/Cookies-journal",
        "Network/Network Persistent State",
        "Network/TransportSecurity",
        "Network/Trust Tokens",
        "Network/Trust Tokens-journal",
        "Network/Reporting and Nel",
        "Network/Reporting and Nel-journal",
        "Network/SCT Auditing Pending Reports",
        // Device telemetry and anti-fraud markers
        "ant-device-registry.json",
        "ccd-ids.json",
        "dispatch-footprint-census.json",
        "Local State",
        "Preferences",
        "DIPS",
        "DIPS-wal",
        "DIPS-shm",
        "SharedStorage",
        "SharedStorage-wal",
        "Crashpad",
        "sentry",
        "blob_storage",
        "WebStorage",
    ];

    let mut cleaned_targets = Vec::new();
    let mut files_removed = 0;
    let mut bytes_freed = 0;

    for target in &target_names {
        let path = app_dir.join(target);
        if is_strictly_whitelisted(target, &path) {
            continue;
        }
        if path.exists() {
            if path.is_dir() {
                if let Ok((count, bytes)) = remove_dir_contents(&path) {
                    files_removed += count;
                    bytes_freed += bytes;
                    let _ = std::fs::remove_dir_all(&path);
                    cleaned_targets.push(target.to_string());
                }
            } else if path.is_file() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    bytes_freed += metadata.len();
                }
                if std::fs::remove_file(&path).is_ok() {
                    files_removed += 1;
                    cleaned_targets.push(target.to_string());
                }
            }
        }
    }

    // Clean up empty Network directory if all contents were removed
    let network_dir = app_dir.join("Network");
    if network_dir.is_dir()
        && let Ok(mut entries) = std::fs::read_dir(&network_dir)
        && entries.next().is_none()
    {
        let _ = std::fs::remove_dir(&network_dir);
    }

    CleanResult {
        provider,
        cleaned_targets,
        files_removed,
        bytes_freed,
        success: true,
        message: format!(
            "Следы старой сессии и кэш {} успешно очищены (удалено файлов: {}).",
            provider.display_name(),
            files_removed
        ),
    }
}

fn remove_dir_contents(path: &std::path::Path) -> std::io::Result<(usize, u64)> {
    let mut count = 0;
    let mut bytes = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if is_strictly_whitelisted("", &entry_path) {
                continue;
            }
            if entry_path.is_dir() {
                let (c, b) = remove_dir_contents(&entry_path)?;
                count += c;
                bytes += b;
                let _ = std::fs::remove_dir_all(&entry_path);
            } else {
                if let Ok(meta) = std::fs::metadata(&entry_path) {
                    bytes += meta.len();
                }
                let _ = std::fs::remove_file(&entry_path);
                count += 1;
            }
        }
    }
    Ok((count, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_cache_cleaner_execution() {
        let result = clean_ai_app_cache(ProviderId::Anthropic);
        assert!(result.success);
    }

    #[test]
    fn test_deep_cache_cleaning_and_whitelist_protection() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let app_dir = temp_dir.path();

        // Create sample target files
        let cookies = app_dir.join("Cookies");
        std::fs::write(&cookies, "cookie_data").unwrap();

        let net_dir = app_dir.join("Network");
        std::fs::create_dir_all(&net_dir).unwrap();
        let net_cookies = net_dir.join("Cookies");
        std::fs::write(&net_cookies, "net_cookie_data").unwrap();

        let ant_device = app_dir.join("ant-device-registry.json");
        std::fs::write(&ant_device, "{}").unwrap();

        let local_state = app_dir.join("Local State");
        std::fs::write(&local_state, "{}").unwrap();

        // Whitelisted file: MUST NEVER BE REMOVED!
        let mcp_config = app_dir.join("claude_desktop_config.json");
        std::fs::write(&mcp_config, r#"{"mcpServers":{}}"#).unwrap();

        let result = clean_ai_app_cache_in_dir(ProviderId::Anthropic, app_dir);
        assert!(result.success);
        assert_eq!(result.files_removed, 4);
        assert!(!cookies.exists());
        assert!(!net_cookies.exists());
        assert!(!ant_device.exists());
        assert!(!local_state.exists());

        // Assert whitelisted config is fully preserved!
        assert!(mcp_config.exists());
        let preserved_content = std::fs::read_to_string(&mcp_config).unwrap();
        assert_eq!(preserved_content, r#"{"mcpServers":{}}"#);
    }
}
