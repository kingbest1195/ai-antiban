//! Production [`PolicyStore`] backed by `crate::win_reg` on Windows and `defaults` on macOS.

use super::{PolicyStore, PolicyValue};
#[cfg(target_os = "macos")]
use super::chromium::CHROMIUM_BROWSERS;
use crate::sysproxy::platform::{PResult, PlatformError};
use crate::sysproxy::{note_dry_run_blocked, os_effects_enabled};

/// Production [`PolicyStore`] backed by `crate::win_reg` on Windows and `defaults` on macOS.
pub struct RealPolicyStore;

#[cfg(target_os = "macos")]
pub(super) fn macos_app_bundles_for_domain(domain: &str) -> &'static [&'static str] {
    CHROMIUM_BROWSERS
        .iter()
        .find(|b| {
            b.id == domain || (domain == "com.microsoft.Edge" && b.id == "com.microsoft.edgemac")
        })
        .map_or(&[], |b| b.macos_bundles)
}

#[cfg(target_os = "macos")]
fn macos_domain_installed(domain: &str) -> bool {
    for app_name in macos_app_bundles_for_domain(domain) {
        if std::path::Path::new("/Applications")
            .join(app_name)
            .exists()
        {
            return true;
        }
        if let Some(home) = crate::sysproxy::user_home_dir()
            && home.join("Applications").join(app_name).exists()
        {
            return true;
        }
    }
    crate::sysproxy::user_home_dir().is_some_and(|h| {
        h.join("Library")
            .join("Preferences")
            .join(format!("{domain}.plist"))
            .exists()
    })
}

#[cfg(target_os = "macos")]
fn is_defaults_not_found(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("does not exist") || lower.contains("not found")
}

#[cfg(target_os = "macos")]
fn parse_defaults_read(type_out: &str, val_out: &str) -> PResult<PolicyValue> {
    let t = type_out.trim().to_ascii_lowercase();
    let v = val_out.trim();
    if t.contains("boolean") {
        let b = matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        Ok(PolicyValue::Bool(b))
    } else if t.contains("integer") {
        let n = v
            .parse::<u32>()
            .map_err(|_| PlatformError::Unsupported("policy_defaults_int"))?;
        Ok(PolicyValue::Dword(n))
    } else if t.contains("string") {
        Ok(PolicyValue::Sz(v.to_string()))
    } else {
        Err(PlatformError::Unsupported("policy_defaults_type"))
    }
}

impl PolicyStore for RealPolicyStore {
    fn is_domain_applicable(&self, domain: &str) -> bool {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:check");
            return false;
        }
        #[cfg(target_os = "windows")]
        {
            let _ = domain;
            true
        }
        #[cfg(target_os = "macos")]
        {
            macos_domain_installed(domain)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = domain;
            false
        }
    }

    fn read(&self, domain: &str, key: &str) -> PResult<Option<PolicyValue>> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:read");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{
                ERROR_SUCCESS, REG_DWORD, REG_SZ, RootKey, decode_dword, decode_utf16_le_string,
                is_not_found_status, read_raw,
            };
            let raw = read_raw(RootKey::HkeyCurrentUser, domain, key);
            if is_not_found_status(raw.status) {
                return Ok(None);
            }
            if raw.status != ERROR_SUCCESS {
                return Err(PlatformError::Failed("win_reg_read_policy"));
            }
            match raw.kind {
                REG_DWORD => decode_dword(&raw.data)
                    .map(|n| Some(PolicyValue::Dword(n)))
                    .map_err(|_| PlatformError::Unsupported("policy_reg_dword")),
                REG_SZ => decode_utf16_le_string(&raw.data)
                    .map(|s| Some(PolicyValue::Sz(s)))
                    .map_err(|_| PlatformError::Unsupported("policy_reg_sz")),
                _ => Err(PlatformError::Unsupported("policy_reg_type")),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let read_out = crate::sysproxy::silent_command("defaults")
                .args(["read", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_read"))?;
            if !read_out.status.success() {
                let err = String::from_utf8_lossy(&read_out.stderr);
                if is_defaults_not_found(&err) {
                    return Ok(None);
                }
                return Err(PlatformError::Failed("defaults_read"));
            }
            let type_out = crate::sysproxy::silent_command("defaults")
                .args(["read-type", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_read_type"))?;
            if !type_out.status.success() {
                let err = String::from_utf8_lossy(&type_out.stderr);
                if is_defaults_not_found(&err) {
                    return Ok(None);
                }
                return Err(PlatformError::Failed("defaults_read_type"));
            }
            let val_s = String::from_utf8_lossy(&read_out.stdout);
            let type_s = String::from_utf8_lossy(&type_out.stdout);
            parse_defaults_read(&type_s, &val_s).map(Some)
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }

    fn write(&self, domain: &str, key: &str, value: &PolicyValue) -> PResult<()> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:write");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{RootKey, set_dword, set_sz};
            match value {
                PolicyValue::Dword(n) => set_dword(RootKey::HkeyCurrentUser, domain, key, *n)
                    .map_err(|_| PlatformError::Failed("win_reg_set_dword")),
                PolicyValue::Sz(s) => set_sz(RootKey::HkeyCurrentUser, domain, key, s)
                    .map_err(|_| PlatformError::Failed("win_reg_set_sz")),
                PolicyValue::Bool(b) => {
                    set_dword(RootKey::HkeyCurrentUser, domain, key, u32::from(*b))
                        .map_err(|_| PlatformError::Failed("win_reg_set_bool"))
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let mut cmd = crate::sysproxy::silent_command("defaults");
            cmd.args(["write", domain, key]);
            match value {
                PolicyValue::Bool(b) => {
                    cmd.args(["-bool", if *b { "true" } else { "false" }]);
                }
                PolicyValue::Dword(n) => {
                    cmd.args(["-int", &n.to_string()]);
                }
                PolicyValue::Sz(s) => {
                    cmd.args(["-string", s]);
                }
            }
            let out = cmd
                .output()
                .map_err(|_| PlatformError::Failed("defaults_write"))?;
            if out.status.success() {
                Ok(())
            } else {
                Err(PlatformError::Failed("defaults_write"))
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key, value);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }

    fn delete(&self, domain: &str, key: &str) -> PResult<()> {
        if !os_effects_enabled() {
            note_dry_run_blocked("browser_policy:delete");
            return Err(PlatformError::DryRun);
        }
        #[cfg(target_os = "windows")]
        {
            use crate::win_reg::{RootKey, delete_value};
            delete_value(RootKey::HkeyCurrentUser, domain, key)
                .map_err(|_| PlatformError::Failed("win_reg_delete_policy"))
        }
        #[cfg(target_os = "macos")]
        {
            let out = crate::sysproxy::silent_command("defaults")
                .args(["delete", domain, key])
                .output()
                .map_err(|_| PlatformError::Failed("defaults_delete"))?;
            if out.status.success() {
                return Ok(());
            }
            let err = String::from_utf8_lossy(&out.stderr);
            if is_defaults_not_found(&err) {
                Ok(())
            } else {
                Err(PlatformError::Failed("defaults_delete"))
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = (domain, key);
            Err(PlatformError::Unsupported("browser_policy"))
        }
    }
}
