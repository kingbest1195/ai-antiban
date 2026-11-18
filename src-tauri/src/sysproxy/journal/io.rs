//! Reading, writing, and change-notification dispatch for OS and file-backed journal resources.

use super::entry::{Resource, Value};
use crate::sysproxy::browser_policies::PolicyStore;
use crate::sysproxy::fs::{Fs, WriteMode};
use crate::sysproxy::jsonc;
use crate::sysproxy::platform::{PResult, PacState, Platform, PlatformError};
use crate::sysproxy::shell_rc;
use std::path::Path;

pub(super) fn read_value(
    fs: &dyn Fs,
    platform: &dyn Platform,
    policies: &dyn PolicyStore,
    res: &Resource,
) -> PResult<Value> {
    Ok(match res {
        Resource::Pac { service } => Value::Pac(platform.get_pac(service)?),
        Resource::Chain { service } => Value::Chain(platform.get_chain(service)?),
        Resource::Bypass { service } => Value::Bypass(platform.get_proxy_bypass_domains(service)?),
        Resource::UserEnv { name } => Value::Env(platform.get_user_env(name)?),
        Resource::Inet { name } => Value::Reg(platform.get_inet(name)?),
        Resource::BrowserPolicy { domain, key } => Value::Policy(policies.read(domain, key)?),
        Resource::BrowserPacPref { file, .. } => Value::Json(
            crate::sysproxy::browser_policies::read_browser_proxy_pref(fs, Path::new(file))?,
        ),
        Resource::JsonKey { .. }
        | Resource::JsonObject { .. }
        | Resource::TextBlock { .. }
        | Resource::File { .. } => read_file_value(fs, res)?,
    })
}

/// Result of a best-effort change notification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Notified {
    Yes,
    /// The notification failed; the written value stays, the notification is repeated later.
    Failed,
}

/// Tells the OS about a change (WinINet refresh / environment broadcast). `Unsupported` means
/// "nothing to notify on this OS".
pub(super) fn notify(platform: &dyn Platform, res: &Resource) -> Notified {
    let r = match res {
        Resource::Inet { .. } => platform.notify_inet_refresh(),
        Resource::UserEnv { .. } => platform.broadcast_env_change(),
        Resource::Pac { .. }
        | Resource::Chain { .. }
        | Resource::Bypass { .. }
        | Resource::JsonKey { .. }
        | Resource::JsonObject { .. }
        | Resource::TextBlock { .. }
        | Resource::File { .. }
        | Resource::BrowserPolicy { .. }
        | Resource::BrowserPacPref { .. } => Ok(()),
    };
    match r {
        Ok(()) | Err(PlatformError::Unsupported(_)) => Notified::Yes,
        Err(_) => Notified::Failed,
    }
}

/// Writes `v` into the OS. An `Err` means the write failed; a failed notification is reported
/// separately because the value did land.
pub(super) fn write_value(
    fs: &dyn Fs,
    platform: &dyn Platform,
    policies: &dyn PolicyStore,
    res: &Resource,
    v: &Value,
) -> PResult<Notified> {
    if res.is_file_resource() {
        write_file_value(fs, res, v)?;
        return Ok(Notified::Yes);
    }
    match (res, v) {
        (Resource::Pac { service }, Value::Pac(p)) => {
            // An absent URL is restored by clearing it (networksetup has no "unset"); an unknown
            // flag means the PAC was not in use before us, so it is switched off.
            let pac = PacState {
                url: Some(p.url.clone().unwrap_or_default()),
                enabled: p.enabled.or(Some(false)),
            };
            platform.set_pac(service, &pac)?;
        }
        (Resource::Chain { service }, Value::Chain(c)) => platform.set_chain(service, c)?,
        (Resource::Bypass { service }, Value::Bypass(d)) => {
            platform.set_proxy_bypass_domains(service, d)?
        }
        (Resource::UserEnv { name }, Value::Env(Some(s))) => platform.set_user_env(name, s)?,
        (Resource::UserEnv { name }, Value::Env(None)) => platform.unset_user_env(name)?,
        (Resource::Inet { name }, Value::Reg(Some(r))) => platform.set_inet(name, r)?,
        (Resource::Inet { name }, Value::Reg(None)) => platform.delete_inet(name)?,
        (Resource::BrowserPolicy { domain, key }, Value::Policy(Some(val))) => {
            policies.write(domain, key, val)?
        }
        (Resource::BrowserPolicy { domain, key }, Value::Policy(None)) => {
            policies.delete(domain, key)?
        }
        (Resource::BrowserPacPref { file, .. }, Value::Json(val)) => {
            crate::sysproxy::browser_policies::write_browser_proxy_pref(
                fs,
                Path::new(file),
                val.as_deref(),
            )?;
        }
        _ => return Err(PlatformError::Unsupported("kind_mismatch")),
    }
    Ok(notify(platform, res))
}

// ---------------------------------------------------------------------------------------------
// File resources: the value is read from / written to the user's file through `Fs`
// ---------------------------------------------------------------------------------------------

/// The file as text. `Ok(None)`: no such file. A file that is not UTF-8 is never edited.
fn read_text(fs: &dyn Fs, file: &str) -> PResult<Option<String>> {
    match fs.read(Path::new(file)) {
        Ok(None) => Ok(None),
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| PlatformError::Failed("file_not_utf8")),
        Err(_) => Err(PlatformError::Failed("file_read")),
    }
}

fn key_path(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

fn json_err(_: jsonc::JsoncError) -> PlatformError {
    PlatformError::Failed("file_not_editable")
}

fn read_file_value(fs: &dyn Fs, res: &Resource) -> PResult<Value> {
    match res {
        Resource::File { file, .. } => Ok(Value::Present(fs.exists(Path::new(file)))),
        Resource::JsonKey { file, path } => {
            let Some(text) = read_text(fs, file)? else {
                return Ok(Value::Json(None));
            };
            if jsonc::is_blank(&text) {
                return Ok(Value::Json(None));
            }
            let found = jsonc::get(&text, &key_path(path)).map_err(json_err)?;
            Ok(Value::Json(found.map(|f| f.raw.to_string())))
        }
        Resource::JsonObject { file, path } => {
            let Some(text) = read_text(fs, file)? else {
                return Ok(Value::Present(false));
            };
            if jsonc::is_blank(&text) {
                return Ok(Value::Present(false));
            }
            match jsonc::get(&text, &key_path(path)).map_err(json_err)? {
                None => Ok(Value::Present(false)),
                Some(f) if f.is_object => Ok(Value::Present(true)),
                Some(_) => Err(PlatformError::Failed("file_not_editable")),
            }
        }
        Resource::TextBlock { file } => {
            let Some(text) = read_text(fs, file)? else {
                return Ok(Value::Block(None));
            };
            let range = shell_rc::find_block(&text)
                .map_err(|_| PlatformError::Failed("file_not_editable"))?;
            Ok(Value::Block(range.map(|r| text[r].replace("\r\n", "\n"))))
        }
        _ => Err(PlatformError::Unsupported("kind_mismatch")),
    }
}

fn write_text(fs: &dyn Fs, file: &str, old: &str, new: String) -> PResult<()> {
    if new == old {
        return Ok(());
    }
    fs.write_atomic(Path::new(file), new.as_bytes(), WriteMode::KeepExisting)
        .map_err(|_| PlatformError::Failed("file_write"))
}

fn write_file_value(fs: &dyn Fs, res: &Resource, v: &Value) -> PResult<()> {
    match (res, v) {
        (Resource::File { file, skeleton }, Value::Present(true)) => {
            if fs.exists(Path::new(file)) {
                return Ok(());
            }
            if let Some(dir) = Path::new(file)
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                && !fs.exists(dir)
            {
                fs.create_private_dir_all(dir)
                    .map_err(|_| PlatformError::Failed("file_write"))?;
            }
            fs.write_atomic(
                Path::new(file),
                skeleton.as_bytes(),
                WriteMode::KeepExisting,
            )
            .map_err(|_| PlatformError::Failed("file_write"))
        }
        (Resource::File { file, skeleton }, Value::Present(false)) => {
            let Some(text) = read_text(fs, file)? else {
                return Ok(());
            };
            // Only the bare file Zastava created is removed; anything else in it is the user's.
            let bare = |t: &str| t.trim_start_matches('\u{feff}').trim().to_string();
            if bare(&text) == bare(skeleton) {
                fs.remove_file(Path::new(file))
                    .map_err(|_| PlatformError::Failed("file_write"))?;
            }
            Ok(())
        }
        (Resource::JsonKey { file, path }, Value::Json(want)) => {
            let Some(text) = read_text(fs, file)? else {
                return match want {
                    None => Ok(()),
                    Some(_) => Err(PlatformError::NotFound("file")),
                };
            };
            let p = key_path(path);
            let new = match want {
                Some(raw) => jsonc::set(&text, &p, raw),
                None if jsonc::is_blank(&text) => return Ok(()),
                None => jsonc::remove(&text, &p),
            }
            .map_err(json_err)?;
            write_text(fs, file, &text, new)
        }
        (Resource::JsonObject { file, path }, Value::Present(want)) => {
            let Some(text) = read_text(fs, file)? else {
                return match want {
                    false => Ok(()),
                    true => Err(PlatformError::NotFound("file")),
                };
            };
            let p = key_path(path);
            let existing = if jsonc::is_blank(&text) {
                None
            } else {
                jsonc::get(&text, &p).map_err(json_err)?
            };
            let new = match (want, existing) {
                (true, None) => jsonc::set(&text, &p, "{}").map_err(json_err)?,
                (true, Some(f)) if f.is_object => return Ok(()),
                // Removed only while it is empty: whatever the user put inside is not ours.
                (false, Some(f)) if f.is_object && f.is_empty_object => {
                    jsonc::remove(&text, &p).map_err(json_err)?
                }
                (false, _) => return Ok(()),
                (true, Some(_)) => return Err(PlatformError::Failed("file_not_editable")),
            };
            write_text(fs, file, &text, new)
        }
        (Resource::TextBlock { file }, Value::Block(want)) => {
            let Some(text) = read_text(fs, file)? else {
                return match want {
                    None => Ok(()),
                    Some(_) => Err(PlatformError::NotFound("file")),
                };
            };
            let new = match want {
                Some(block) => shell_rc::upsert_block(&text, block),
                None => shell_rc::remove_block(&text),
            }
            .map_err(|_| PlatformError::Failed("file_not_editable"))?;
            write_text(fs, file, &text, new)
        }
        _ => Err(PlatformError::Unsupported("kind_mismatch")),
    }
}
