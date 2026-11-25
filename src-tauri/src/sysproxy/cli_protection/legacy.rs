use super::super::ai_cli::AGENT_ENV_KEY;
use super::super::cleanup::is_zastava_proxy_json;
use super::super::fs::{Fs, WriteMode};
use super::super::ide::{IDE_ENV_KEYS, PROXY_VARS, TZ_VARS_REMOVABLE, ide_candidates, json_str};
use super::super::journal::{Journal, Outcome, ReportItem, Resource};
use super::super::jsonc;
use super::super::platform::Platform;
use super::super::shell_rc::{
    SAFE_LOCALE, find_block, is_generated_block, remove_block, sanitize_timezone,
};
use super::super::{FileCtx, KNOWN_NO_PROXY_VALUES, state};
use super::files::{HostOs, restore_profile};
use crate::state::CliMode;
use std::path::{Path, PathBuf};

/// Marker of the finished one-time cleanup of settings files that builds without a journal
/// (1.3.x, 2.0) left behind.
pub(super) const LEGACY_FILES_MARK: &str = "legacy-2.0-files-cleanup";

/// Marker of the finished one-time cleanup of the marked blocks 2.0.0 left in shell profiles
/// (and in `~/.zshenv`). Separate from [`LEGACY_FILES_MARK`], which early 2.1 builds may already
/// have set.
pub(super) const LEGACY_SHELL_MARK: &str = "legacy-2.0-shell-blocks-cleanup";

/// The interactive profiles Zastava may WRITE its block into (only in `global_terminal`).
pub(super) const SHELL_WRITE_FILES: [&str; 2] = [".zshrc", ".bash_profile"];

/// The profile Zastava no longer writes into. Only ever CLEANED: an old marked block is cut out by
/// its exact markers (every `zsh` subshell of `brew` / `npm` runs `~/.zshenv`, and the block's
/// `nc -z` probe made hundreds of calls).
pub(super) const ZSHENV: &str = ".zshenv";

pub(super) fn read_utf8(fs: &dyn Fs, file: &Path) -> Result<Option<String>, &'static str> {
    match fs.read(file) {
        Ok(None) => Ok(None),
        Ok(Some(b)) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| "profile is not UTF-8"),
        Err(_) => Err("profile cannot be read"),
    }
}

pub(super) fn text_block_res(file: &Path) -> Resource {
    Resource::TextBlock {
        file: file.to_string_lossy().into_owned(),
    }
}

/// What cutting a block out of a profile by its exact markers came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strip {
    /// No block (or no file).
    Absent,
    /// The block was cut out; the bytes around it are unchanged.
    Removed,
    /// The journal records this block: it is given back through the journal, not here.
    Journaled,
    /// A marker without its partner (or repeated / not on its own line): not changed.
    Partial,
    /// Between the markers there is something Zastava does not write: not changed.
    Edited,
    /// The file could not be read (or is not UTF-8): not changed.
    Unreadable,
    /// The file could not be written.
    WriteFailed,
}

impl Strip {
    /// Fully dealt with: nothing is left that a later pass would have to do.
    fn is_clean(self) -> bool {
        matches!(self, Strip::Absent | Strip::Removed | Strip::Journaled)
    }

    /// Russian note for the user (names a profile, never a value). `None` when nothing to say.
    pub(crate) fn note(self, label: &str) -> Option<String> {
        match self {
            Strip::Partial => Some(format!(
                "обнаружен незавершённый блок Заставы в {label} — не изменён"
            )),
            Strip::Edited => Some(format!(
                "блок Заставы в {label} изменён пользователем — не тронут"
            )),
            Strip::Unreadable => Some(format!("{label} не удалось прочитать — не изменён")),
            Strip::WriteFailed => Some(format!("не удалось убрать блок Заставы из {label}")),
            Strip::Absent | Strip::Removed | Strip::Journaled => None,
        }
    }
}

/// Cuts the Zastava block out of `file` strictly by its exact markers (the bytes before and after
/// it stay as they are), but only when no journal record covers it and every line of the block is
/// one a Zastava build writes. Partial markers and blocks with foreign lines are reported, never
/// changed.
pub(super) fn strip_marked_block(j: &Journal, fs: &dyn Fs, file: &Path) -> Strip {
    if j.entry(&text_block_res(file)).is_some() {
        return Strip::Journaled;
    }
    let text = match read_utf8(fs, file) {
        Ok(Some(t)) => t,
        Ok(None) => return Strip::Absent,
        Err(_) => return Strip::Unreadable,
    };
    let range = match find_block(&text) {
        Ok(Some(r)) => r,
        Ok(None) => return Strip::Absent,
        Err(_) => return Strip::Partial,
    };
    if !is_generated_block(&text[range]) {
        return Strip::Edited;
    }
    match remove_block(&text) {
        Ok(cleaned) => {
            if fs
                .write_atomic(file, cleaned.as_bytes(), WriteMode::KeepExisting)
                .is_ok()
            {
                Strip::Removed
            } else {
                Strip::WriteFailed
            }
        }
        Err(_) => Strip::Partial,
    }
}

/// Home-relative display name of a profile, e.g. `~/.zshrc` (fixed names, no user data).
pub(super) fn home_label(ctx: &FileCtx, file: &Path) -> String {
    let rel = file.strip_prefix(&ctx.home).unwrap_or(file);
    let parts: Vec<_> = rel.iter().map(|c| c.to_string_lossy()).collect();
    format!("~/{}", parts.join("/"))
}

pub(super) fn strip_report_item(file: &Path, s: Strip) -> ReportItem {
    ReportItem {
        resource: format!(
            "legacy:profile:{}",
            file.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
        ),
        outcome: match s {
            Strip::Removed => Outcome::Restored,
            Strip::Absent | Strip::Journaled => Outcome::AlreadyRestored,
            // Left as it is, and said so: not a failure, the user decides.
            Strip::Partial | Strip::Edited | Strip::Unreadable => Outcome::ExternalChange,
            Strip::WriteFailed => Outcome::Failed("profile_write"),
        },
    }
}

/// `~/.zshenv`: gives back what the journal recorded for it (an early 2.1 build wrote there) and
/// cuts out an old block by its exact markers. Run at start, on every enable / disable and in
/// `--cleanup`: cheap, and byte-exact for everything around the block.
pub(crate) fn clean_zshenv(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
) -> (Strip, Vec<ReportItem>) {
    let file = ctx.home.join(ZSHENV);
    let mut items = restore_profile(j, p, &file);
    let s = strip_marked_block(j, &*ctx.fs, &file);
    items.push(strip_report_item(&file, s));
    (s, items)
}

/// Removes the keys a build without a journal left in one settings file: only values that carry
/// the Zastava signature (or are exactly what Zastava writes), and only keys the journal does not
/// know. Returns `false` when the file could not be examined or written.
pub(super) fn clean_legacy_json(
    j: &Journal,
    fs: &dyn Fs,
    file: &Path,
    root: bool,
    containers: &[&str],
    gateway_port: Option<u16>,
) -> bool {
    let name = file.to_string_lossy().into_owned();
    let text = match fs.read(file) {
        Ok(None) => return true,
        Ok(Some(b)) => match String::from_utf8(b) {
            Ok(t) => t,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    if jsonc::is_blank(&text) {
        return true;
    }
    let known = |path: &[&str]| {
        j.entry(&Resource::JsonKey {
            file: name.clone(),
            path: path.iter().map(|s| s.to_string()).collect(),
        })
        .is_some()
    };
    let signed_val = |raw: &str| is_zastava_proxy_json(raw, gateway_port);
    let run = || -> Result<String, jsonc::JsoncError> {
        let mut cur = text.clone();
        if root {
            let sig = |t: &str, k: &str| -> Result<bool, jsonc::JsoncError> {
                Ok(jsonc::get(t, &[k])?.is_some_and(|f| signed_val(f.raw)))
            };
            if !known(&["http.proxy"]) && sig(&cur, "http.proxy")? {
                cur = jsonc::remove(&cur, &["http.proxy"])?;
                let support = jsonc::get(&cur, &["http.proxySupport"])?
                    .is_some_and(|f| f.raw == "\"override\"");
                if support && !known(&["http.proxySupport"]) {
                    cur = jsonc::remove(&cur, &["http.proxySupport"])?;
                }
            }
        }
        for c in containers {
            // The co-signature: one of the proxy variables points at our gateway.
            let signed =
                ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"]
                    .iter()
                    .try_fold(false, |acc, k| {
                        Ok::<_, jsonc::JsoncError>(
                            acc || (!known(&[c, k])
                                && jsonc::get(&cur, &[c, k])?.is_some_and(|f| signed_val(f.raw))),
                        )
                    })?;
            if !signed {
                continue;
            }
            for var in PROXY_VARS.iter().chain(TZ_VARS_REMOVABLE.iter()) {
                if known(&[c, var]) {
                    continue;
                }
                let Some(f) = jsonc::get(&cur, &[c, var])? else {
                    continue;
                };
                let ours = match *var {
                    "NO_PROXY" => KNOWN_NO_PROXY_VALUES.iter().any(|v| f.raw == json_str(v)),
                    "NODE_USE_ENV_PROXY" => f.raw == json_str("1"),
                    // The zone only next to a signed proxy variable (checked above).
                    "TZ" => serde_json::from_str::<String>(f.raw)
                        .ok()
                        .is_some_and(|v| sanitize_timezone(&v).as_deref() == Some(v.as_str())),
                    // A locale only with the exact value Zastava wrote.
                    "LANG" | "LC_TIME" | "LC_ALL" => f.raw == json_str(SAFE_LOCALE),
                    _ => signed_val(f.raw),
                };
                if ours {
                    cur = jsonc::remove(&cur, &[c, var])?;
                }
            }
            if jsonc::get(&cur, &[c])?.is_some_and(|f| f.is_empty_object) {
                cur = jsonc::remove(&cur, &[c])?;
            }
        }
        Ok(cur)
    };
    match run() {
        Ok(new) if new == text => true,
        Ok(new) => fs
            .write_atomic(file, new.as_bytes(), WriteMode::KeepExisting)
            .is_ok(),
        Err(_) => false,
    }
}

/// Every profile a Zastava block may be in (for cleaning and status): the shell profiles
/// including `~/.zshenv`, and the PowerShell profiles.
pub(super) fn profile_files(ctx: &FileCtx) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::iter::once(ZSHENV)
        .chain(SHELL_WRITE_FILES)
        .map(|n| ctx.home.join(n))
        .collect();
    files.extend(ctx.powershell_profiles());
    files
}

/// The profiles Zastava writes its block into on `os`, in `global_terminal`.
pub(super) fn write_profiles(ctx: &FileCtx, os: HostOs) -> Vec<PathBuf> {
    match os {
        HostOs::Unix => SHELL_WRITE_FILES.iter().map(|n| ctx.home.join(n)).collect(),
        HostOs::Windows => ctx.powershell_profiles(),
    }
}

/// One-time cleanup of what builds without a journal left (see [`LEGACY_FILES_MARK`],
/// [`LEGACY_SHELL_MARK`]):
/// * `~/.zshenv`: the old block is cut out by its markers (also on every later call, see
///   [`clean_zshenv`]);
/// * in `ai_only` the 2.0.0 blocks of `~/.zshrc`, `~/.bash_profile` and the PowerShell profiles
///   are cut out too, only when made of lines Zastava writes (in `global_terminal` the block is
///   replaced when the new one is written);
/// * the keys in `settings.json` files that carry the Zastava signature.
///
/// Returns the notes for the user.
pub(super) fn migrate_legacy_files(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    mode: CliMode,
) -> Vec<String> {
    let fs = &*ctx.fs;
    let mut notes = Vec::new();
    let (z, _) = clean_zshenv(j, p, ctx);
    notes.extend(z.note("~/.zshenv"));
    if !j.has_mark(LEGACY_SHELL_MARK) {
        let mut clean = z.is_clean();
        if mode == CliMode::AiOnly {
            for file in profile_files(ctx)
                .into_iter()
                .filter(|f| !f.ends_with(ZSHENV))
            {
                let s = strip_marked_block(j, fs, &file);
                clean &= s.is_clean();
                notes.extend(s.note(&home_label(ctx, &file)));
            }
        }
        // A block the user edited or a half marker is reported again at the next start; the
        // mark means "everything was examined and nothing is left to do".
        if clean && mode == CliMode::AiOnly {
            let _ = j.set_mark(p, LEGACY_SHELL_MARK);
        }
    }
    if j.has_mark(LEGACY_FILES_MARK) {
        return notes;
    }
    let gw = state().gateway_port();
    let mut complete =
        clean_legacy_json(j, fs, &ctx.claude_settings(), false, &[AGENT_ENV_KEY], gw);
    complete &= clean_legacy_json(j, fs, &ctx.gemini_settings(), false, &[AGENT_ENV_KEY], gw);
    let codex_settings = ctx.home.join(".codex").join("settings.json");
    complete &= clean_legacy_json(j, fs, &codex_settings, false, &[AGENT_ENV_KEY], gw);
    for (_, file) in ide_candidates(ctx) {
        complete &= clean_legacy_json(j, fs, &file, true, &IDE_ENV_KEYS, gw);
    }
    if complete {
        let _ = j.set_mark(p, LEGACY_FILES_MARK);
    }
    notes
}
