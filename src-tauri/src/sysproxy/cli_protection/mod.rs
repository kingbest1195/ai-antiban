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

mod detect;
mod files;
mod legacy;

pub use detect::{is_cli_protection_enabled, sync_ai_tz_active};
pub(super) use files::disable_cli_files;
pub(super) use legacy::clean_zshenv;

use super::journal::{RecoveryReport, Resource};
use super::shell_rc::{SAFE_LOCALE, normalize_proxy_url_and_port, sanitize_timezone};
use super::{CliProtectionReport, NO_PROXY_VALUE, Run, SysState, journal_failure_text, state, with_files};
use crate::state::CliMode;
use files::{FilePlan, FilesApplied, HostOs, apply_files};
use legacy::migrate_legacy_files;

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


#[cfg(test)]
#[path = "../cli_protection_tests/mod.rs"]
mod file_tests;

#[cfg(test)]
#[allow(unused_imports)]
use super::ai_cli::apply_agent_settings;
#[cfg(test)]
#[allow(unused_imports)]
use super::fs::Fs;
#[cfg(test)]
#[allow(unused_imports)]
use super::ide::{apply_ide_settings, json_str};
#[cfg(test)]
#[allow(unused_imports)]
use super::journal::{EntryState, Journal, Value};
#[cfg(test)]
#[allow(unused_imports)]
use super::platform::Platform;
#[cfg(test)]
#[allow(unused_imports)]
use super::shell_rc::{build_powershell_block, build_shell_block, is_generated_block};
#[cfg(test)]
#[allow(unused_imports)]
use super::{FileCtx, jsonc};
#[cfg(test)]
#[allow(unused_imports)]
use detect::{files_show_protection, files_show_tz_sync};
#[cfg(test)]
#[allow(unused_imports)]
use files::{apply_profile_block, disable_files};
#[cfg(test)]
#[allow(unused_imports)]
use legacy::{
    LEGACY_FILES_MARK, LEGACY_SHELL_MARK, Strip, clean_legacy_json, strip_marked_block,
};
#[cfg(test)]
#[allow(unused_imports)]
use std::path::Path;
