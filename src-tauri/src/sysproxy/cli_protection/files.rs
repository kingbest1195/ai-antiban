use super::super::ai_cli::apply_agent_settings;
use super::super::fs::{Fs, WriteMode};
use super::super::ide::{apply_ide_settings, ide_candidates};
use super::super::journal::{Journal, RecoveryReport, ReportItem, Resource, Value};
use super::super::platform::Platform;
use super::super::shell_rc::{
    build_powershell_block, build_shell_block, find_block, is_generated_block, remove_block,
};
use super::super::{FileCtx, Run, state, with_journal};
use super::legacy::{
    home_label, migrate_legacy_files, read_utf8, strip_marked_block, strip_report_item,
    text_block_res, write_profiles,
};
use crate::state::CliMode;
use std::path::Path;

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

/// Puts the Zastava block into a shell / PowerShell profile through the journal. Refused (nothing
/// written) when the markers are partial or repeated, when the file is not UTF-8, or when an
/// existing block is not one Zastava wrote and the journal has no record of it (the user's own
/// edit). A block left by a build without a journal is migrated: it is removed and replaced
/// (this is also where the dangerous old PowerShell `else` branch goes).
pub(super) fn apply_profile_block(
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
pub(super) fn restore_profile(j: &mut Journal, p: &dyn Platform, file: &Path) -> Vec<ReportItem> {
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

/// The file side of a complete cleanup (exit, `--cleanup`, the "clean everything" button): IDE /
/// CLI settings, shell profiles, PowerShell profiles; both parts, proxy and time zone. Nothing is
/// changed when the journal cannot be opened.
pub(crate) fn disable_cli_files() -> RecoveryReport {
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
