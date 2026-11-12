//! CLI / IDE protection orchestration: enable (Claude Code, Gemini CLI, shell RC files, PowerShell
//! profiles, IDE settings, macOS launchd), disable, and status detection.
//!
//! Every file is reached through the context ([`FileCtx`]: file system, home, editor roots) and
//! every change goes through the ownership journal: the key (or the marked block) is recorded
//! with what was there before, edited in place, and put back only if it still holds what Zastava
//! wrote. Files that are damaged, ambiguous or not UTF-8 are left alone.

use super::ai_cli::{AGENT_ENV_KEY, apply_agent_settings};
use super::fs::{Fs, WriteMode};
use super::ide::{IDE_ENV_KEYS, TZ_VARS, apply_ide_settings, ide_candidates, json_str};
use super::journal::{Journal, RecoveryReport, Resource, Value};
use super::jsonc;
use super::platform::Platform;
use super::shell_rc::{
    build_powershell_guard_block_with_tz, build_shell_rc_guard_block_with_tz, find_block,
    is_generated_block, normalize_proxy_url_and_port, remove_block, sanitize_timezone,
};
use super::{
    CliProtectionReport, FileCtx, KNOWN_NO_PROXY_VALUES, NO_PROXY_VALUE, Run, ZASTAVA_RC_START,
    is_zastava_local_proxy_val, state, with_files, with_journal,
};
use std::path::Path;

/// Marker of the finished one-time cleanup of settings files that builds without a journal
/// (1.3.x, 2.0) left behind.
const LEGACY_FILES_MARK: &str = "legacy-2.0-files-cleanup";

const SHELL_RC_FILES: [&str; 3] = [".zshenv", ".zshrc", ".bash_profile"];

fn read_utf8(fs: &dyn Fs, file: &Path) -> Result<Option<String>, &'static str> {
    match fs.read(file) {
        Ok(None) => Ok(None),
        Ok(Some(b)) => String::from_utf8(b)
            .map(Some)
            .map_err(|_| "profile is not UTF-8"),
        Err(_) => Err("profile cannot be read"),
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

/// Removes a Zastava block that no journal record covers, but only when every line of it is one
/// a Zastava build writes. Returns `false` when the file could not be examined.
fn strip_legacy_block(j: &Journal, fs: &dyn Fs, file: &Path) -> bool {
    let res = Resource::TextBlock {
        file: file.to_string_lossy().into_owned(),
    };
    if j.entry(&res).is_some() {
        return true;
    }
    let Ok(Some(text)) = read_utf8(fs, file) else {
        return true; // missing is fine; unreadable files are not guessed at
    };
    let Ok(Some(r)) = find_block(&text) else {
        return true;
    };
    if !is_generated_block(&text[r]) {
        return true;
    }
    match remove_block(&text) {
        Ok(cleaned) => fs
            .write_atomic(file, cleaned.as_bytes(), WriteMode::KeepExisting)
            .is_ok(),
        Err(_) => true,
    }
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
    let run = || -> Result<String, jsonc::JsoncError> {
        let mut cur = text.clone();
        if root {
            let sig = |t: &str, k: &str| -> Result<bool, jsonc::JsoncError> {
                Ok(jsonc::get(t, &[k])?.is_some_and(|f| is_zastava_local_proxy_val(f.raw)))
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
            let signed = ["HTTPS_PROXY", "HTTP_PROXY"]
                .iter()
                .try_fold(false, |acc, k| {
                    Ok::<_, jsonc::JsoncError>(
                        acc || (!known(&[c, k])
                            && jsonc::get(&cur, &[c, k])?
                                .is_some_and(|f| is_zastava_local_proxy_val(f.raw))),
                    )
                })?;
            if !signed {
                continue;
            }
            for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
                .iter()
                .chain(TZ_VARS.iter())
            {
                if known(&[c, var]) {
                    continue;
                }
                let Some(f) = jsonc::get(&cur, &[c, var])? else {
                    continue;
                };
                let ours = match *var {
                    "NO_PROXY" => KNOWN_NO_PROXY_VALUES.iter().any(|v| f.raw == json_str(v)),
                    "TZ" => serde_json::from_str::<String>(f.raw)
                        .ok()
                        .is_some_and(|v| sanitize_timezone(&v).as_deref() == Some(v.as_str())),
                    "LANG" | "LC_TIME" | "LC_ALL" => f.raw == json_str("en_US.UTF-8"),
                    _ => is_zastava_local_proxy_val(f.raw),
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

fn profile_files(ctx: &FileCtx) -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = SHELL_RC_FILES.iter().map(|n| ctx.home.join(n)).collect();
    files.extend(ctx.powershell_profiles());
    files
}

/// One-time cleanup of what builds without a journal left in settings files and profiles (see
/// [`LEGACY_FILES_MARK`]); the profile part only touches blocks made of lines Zastava writes and
/// repeats cheaply, the settings part runs until it has examined every file once.
fn migrate_legacy_files(j: &mut Journal, p: &dyn Platform, ctx: &FileCtx) {
    let fs = &*ctx.fs;
    for file in profile_files(ctx) {
        strip_legacy_block(j, fs, &file);
    }
    if j.has_mark(LEGACY_FILES_MARK) {
        return;
    }
    let mut complete = clean_legacy_json(j, fs, &ctx.claude_settings(), false, &[AGENT_ENV_KEY]);
    complete &= clean_legacy_json(j, fs, &ctx.gemini_settings(), false, &[AGENT_ENV_KEY]);
    for (_, file) in ide_candidates(ctx) {
        complete &= clean_legacy_json(j, fs, &file, true, &IDE_ENV_KEYS);
    }
    if complete {
        let _ = j.set_mark(p, LEGACY_FILES_MARK);
    }
}

/// Writes the CLI / IDE side of the protection and returns the display names of what was set up.
/// Every target is independent: a file that cannot be edited safely is skipped (and named in the
/// log, without values), the others go on.
pub(super) fn enable_files(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    proxy_url: &str,
    port: u16,
    tz: Option<&str>,
) -> Vec<String> {
    let mut targets = Vec::new();
    migrate_legacy_files(j, p, ctx);
    let note = |label: &str, r: Result<(), String>, targets: &mut Vec<String>| match r {
        Ok(()) => targets.push(label.to_string()),
        Err(e) => eprintln!("Застава: {label} пропущен: {e}"),
    };

    // 1. Claude Code settings (~/.claude/settings.json)
    let r = apply_agent_settings(j, p, ctx, &ctx.claude_settings(), proxy_url, tz);
    note("Claude Code", r, &mut targets);

    // 2. Gemini CLI / Antigravity settings (~/.gemini/settings.json if the directory exists)
    if ctx.fs.exists(&ctx.home.join(".gemini")) {
        let r = apply_agent_settings(j, p, ctx, &ctx.gemini_settings(), proxy_url, tz);
        note("Gemini CLI", r, &mut targets);
    }

    // 3. Shell RC files on Unix (~/.zshenv, ~/.zshrc, ~/.bash_profile)
    if cfg!(unix) {
        let block = build_shell_rc_guard_block_with_tz(proxy_url, port, tz);
        let mut configured = false;
        for rc_name in SHELL_RC_FILES {
            let rc_path = ctx.home.join(rc_name);
            if rc_name != ".bash_profile" || ctx.fs.exists(&rc_path) {
                match apply_profile_block(j, p, &*ctx.fs, &rc_path, &block) {
                    Ok(()) => configured = true,
                    Err(e) => eprintln!("Застава: {rc_name} пропущен: {e}"),
                }
            }
        }
        if configured {
            targets.push("Терминал (~/.zshenv, ~/.zshrc)".to_string());
        }
    }

    // 3b. PowerShell profiles on Windows. NEVER write proxy vars or TZ / LANG / LC_TIME into the
    // global HKCU\Environment: the Windows CRT (_tzset) and Qt/Electron cannot parse IANA
    // timezones and fall back to UTC+0. Stale values from old builds are removed only by the
    // signature-based cleanup on disable / exit.
    if cfg!(target_os = "windows") {
        let block = build_powershell_guard_block_with_tz(proxy_url, tz);
        let mut configured = false;
        for ps_path in ctx.powershell_profiles() {
            match apply_profile_block(j, p, &*ctx.fs, &ps_path, &block) {
                Ok(()) => configured = true,
                Err(e) => eprintln!("Застава: профиль PowerShell пропущен: {e}"),
            }
        }
        if configured {
            targets.push("PowerShell ($PROFILE)".to_string());
        }
    }

    // 4. Installed IDEs (VS Code, Cursor, Windsurf, VSCodium, Antigravity)
    for (label, settings_path) in ide_candidates(ctx) {
        let r = apply_ide_settings(j, p, ctx, &settings_path, proxy_url, tz);
        note(label, r, &mut targets);
    }
    targets
}

/// Puts back what Zastava changed in the user's files: each key / block only if it still holds
/// what Zastava wrote, files it created only while they are still bare.
pub(super) fn disable_files(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: Option<&FileCtx>,
) -> RecoveryReport {
    if let Some(ctx) = ctx {
        migrate_legacy_files(j, p, ctx);
    }
    j.restore_where(p, Resource::is_file_resource)
}

/// Automatically configures CLI & IDE protection across:
/// 1. `~/.claude/settings.json` and `~/.gemini/settings.json` (`env.HTTPS_PROXY`, `env.HTTP_PROXY`, optional `TZ`)
/// 2. VS Code / Cursor / Windsurf `settings.json` (`http.proxy` + `terminal.integrated.env.*`)
/// 3. Shell profiles (`~/.zshrc`, `~/.bash_profile`) with an automatic `nc -z` liveness check
///
/// macOS `launchctl setenv` is no longer used: the GUI session stays clean.
pub fn enable_cli_and_ide_protection(proxy_addr_or_url: &str) -> CliProtectionReport {
    enable_cli_and_ide_protection_with_tz(proxy_addr_or_url, None)
}

/// Configures CLI & IDE protection with optional 1-click timezone (`TZ`) and UTF-8 locale sync.
pub fn enable_cli_and_ide_protection_with_tz(
    proxy_addr_or_url: &str,
    tz: Option<&str>,
) -> CliProtectionReport {
    let (proxy_url, port) = normalize_proxy_url_and_port(proxy_addr_or_url);
    let mut configured_targets = Vec::new();

    // Since 2.1 nothing is put into the launchd (GUI session) environment: not the proxy variables
    // and not TZ / LANG / LC_TIME. CUPS / IPP, Finder and the system services must not inherit
    // them. Leftovers of 2.0.0 are removed by the one-time migration (see `cleanup`). On Windows
    // nothing is written into `HKCU\Environment` either.

    if let Run::Done(targets) = with_files("cli_files:enable", |j, p, ctx| {
        enable_files(j, p, ctx, &proxy_url, port, tz)
    }) {
        configured_targets.extend(targets);
    }

    state().set_cli_protection_active(true);

    let mut shell_command = format!(
        "export HTTP_PROXY=\"{proxy_url}\" HTTPS_PROXY=\"{proxy_url}\" ALL_PROXY=\"{proxy_url}\" NO_PROXY=\"{NO_PROXY_VALUE}\""
    );
    if let Some(trimmed) = tz.and_then(sanitize_timezone) {
        shell_command.push_str(&format!(
            " TZ=\"{trimmed}\" LANG=\"en_US.UTF-8\" LC_ALL=\"en_US.UTF-8\""
        ));
    }

    CliProtectionReport {
        enabled: true,
        proxy_url,
        configured_targets,
        shell_command,
    }
}

/// Puts back the IDE `settings.json`, `~/.claude/settings.json` and `~/.gemini/settings.json`
/// keys Zastava wrote. A user environment recorded in the journal by an earlier build is
/// restored from the journal (see [`disable_cli_protection`]), not guessed here.
pub fn disable_cli_and_ide_runtime_settings() {
    let _ = with_files("cli_settings:restore", |j, p, ctx| {
        migrate_legacy_files(j, p, ctx);
        j.restore_where(p, |r| {
            matches!(r, Resource::JsonKey { .. } | Resource::JsonObject { .. })
                || matches!(r, Resource::File { skeleton, .. } if !skeleton.is_empty())
        })
    });
}

/// Switches CLI protection off: the user environment Zastava set is restored from the ownership
/// journal (foreign values stay), then the IDE / CLI / shell files are put back.
pub fn disable_cli_protection() {
    let _ = super::cleanup::restore_user_env();
    disable_cli_files();
}

/// The file side of [`disable_cli_protection`]: IDE / CLI settings, shell profiles, PowerShell
/// profiles. Nothing is changed when the journal cannot be opened.
pub(super) fn disable_cli_files() {
    state().set_cli_protection_active(false);
    let _ = with_journal("cli_files:restore", |j, p| {
        match FileCtx::real_with_fs(j.fs()) {
            Some(ctx) => disable_files(j, p, Some(&ctx)),
            None => disable_files(j, p, None),
        }
    });
}

/// Whether the files carry Zastava's protection: a marked block in a profile, or the Zastava
/// proxy in the Claude / Gemini settings.
pub(super) fn files_show_protection(ctx: &FileCtx) -> bool {
    let read = |f: &Path| -> Option<String> {
        ctx.fs
            .read(f)
            .ok()
            .flatten()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    for rc_path in profile_files(ctx) {
        if let Some(content) = read(&rc_path)
            && (content.contains(ZASTAVA_RC_START)
                || content.contains("# >>> ZASTAVA AI GUARD >>>")
                || content.to_ascii_uppercase().contains("ZASTAVA AI")
                || content.contains("127.0.0.1:8899"))
        {
            return true;
        }
    }
    for settings in [ctx.claude_settings(), ctx.gemini_settings()] {
        if let Some(content) = read(&settings)
            && is_zastava_local_proxy_val(&content)
        {
            return true;
        }
    }
    false
}

/// Checks whether CLI protection is currently enabled in memory, in shell RC files (~/.zshenv, ~/.zshrc, ~/.bash_profile),
/// Claude/Gemini settings, or Windows registry/PowerShell environment.
pub fn is_cli_protection_enabled() -> bool {
    if state().cli_protection_active() {
        return true;
    }
    if FileCtx::real().is_some_and(|ctx| files_show_protection(&ctx)) {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        if super::real_user_env("HTTP_PROXY").is_some_and(|v| is_zastava_local_proxy_val(&v)) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod file_tests {
    //! The file side on `FakeFs`: no test reads or writes a real home directory.
    use super::*;
    use crate::sysproxy::fs::{FakeFs, FsOp};
    use crate::sysproxy::ide::{ide_candidates, ide_env_key};
    use crate::sysproxy::platform::FakePlatform;
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
        fn enable(&self, tz: Option<&str>) -> Vec<String> {
            let mut j = self.journal();
            enable_files(&mut j, &self.p, &self.ctx, URL, 8899, tz)
        }
        fn disable(&self) -> RecoveryReport {
            let mut j = self.journal();
            disable_files(&mut j, &self.p, Some(&self.ctx))
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
            let r = apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, URL, None);
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
            assert!(apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, URL, None).is_err());
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
        enable_files(&mut j, &e.p, &e.ctx, "http://127.0.0.1:8900", 8900, None);
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
        let r = apply_ide_settings(&mut j, &e.p, &e.ctx, &ide, URL, None);
        assert!(r.is_err());
        assert!(j.is_empty(), "no intent for a file that could not be read");
        assert_eq!(e.text(&ide), original);
        // The next file is independent.
        let claude = e.ctx.claude_settings();
        apply_agent_settings(&mut j, &e.p, &e.ctx, &claude, URL, None).unwrap();
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
            e.text(&e.ctx.home.join(".zshenv"))
                .contains(ZASTAVA_RC_START)
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
        let targets = enable_files(&mut j, &p, &ctx, URL, 8899, Some("Europe/Berlin"));
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

        let report = disable_files(&mut j, &p, Some(&ctx));
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
        // zsh/bash profiles are only written on Unix; Windows has the PowerShell profile instead.
        if cfg!(unix) {
            assert!(after.contains(NO_PROXY_VALUE), "refreshed to the new value");
            assert_eq!(after.matches(ZASTAVA_RC_START).count(), 1);
        }
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
}
