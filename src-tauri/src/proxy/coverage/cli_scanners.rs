use super::ide_scanners::antigravity_kind;
use super::{CoverageEnv, CoverageStatus, proxy_value_targets_gateway};
use super::types::{Verdict, steps, steps_of};
use crate::state::CliMode;
use crate::sysproxy::FileCtx;
use crate::sysproxy::fs::Fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Settings file of the AI command-line clients that Zastava configures (`ai_only`).
fn agent_settings_path(ctx: &FileCtx, id: &str) -> Option<PathBuf> {
    match id {
        "claude-code" => Some(ctx.claude_settings()),
        "gemini-cli" => Some(ctx.gemini_settings()),
        _ => None,
    }
}

/// `env.HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` of a Claude Code / Gemini CLI `settings.json`
/// against the gateway port. A missing file is `Off`; an unreadable one is `Unknown`.
fn agent_verdict(ctx: &FileCtx, path: &Path, gateway_port: u16) -> Verdict {
    let text = match ctx.fs.read(path) {
        Ok(Some(bytes)) => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(None) => return Verdict::Off,
        Err(_) => return Verdict::Unknown,
    };
    let text = text.trim_start_matches('\u{feff}');
    if text.trim().is_empty() {
        return Verdict::Off;
    }
    let cleaned = crate::sysproxy::sanitize_jsonc(text);
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&cleaned) else {
        return Verdict::Unknown;
    };
    let env = v.get("env");
    let targets = ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"].iter().any(|k| {
        env.and_then(|e| e.get(*k))
            .and_then(|p| p.as_str())
            .is_some_and(|p| proxy_value_targets_gateway(p, gateway_port))
    });
    if targets {
        Verdict::Configured
    } else {
        Verdict::Off
    }
}

/// Status of a command-line application (`category == "cli"`) in the given CLI mode.
///
/// * `ai_only`: Claude Code and Gemini CLI are `Configured` only when their own `settings.json`
///   carries the Zastava proxy; the general tools (`node`, `python`, `curl`) are not covered at all
///   (`Off`, no "enable protection" step: it would not change anything).
/// * `global_terminal`: the shell profiles carry the proxy, so every CLI follows the protection
///   flag; a terminal opened before needs reopening.
pub(super) fn cli_fact(
    id: &str,
    env: &CoverageEnv<'_>,
    gateway: Option<SocketAddr>,
    mode: CliMode,
) -> (CoverageStatus, Vec<String>, String) {
    if mode == CliMode::GlobalTerminal {
        return if env.cli_protection_enabled {
            (
                CoverageStatus::Configured,
                steps_of(&[steps::REOPEN_TERMINAL]),
                "Защита терминала включена (действует в новых терминалах)".to_string(),
            )
        } else {
            (
                CoverageStatus::Off,
                steps_of(&[steps::ENABLE_PROTECTION, steps::SET_ENV_PROXY]),
                "Защита терминала не включена".to_string(),
            )
        };
    }
    let verdict = match (env.files, gateway) {
        (Some(ctx), Some(g)) => {
            agent_settings_path(ctx, id).map(|path| agent_verdict(ctx, &path, g.port()))
        }
        _ if agent_settings_path_known(id) => Some(Verdict::Unknown),
        _ => None,
    };
    match verdict {
        Some(Verdict::Configured) => (
            CoverageStatus::Configured,
            Vec::new(),
            "В settings.json прописан прокси Заставы (действует для новых сессий)".to_string(),
        ),
        Some(Verdict::Off) => (
            CoverageStatus::Off,
            steps_of(&[steps::ENABLE_PROTECTION, steps::SET_ENV_PROXY]),
            "В settings.json нет прокси Заставы".to_string(),
        ),
        Some(Verdict::Unknown) => (
            CoverageStatus::Unknown,
            steps_of(&[steps::SET_ENV_PROXY]),
            "Не удалось прочитать settings.json".to_string(),
        ),
        None if id == "opencode" => (
            CoverageStatus::Off,
            steps_of(&[steps::SET_ENV_PROXY]),
            "Терминальная утилита без глобального прокси: включите «Весь терминал» в Настройках или запустите с переменными прокси".to_string(),
        ),
        None => (
            CoverageStatus::Off,
            steps_of(&[steps::SET_ENV_PROXY]),
            "Не покрывается в режиме «Только ИИ-клиенты и IDE»".to_string(),
        ),
    }
}

fn agent_settings_path_known(id: &str) -> bool {
    matches!(id, "claude-code" | "gemini-cli")
}

/// Checks whether an application is installed on this machine (real home).
pub fn check_app_installed(id: &str) -> bool {
    FileCtx::real()
        .map(|ctx| check_app_installed_in(id, &ctx))
        .unwrap_or(matches!(id, "browsers" | "curl"))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

/// Whether the application is installed or its config / settings directory exists, looking
/// only through `ctx` (its file system, home and editor roots).
pub(crate) fn check_app_installed_in(id: &str, ctx: &FileCtx) -> bool {
    let fs: &dyn Fs = &*ctx.fs;
    let ex = |p: &Path| fs.exists(p);
    let in_roots = |folder: &str| ctx.ide_roots.iter().any(|r| ex(&r.join(folder)));
    let windows_local = |sub: &[&str]| {
        cfg!(target_os = "windows")
            && env_dir("LOCALAPPDATA").is_some_and(|l| {
                let mut p = l;
                for s in sub {
                    p = p.join(s);
                }
                ex(&p)
            })
    };
    let has_ide_folder = |folder: &str| {
        ctx.ide_roots
            .iter()
            .any(|r| ex(&r.join(folder).join("User")))
    };

    match id {
        "browsers" | "curl" => true,
        "claude-desktop" => {
            ex(Path::new("/Applications/Claude.app"))
                || ex(&ctx.home.join("Applications").join("Claude.app"))
                || in_roots("Claude")
                || windows_local(&["Programs", "Claude"])
        }
        "chatgpt-desktop" => {
            ex(Path::new("/Applications/ChatGPT.app"))
                || ex(&ctx.home.join("Applications").join("ChatGPT.app"))
                || in_roots("ChatGPT")
                || windows_local(&["Programs", "ChatGPT"])
        }
        "antigravity" => antigravity_kind(ctx).is_some(),
        "cursor" => has_ide_folder("Cursor") || ex(Path::new("/Applications/Cursor.app")),
        "vscode" => {
            has_ide_folder("Code")
                || has_ide_folder("VSCodium")
                || ex(Path::new("/Applications/Visual Studio Code.app"))
        }
        "windsurf" => has_ide_folder("Windsurf") || ex(Path::new("/Applications/Windsurf.app")),
        "jetbrains" => {
            in_roots("JetBrains")
                || windows_local(&["JetBrains"])
                || ex(Path::new("/Applications/IntelliJ IDEA.app"))
                || ex(Path::new("/Applications/PyCharm.app"))
                || ex(Path::new("/Applications/WebStorm.app"))
        }
        "claude-code" => ex(&ctx.home.join(".claude")),
        "gemini-cli" => ex(&ctx.home.join(".gemini")),
        "opencode" => {
            ex(&ctx.home.join(".config").join("opencode"))
                || ex(&ctx.home.join(".opencode").join("bin").join("opencode"))
                || ex(Path::new("/opt/homebrew/bin/opencode"))
                || ex(Path::new("/usr/local/bin/opencode"))
        }
        "node-cli" => {
            ex(&ctx.home.join(".nvm"))
                || ex(&ctx.home.join(".fnm"))
                || ex(Path::new("/usr/local/bin/node"))
                || ex(Path::new("/opt/homebrew/bin/node"))
                || env_dir("ProgramFiles").is_some_and(|p| ex(&p.join("nodejs")))
        }
        "python-cli" => {
            ex(Path::new("/usr/bin/python3"))
                || ex(Path::new("/usr/local/bin/python3"))
                || ex(Path::new("/opt/homebrew/bin/python3"))
                || windows_local(&["Programs", "Python"])
        }
        _ => false,
    }
}
