use super::super::ai_cli::AGENT_ENV_KEY;
#[cfg(target_os = "windows")]
use super::super::cleanup::is_zastava_env_signature;
use super::super::cleanup::is_zastava_proxy_json;
use super::super::ide::{ide_candidates, ide_env_key, json_str};
use super::super::jsonc;
use super::super::shell_rc::{SAFE_LOCALE, find_block};
use super::super::{FileCtx, state};
use super::legacy::profile_files;
use std::path::Path;

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
pub(crate) fn files_show_protection(ctx: &FileCtx) -> bool {
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
pub(crate) fn files_show_tz_sync(ctx: &FileCtx) -> bool {
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
        if super::super::real_user_env("HTTP_PROXY")
            .is_some_and(|v| is_zastava_env_signature(&v, gw))
        {
            return true;
        }
    }
    false
}
