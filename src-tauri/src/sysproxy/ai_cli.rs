//! Claude Code (`~/.claude/settings.json`) and Gemini CLI (`~/.gemini/settings.json`) settings.
//!
//! Both files keep the child-process environment in an `env` object. Zastava owns the individual
//! variables it writes there (through the ownership journal, see `ide::apply_settings_keys`); the
//! rest of the file is never rewritten.

use super::ide::{KeySpec, TZ_VARS, apply_settings_keys};
use super::journal::Journal;
use super::platform::Platform;
use super::{FileCtx, NO_PROXY_VALUE};
use std::path::Path;

/// The object that holds the variables.
const ENV_KEY: &str = "env";

fn agent_keys(proxy_url: &str, tz: Option<&str>) -> (Vec<KeySpec>, Vec<Vec<String>>) {
    let mut keys = vec![
        KeySpec::new(&[ENV_KEY, "HTTP_PROXY"], proxy_url),
        KeySpec::new(&[ENV_KEY, "HTTPS_PROXY"], proxy_url),
        KeySpec::new(&[ENV_KEY, "ALL_PROXY"], proxy_url),
        KeySpec::new(&[ENV_KEY, "NO_PROXY"], NO_PROXY_VALUE),
    ];
    let mut retire = Vec::new();
    match tz.and_then(super::shell_rc::sanitize_timezone) {
        Some(timezone) => {
            keys.push(KeySpec::new(&[ENV_KEY, "TZ"], &timezone));
            for v in &TZ_VARS[1..] {
                keys.push(KeySpec::new(&[ENV_KEY, v], "en_US.UTF-8"));
            }
        }
        None => retire.extend(
            TZ_VARS
                .iter()
                .map(|v| vec![ENV_KEY.to_string(), v.to_string()]),
        ),
    }
    (keys, retire)
}

/// Routes Claude Code / Gemini CLI through Zastava: proxy variables and, optionally, the
/// timezone / locale variables, in the `env` block of `settings_path`.
pub(super) fn apply_agent_settings(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    settings_path: &Path,
    proxy_url: &str,
    tz: Option<&str>,
) -> Result<(), String> {
    let (keys, retire) = agent_keys(proxy_url, tz);
    apply_settings_keys(j, p, &*ctx.fs, settings_path, &keys, &retire)
}

/// The variable names Zastava writes into `env` (for legacy cleanup and status checks).
pub(super) const AGENT_ENV_KEY: &str = ENV_KEY;
