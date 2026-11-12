//! Claude Code (`~/.claude/settings.json`) and Gemini CLI (`~/.gemini/settings.json`) settings.
//!
//! Both files keep the child-process environment in an `env` object. Zastava owns the individual
//! variables it writes there (through the ownership journal, see `ide::apply_settings_keys`); the
//! rest of the file is never rewritten. The proxy variables and the time zone / locale variables
//! are independent: each group is written, or given back, on its own.

use super::FileCtx;
use super::ide::{KeySpec, PROXY_VARS, apply_settings_keys, proxy_env_keys, tz_key_specs};
use super::journal::{Journal, ReportItem};
use super::platform::Platform;
use std::path::Path;

/// The object that holds the variables.
const ENV_KEY: &str = "env";

fn agent_keys(proxy_url: Option<&str>, tz: Option<&str>) -> (Vec<KeySpec>, Vec<Vec<String>>) {
    let mut keys = Vec::new();
    let mut retire = Vec::new();
    match proxy_url {
        Some(url) => keys.extend(proxy_env_keys(ENV_KEY, url)),
        None => retire.extend(
            PROXY_VARS
                .iter()
                .map(|v| vec![ENV_KEY.to_string(), v.to_string()]),
        ),
    }
    let (tz_keys, tz_retire) = tz_key_specs(ENV_KEY, tz);
    keys.extend(tz_keys);
    retire.extend(tz_retire);
    (keys, retire)
}

/// Routes Claude Code / Gemini CLI through Zastava (`proxy_url`) and / or syncs the timezone /
/// locale variables (`tz`) in the `env` block of `settings_path`.
pub(super) fn apply_agent_settings(
    j: &mut Journal,
    p: &dyn Platform,
    ctx: &FileCtx,
    settings_path: &Path,
    proxy_url: Option<&str>,
    tz: Option<&str>,
) -> Result<Vec<ReportItem>, String> {
    let (keys, retire) = agent_keys(proxy_url, tz);
    apply_settings_keys(j, p, &*ctx.fs, settings_path, &keys, &retire)
}

/// The object of the settings files that holds the variables Zastava writes.
pub(super) const AGENT_ENV_KEY: &str = ENV_KEY;
