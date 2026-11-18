//! Journal resource, value, and entry models, URL equivalence, and schema validation.

use super::{JournalError, SCHEMA_VERSION};
use crate::sysproxy::browser_policies::PolicyValue;
use crate::sysproxy::platform::{ChainState, PacState, RegValue, ServiceId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A system setting Zastava may own.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Resource {
    /// Auto Proxy (PAC) of one macOS service.
    Pac { service: ServiceId },
    /// Explicit HTTP/HTTPS proxy of one macOS service.
    Chain { service: ServiceId },
    /// Proxy bypass domains of one macOS service (a snapshot taken before its explicit proxy is
    /// switched off, so the list comes back exactly as the user had it).
    Bypass { service: ServiceId },
    /// One variable of the user environment (launchctl / `HKCU\Environment`).
    UserEnv { name: String },
    /// One WinINet value (`AutoConfigURL`, `ProxyEnable`, ...).
    Inet { name: String },
    /// One key inside a JSONC settings file (`path` holds the exact key names, outermost first).
    JsonKey { file: String, path: Vec<String> },
    /// An object inside a JSONC settings file that Zastava may have created. Restoring a
    /// baseline of "absent" removes it only while it is empty (no members, no comments).
    JsonObject { file: String, path: Vec<String> },
    /// The Zastava block (between its exact marker lines) inside a shell / PowerShell profile.
    TextBlock { file: String },
    /// A file Zastava may have created. Restoring a baseline of "absent" removes it only while
    /// its content is still the bare `skeleton` it was created with.
    File { file: String, skeleton: String },
    /// Per-user browser policy setting (QUIC / DoH) keyed by domain/subkey and preference/value name.
    BrowserPolicy { domain: String, key: String },
    /// Chromium profile `Preferences` JSON `"proxy"` key, keyed by browser domain/id and file path.
    BrowserPacPref { domain: String, file: String },
}

/// Last path components, for logs: names a file without the user's home directory. A path that
/// goes through `Users/<name>` or `home/<name>` is cut right after the account name, so the name
/// never reaches a log (`/Users/ivan/.zshrc` -> `.zshrc`).
pub(super) fn file_label(file: &str) -> String {
    let parts: Vec<&str> = file.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
    let rest = parts
        .iter()
        .position(|p| p.eq_ignore_ascii_case("Users") || p.eq_ignore_ascii_case("home"))
        .map_or(&parts[..], |i| &parts[(i + 2).min(parts.len())..]);
    rest[rest.len().saturating_sub(3)..].join("/")
}

impl Resource {
    /// Name of the resource for logs and reports. Contains no values.
    pub fn id(&self) -> String {
        match self {
            Resource::Pac { service } => format!("pac:{}", service.key()),
            Resource::Chain { service } => format!("chain:{}", service.key()),
            Resource::Bypass { service } => format!("bypass:{}", service.key()),
            Resource::UserEnv { name } => format!("env:{name}"),
            Resource::Inet { name } => format!("inet:{name}"),
            Resource::JsonKey { file, path } => {
                format!("json:{}:{}", file_label(file), path.join("/"))
            }
            Resource::JsonObject { file, path } => {
                format!("jsonobj:{}:{}", file_label(file), path.join("/"))
            }
            Resource::TextBlock { file } => format!("block:{}", file_label(file)),
            Resource::File { file, .. } => format!("file:{}", file_label(file)),
            Resource::BrowserPolicy { domain, key } => format!("policy:{domain}:{key}"),
            Resource::BrowserPacPref { domain, file } => {
                format!("browser_pac_pref:{domain}:{}", file_label(file))
            }
        }
    }

    /// Whether the resource lives in a user file (as opposed to the OS settings).
    pub fn is_file_resource(&self) -> bool {
        matches!(
            self,
            Resource::JsonKey { .. }
                | Resource::JsonObject { .. }
                | Resource::TextBlock { .. }
                | Resource::File { .. }
        )
    }

    /// Order inside one restore pass: keys and blocks first, then the objects that held them,
    /// then the files that held those. Stable for everything else.
    pub(super) fn restore_rank(&self) -> u8 {
        match self {
            Resource::JsonObject { .. } => 1,
            Resource::File { .. } => 2,
            _ => 0,
        }
    }
}

/// A typed snapshot of a resource. "No value" is part of the type, never an empty string.
/// `Debug` names the variant and whether a value is there, never the value itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Value {
    Pac(PacState),
    Chain(ChainState),
    /// Bypass domains of a service; empty = none.
    Bypass(Vec<String>),
    Env(Option<String>),
    Reg(Option<RegValue>),
    /// The exact JSON text of a value in a JSONC file; `None` = the key is absent.
    Json(Option<String>),
    /// Whether the object / file exists.
    Present(bool),
    /// The text of the Zastava block (line ends normalised to `\n`); `None` = no block.
    Block(Option<String>),
    /// Per-user browser policy value; `None` = key/value absent before Zastava touched it.
    Policy(Option<PolicyValue>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn shown(present: bool) -> &'static str {
            if present { "<redacted>" } else { "None" }
        }
        match self {
            // `PacState`, `ChainState` and `RegValue` redact their own `Debug`.
            Value::Pac(p) => write!(f, "Pac({p:?})"),
            Value::Chain(c) => write!(f, "Chain({c:?})"),
            Value::Reg(r) => write!(f, "Reg({r:?})"),
            Value::Bypass(d) => write!(f, "Bypass(<{} entries>)", d.len()),
            Value::Env(v) => write!(f, "Env({})", shown(v.is_some())),
            Value::Json(v) => write!(f, "Json({})", shown(v.is_some())),
            Value::Block(v) => write!(f, "Block({})", shown(v.is_some())),
            Value::Present(b) => write!(f, "Present({b})"),
            Value::Policy(v) => write!(f, "Policy({v:?})"),
        }
    }
}

impl Value {
    pub(super) fn matches(&self, res: &Resource) -> bool {
        matches!(
            (self, res),
            (Value::Pac(_), Resource::Pac { .. })
                | (Value::Chain(_), Resource::Chain { .. })
                | (Value::Bypass(_), Resource::Bypass { .. })
                | (Value::Env(_), Resource::UserEnv { .. })
                | (Value::Reg(_), Resource::Inet { .. })
                | (Value::Json(_), Resource::JsonKey { .. })
                | (Value::Present(_), Resource::JsonObject { .. })
                | (Value::Present(_), Resource::File { .. })
                | (Value::Block(_), Resource::TextBlock { .. })
                | (Value::Policy(_), Resource::BrowserPolicy { .. })
                | (Value::Json(_), Resource::BrowserPacPref { .. })
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Intent is durable; the OS write is not confirmed yet (or an update is in flight).
    Pending,
    /// The OS write is confirmed; `expected` is what we wrote.
    Applied,
}

/// One owned resource.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub resource: Resource,
    /// What was there before Zastava touched it. Written once, never replaced.
    pub baseline: Value,
    /// The last confirmed value we wrote.
    #[serde(default)]
    pub expected: Option<Value>,
    /// The value an in-flight write is about to set; the previous `expected` stays meanwhile.
    #[serde(default)]
    pub pending: Option<Value>,
    pub state: EntryState,
    /// The OS write landed but the best-effort change notification (WinINet refresh, environment
    /// broadcast) failed; it is repeated by the next pass.
    #[serde(default, skip_serializing_if = "is_false")]
    pub notify_pending: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Scheme and host in lower case, the default port dropped, an empty path read as `/`: the ways
/// an OS may rewrite a URL it was given without changing where it points. `None` = not a URL.
fn normalize_url(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if scheme.is_empty() || authority.is_empty() {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let mut authority = authority.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => ":80",
        "https" => ":443",
        _ => "",
    };
    if !default_port.is_empty() && authority.ends_with(default_port) {
        authority.truncate(authority.len() - default_port.len());
    }
    let tail = if tail.is_empty() || tail.starts_with(['?', '#']) {
        format!("/{tail}")
    } else {
        tail.to_string()
    };
    Some(format!("{scheme}://{authority}{tail}"))
}

pub(super) fn urls_equivalent(a: &str, b: &str) -> bool {
    a == b
        || matches!(
            (normalize_url(a), normalize_url(b)),
            (Some(x), Some(y)) if x == y
        )
}

/// Whether `known` (a value we wrote) and `cur` (what the OS holds now) are the same value up to
/// the OS's own normalisation of a URL (case of the host, default port, empty path).
pub(super) fn same_as_written(res: &Resource, known: &Value, cur: &Value) -> bool {
    if known == cur {
        return true;
    }
    match (res, known, cur) {
        (Resource::Pac { .. }, Value::Pac(a), Value::Pac(b)) => {
            a.enabled == b.enabled
                && match (&a.url, &b.url) {
                    (Some(x), Some(y)) => urls_equivalent(x, y),
                    (x, y) => x == y,
                }
        }
        (Resource::Inet { name }, Value::Reg(Some(a)), Value::Reg(Some(b)))
            if name == "AutoConfigURL" =>
        {
            a.kind == b.kind && urls_equivalent(&a.data, &b.data)
        }
        (
            Resource::BrowserPolicy { key, .. },
            Value::Policy(Some(PolicyValue::Sz(a))),
            Value::Policy(Some(PolicyValue::Sz(b))),
        ) if key == crate::sysproxy::browser_policies::KEY_PROXY_PAC_URL => {
            urls_equivalent(a, b)
        }
        (Resource::BrowserPacPref { .. }, Value::Json(Some(a)), Value::Json(Some(b))) => {
            crate::sysproxy::browser_policies::same_browser_proxy_json(a, b)
        }
        _ => false,
    }
}

/// The PAC URL a value carries (`Pac` of a service, `AutoConfigURL` of WinINet, or browser
/// `ProxyPacUrl` policy), if any.
fn pac_url_of<'a>(res: &Resource, v: &'a Value) -> Option<&'a str> {
    match (res, v) {
        (Resource::Pac { .. }, Value::Pac(p)) => p.url.as_deref(),
        (Resource::Inet { name }, Value::Reg(Some(r))) if name == "AutoConfigURL" => {
            Some(r.data.as_str())
        }
        (Resource::BrowserPolicy { key, .. }, Value::Policy(Some(PolicyValue::Sz(u))))
            if key == crate::sysproxy::browser_policies::KEY_PROXY_PAC_URL =>
        {
            Some(u.as_str())
        }
        _ => None,
    }
}

/// Whether `cur` is a PAC address of Zastava's own gateway. The gateway port is the one of the
/// value being written (`new`). Such a value is never "somebody else's": it must not become the
/// baseline, or a restore would put Zastava's own PAC back.
pub(super) fn carries_zastava_signature(res: &Resource, cur: &Value, new: &Value) -> bool {
    if let (Resource::BrowserPacPref { .. }, Value::Json(Some(cur_s)), Value::Json(Some(new_s))) =
        (res, cur, new)
    {
        let port = crate::sysproxy::browser_policies::extract_pac_url_from_proxy_json(new_s)
            .and_then(|u| crate::sysproxy::parse_gateway_port_from_pac_url(&u));
        return crate::sysproxy::browser_policies::extract_pac_url_from_proxy_json(cur_s)
            .is_some_and(|u| crate::sysproxy::cleanup::is_zastava_pac_signature(&u, port));
    }
    let port = pac_url_of(res, new).and_then(crate::sysproxy::parse_gateway_port_from_pac_url);
    pac_url_of(res, cur)
        .is_some_and(|u| crate::sysproxy::cleanup::is_zastava_pac_signature(u, port))
}

/// What a service's PAC is taken to have held before Zastava, when only its own leftover is
/// found there: off, no address.
pub(super) fn neutral_pac_baseline() -> Value {
    Value::Pac(PacState {
        url: None,
        enabled: Some(false),
    })
}

impl Entry {
    /// Whether `cur` is a value this record accounts for: what we last wrote (`expected`), what
    /// an in-flight write was about to set (`pending`) - both up to the OS's normalisation of a
    /// URL - or, for the explicit proxy of a service, a half-finished write. `set_chain` is two
    /// commands (HTTP, then HTTPS); a process killed between them leaves each side at either the
    /// old or the new value, and that mix is ours, not an external change.
    pub(super) fn is_ours(&self, cur: &Value) -> bool {
        let written = |known: &Option<Value>| {
            known
                .as_ref()
                .is_some_and(|k| same_as_written(&self.resource, k, cur))
        };
        written(&self.expected) || written(&self.pending) || self.is_half_written_chain(cur)
    }

    fn is_half_written_chain(&self, cur: &Value) -> bool {
        let (Resource::Chain { .. }, Value::Chain(c), EntryState::Pending) =
            (&self.resource, cur, self.state)
        else {
            return false;
        };
        let known: Vec<&ChainState> = [
            Some(&self.baseline),
            self.expected.as_ref(),
            self.pending.as_ref(),
        ]
        .into_iter()
        .flatten()
        .filter_map(|v| match v {
            Value::Chain(k) => Some(k),
            _ => None,
        })
        .collect();
        known.iter().any(|k| k.http == c.http) && known.iter().any(|k| k.https == c.https)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileData {
    pub(super) schema_version: u32,
    pub(super) entries: Vec<Entry>,
    /// One-shot markers (e.g. a finished legacy migration). Live under the same lock and are
    /// written atomically together with the entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) marks: Vec<String>,
}

pub(super) fn parse(bytes: &[u8]) -> Result<(Vec<Entry>, Vec<String>), JournalError> {
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| JournalError::Corrupt)?;
    let version = raw
        .get("schema_version")
        .and_then(|v| v.as_u64())
        .ok_or(JournalError::Corrupt)?;
    if version != u64::from(SCHEMA_VERSION) {
        return Err(JournalError::UnknownSchema(
            u32::try_from(version).unwrap_or(u32::MAX),
        ));
    }
    let data: FileData = serde_json::from_value(raw).map_err(|_| JournalError::Corrupt)?;
    for (i, e) in data.entries.iter().enumerate() {
        let kinds_ok = e.baseline.matches(&e.resource)
            && e.expected.as_ref().is_none_or(|v| v.matches(&e.resource))
            && e.pending.as_ref().is_none_or(|v| v.matches(&e.resource));
        let state_ok = match e.state {
            EntryState::Applied => e.expected.is_some() && e.pending.is_none(),
            EntryState::Pending => e.pending.is_some(),
        };
        let unique = !data.entries[..i].iter().any(|o| o.resource == e.resource);
        if !(kinds_ok && state_ok && unique) {
            return Err(JournalError::Corrupt);
        }
    }
    Ok((data.entries, data.marks))
}
