use super::pac_verify::same_pac;
use super::types::{CoverageStatus, Verdict, pac_url_for, steps, steps_of};
use crate::sysproxy::FileCtx;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Which Antigravity this is. Version 1.x was a VS Code fork with `User/settings.json`; 2.x is an
/// Electron app without `User/` whose agent (a separate Go binary) takes the proxy only from
/// environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AntigravityKind {
    /// Has `<root>/Antigravity/User`: `http.proxy` in `settings.json` is the model.
    Editor,
    /// The desktop app (bundle or data folder) without `User/`.
    Desktop,
    /// Only `~/.gemini/antigravity-cli`.
    CliOnly,
}

/// The `.app` bundle of Antigravity: the system one first, then the user's own. One place, so the
/// coverage status and the restart button always mean the same installation.
pub(crate) fn antigravity_app_path(ctx: &FileCtx) -> Option<PathBuf> {
    [
        PathBuf::from("/Applications/Antigravity.app"),
        ctx.home.join("Applications").join("Antigravity.app"),
    ]
    .into_iter()
    .find(|p| ctx.fs.exists(p))
}

pub(crate) fn antigravity_kind(ctx: &FileCtx) -> Option<AntigravityKind> {
    let ex = |p: &Path| ctx.fs.exists(p);
    if ctx
        .ide_roots
        .iter()
        .any(|r| ex(&r.join("Antigravity").join("User")))
    {
        return Some(AntigravityKind::Editor);
    }
    if antigravity_app_path(ctx).is_some()
        || ctx.ide_roots.iter().any(|r| ex(&r.join("Antigravity")))
    {
        return Some(AntigravityKind::Desktop);
    }
    ex(&ctx.home.join(".gemini").join("antigravity-cli")).then_some(AntigravityKind::CliOnly)
}

/// Status of Antigravity 2.x without traffic. The interface part (Chromium) follows the system
/// PAC; the agent does not, so the PAC alone never makes the app covered: only traffic does.
pub(super) fn antigravity_app_fact(
    sysproxy_enabled: bool,
    effective: Option<bool>,
    pac_verdict: Verdict,
) -> (CoverageStatus, Vec<String>, String) {
    let pac_applies = sysproxy_enabled
        && match effective {
            Some(v) => v,
            None => pac_verdict == Verdict::Configured,
        };
    if pac_applies {
        (
            CoverageStatus::Off,
            steps_of(&[steps::LAUNCH_WITH_ENV]),
            "Интерфейс следует системному PAC, а агент — нет: перезапустите через Заставу с переменными прокси или включите «Весь терминал»".to_string(),
        )
    } else {
        (
            CoverageStatus::Off,
            steps_of(&[steps::ENABLE_SYSTEM_PROXY, steps::LAUNCH_WITH_ENV]),
            "Antigravity не использует прокси Заставы: агент может ходить напрямую".to_string(),
        )
    }
}


/// Does a process listing (`ps -axo comm=` paths or `tasklist` names) show Antigravity? Names
/// only: the arguments of processes are never requested.
pub(super) fn listing_has_antigravity(text: &str) -> bool {
    text.lines()
        .any(|l| l.to_ascii_lowercase().contains("antigravity"))
}

/// Is a process of this application an agent of Antigravity? The agent is a separate
/// `language_server*` binary; the id is the one `resolve_app_identity` builds from its name.
pub(super) fn is_antigravity_agent_id(id: &str) -> bool {
    id.starts_with("language-server")
}

/// Folder names under the editors' per-user data root.
pub(super) fn ide_folders(id: &str) -> &'static [&'static str] {
    match id {
        "antigravity" => &["Antigravity"],
        "cursor" => &["Cursor"],
        "vscode" => &["Code", "VSCodium"],
        "windsurf" => &["Windsurf"],
        _ => &[],
    }
}

/// Does an `http.proxy` value point at the local gateway on `port`?
pub fn proxy_value_targets_gateway(raw: &str, port: u16) -> bool {
    let raw = raw.trim();
    if raw.is_empty() {
        return false;
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let Ok(url) = url::Url::parse(&with_scheme) else {
        return false;
    };
    let host_ok = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    host_ok && url.port_or_known_default() == Some(port)
}

/// `http.proxy` of the editor's `settings.json` against the gateway port.
pub(super) fn ide_verdict(ctx: &FileCtx, folders: &[&str], gateway_port: u16) -> Verdict {
    let mut unreadable = false;
    for root in &ctx.ide_roots {
        for folder in folders {
            let path = root.join(folder).join("User").join("settings.json");
            match ctx.fs.read(&path) {
                Ok(Some(bytes)) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let text = text.trim_start_matches('\u{feff}');
                    let cleaned = crate::sysproxy::sanitize_jsonc(text);
                    match serde_json::from_str::<serde_json::Value>(&cleaned) {
                        Ok(v) => {
                            if v.get("http.proxy")
                                .and_then(|p| p.as_str())
                                .is_some_and(|p| proxy_value_targets_gateway(p, gateway_port))
                            {
                                return Verdict::Configured;
                            }
                        }
                        Err(_) => unreadable = true,
                    }
                }
                Ok(None) => {}
                Err(_) => unreadable = true,
            }
        }
    }
    if unreadable {
        Verdict::Unknown
    } else {
        Verdict::Off
    }
}

// ----- JetBrains -------------------------------------------------------------------------------

/// Value of `<option name="X" value="Y" />` in a JetBrains settings XML (the format is not
/// confirmed: see [`JETBRAINS_XML_CONFIRMED`]).
fn xml_option(xml: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{name}\"");
    let at = xml.find(&needle)?;
    let tag_start = xml[..at].rfind('<')?;
    let tag_end = at + xml[at..].find('>')?;
    let tag = &xml[tag_start..=tag_end];
    let v_at = tag.find("value=\"")? + "value=\"".len();
    let rest = &tag[v_at..];
    Some(rest[..rest.find('"')?].to_string())
}

fn jetbrains_xml_verdict(xml: &str, gateway: SocketAddr) -> Verdict {
    let flag = |n: &str| xml_option(xml, n).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if flag("USE_HTTP_PROXY") {
        let host_ok = xml_option(xml, "PROXY_HOST")
            .is_some_and(|h| matches!(h.trim(), "127.0.0.1" | "localhost"));
        let port_ok = xml_option(xml, "PROXY_PORT")
            .and_then(|p| p.trim().parse::<u16>().ok())
            .is_some_and(|p| p == gateway.port());
        return if host_ok && port_ok {
            Verdict::Configured
        } else {
            Verdict::Off
        };
    }
    if flag("USE_PROXY_PAC") {
        return match xml_option(xml, "PAC_URL") {
            Some(u) if same_pac(&u, &pac_url_for(gateway)) => Verdict::Configured,
            Some(_) => Verdict::Off,
            None => Verdict::Unknown,
        };
    }
    Verdict::Unknown
}

/// `<root>/JetBrains/<Product>/options/proxy.settings.xml` for every product directory.
fn jetbrains_xml_candidates(ctx: &FileCtx) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in &ctx.ide_roots {
        if let Ok(rd) = std::fs::read_dir(root.join("JetBrains")) {
            for entry in rd.flatten() {
                out.push(entry.path().join("options").join("proxy.settings.xml"));
            }
        }
    }
    out.sort();
    out
}

pub(super) fn jetbrains_fact(
    files: Option<&FileCtx>,
    gateway: Option<SocketAddr>,
    confirmed: bool,
) -> (CoverageStatus, Vec<String>, String) {
    let manual = steps_of(&[
        steps::JETBRAINS_PROXY_SETTINGS,
        steps::SET_PAC_URL,
        steps::SET_HTTP_PROXY,
    ]);
    let unknown = (
        CoverageStatus::Unknown,
        manual.clone(),
        "Настройки прокси JetBrains проверить нельзя: смотрим по трафику".to_string(),
    );
    if !confirmed {
        return unknown;
    }
    let (Some(ctx), Some(g)) = (files, gateway) else {
        return unknown;
    };
    let mut seen_configured = false;
    let mut seen_off = false;
    for path in jetbrains_xml_candidates(ctx) {
        if let Ok(Some(bytes)) = ctx.fs.read(&path) {
            match jetbrains_xml_verdict(&String::from_utf8_lossy(&bytes), g) {
                Verdict::Configured => seen_configured = true,
                Verdict::Off => seen_off = true,
                Verdict::Unknown => {}
            }
        }
    }
    if seen_configured {
        (
            CoverageStatus::Configured,
            Vec::new(),
            "Прокси JetBrains указывает на Заставу, ждём первый запрос".to_string(),
        )
    } else if seen_off {
        (
            CoverageStatus::Off,
            manual,
            "Прокси JetBrains настроен не на Заставу".to_string(),
        )
    } else {
        unknown
    }
}
