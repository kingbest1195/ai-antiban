//! SemVer helpers, GitHub release discovery, and rollback manifest validation.

use super::{CURRENT_VERSION, GITHUB_REPO, RollbackReleaseInfo, UpdateFailure};
use serde::Deserialize;
use std::cmp::Ordering;
use std::time::Duration;

const GITHUB_RELEASES_API_URL: &str =
    "https://api.github.com/repos/kingbest1195/ai-antiban/releases?per_page=15";
const ROLLBACK_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
pub const ROLLBACK_MAX_RELEASES: usize = 8;

#[derive(Debug, Clone, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitHubReleaseAsset {
    name: String,
}

/// Parses a semantic version string (e.g. `"v1.0.4"` -> `(1, 0, 4)`).
pub fn parse_semver(ver: &str) -> Option<(u32, u32, u32)> {
    let clean = ver.trim().trim_start_matches(['v', 'V']);
    let core = clean.split('-').next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    Some((major, minor, patch))
}

/// The pre-release tail of a version (`"2.1.0-rc.1"` -> `Some("rc.1")`), if any.
fn pre_release(ver: &str) -> Option<&str> {
    let clean = ver.trim().trim_start_matches(['v', 'V']);
    clean
        .split_once('-')
        .map(|(_, pre)| pre)
        .filter(|p| !p.is_empty())
}

/// Orders two pre-release tails the way semver does: dot-separated identifiers, numbers compare
/// numerically and sort before words, a shorter tail sorts before a longer one it prefixes.
fn compare_pre_release(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Returns `true` if `latest` is strictly newer than `current`. A release is newer than its own
/// pre-release (`2.1.0` > `2.1.0-1`), so a trial build can update to the final release.
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(cur), Some(lat)) if cur != lat => lat > cur,
        (Some(_), Some(_)) => match (pre_release(current), pre_release(latest)) {
            (Some(_), None) => true,
            (Some(c), Some(l)) => compare_pre_release(c, l) == Ordering::Less,
            (None, _) => false,
        },
        _ => false,
    }
}

/// Strictly validates and normalizes a SemVer string (`major.minor.patch`, optional `-pre`),
/// stripping at most one leading `v`/`V`. Rejects empty strings, missing/extra dot segments,
/// leading zeros on multi-digit numeric parts, and URL-unsafe characters.
pub fn normalize_semver(ver: &str) -> Option<String> {
    let trimmed = ver.trim();
    let clean = trimmed.strip_prefix(['v', 'V']).unwrap_or(trimmed);
    if clean.is_empty() {
        return None;
    }
    let (core, pre) = match clean.split_once('-') {
        Some((c, p)) => {
            if p.is_empty()
                || p.starts_with('.')
                || p.ends_with('.')
                || p.contains("..")
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                return None;
            }
            (c, Some(p))
        }
        None => (clean, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    for part in &parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        part.parse::<u32>().ok()?;
    }
    Some(match pre {
        Some(p) => format!("{core}-{p}"),
        None => core.to_string(),
    })
}

/// Returns `true` if `candidate` is a valid SemVer strictly older than `current`.
pub fn is_older_version(current: &str, candidate: &str) -> bool {
    let (Some(cur), Some(cand)) = (normalize_semver(current), normalize_semver(candidate)) else {
        return false;
    };
    is_newer_version(&cand, &cur)
}

fn compare_semver_desc(a: &str, b: &str) -> Ordering {
    if is_newer_version(b, a) {
        Ordering::Less
    } else if is_newer_version(a, b) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// Parses GitHub Releases API JSON into rollback-eligible releases strictly older than
/// `current_version`, sorted newest-first and capped at [`ROLLBACK_MAX_RELEASES`].
pub fn parse_rollback_releases(
    json_str: &str,
    current_version: &str,
) -> Result<Vec<RollbackReleaseInfo>, UpdateFailure> {
    let releases: Vec<GitHubRelease> =
        serde_json::from_str(json_str).map_err(|_| UpdateFailure::NoRelease)?;
    let repo_prefix = format!("https://github.com/{GITHUB_REPO}/");

    let mut items: Vec<RollbackReleaseInfo> = releases
        .into_iter()
        .filter(|r| !r.draft && !r.prerelease)
        .filter(|r| r.assets.iter().any(|a| a.name == "latest.json"))
        .filter_map(|r| {
            let version = normalize_semver(&r.tag_name)?;
            if !is_older_version(current_version, &version) {
                return None;
            }
            let name = r
                .name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| format!("Zastava v{version}"));
            let notes_url = r
                .html_url
                .map(|u| u.trim().to_string())
                .filter(|u| u.starts_with(&repo_prefix))
                .unwrap_or_else(|| release_url_for(&version));
            Some(RollbackReleaseInfo {
                version,
                tag: r.tag_name.trim().to_string(),
                name,
                published_at: r.published_at,
                notes_url,
            })
        })
        .collect();

    items.sort_by(|a, b| compare_semver_desc(&a.version, &b.version));
    items.dedup_by(|a, b| a.version == b.version);
    items.truncate(ROLLBACK_MAX_RELEASES);
    Ok(items)
}

/// Validates a target rollback version and builds the canonical `github.com` `latest.json` URL.
pub fn rollback_manifest_url(version: &str) -> Result<(String, url::Url), UpdateFailure> {
    let clean = normalize_semver(version).ok_or(UpdateFailure::NoRelease)?;
    if !is_older_version(CURRENT_VERSION, &clean) {
        return Err(UpdateFailure::NoRelease);
    }
    let raw = format!("https://github.com/{GITHUB_REPO}/releases/download/v{clean}/latest.json");
    let url = url::Url::parse(&raw).map_err(|_| UpdateFailure::NoRelease)?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        return Err(UpdateFailure::NoRelease);
    }
    Ok((clean, url))
}

/// Release page for a version, always on our own repository.
pub fn release_url_for(version: &str) -> String {
    let clean = version.trim().trim_start_matches(['v', 'V']);
    format!("https://github.com/{GITHUB_REPO}/releases/tag/v{clean}")
}

pub(super) fn latest_release_url() -> String {
    format!("https://github.com/{GITHUB_REPO}/releases/latest")
}

/// Fetches recent GitHub Releases and returns signed releases strictly older than
/// [`CURRENT_VERSION`] (newest-first, up to 8 entries) that include a `latest.json` asset.
pub async fn list_rollback_versions() -> Result<Vec<RollbackReleaseInfo>, UpdateFailure> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(ROLLBACK_HTTP_TIMEOUT)
        .build()
        .map_err(|_| UpdateFailure::Network)?;

    let resp = client
        .get(GITHUB_RELEASES_API_URL)
        .header(reqwest::header::USER_AGENT, "Zastava-Updater")
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| UpdateFailure::Network)?;

    if !resp.status().is_success() {
        return Err(UpdateFailure::Network);
    }

    let body = resp.text().await.map_err(|_| UpdateFailure::Network)?;
    parse_rollback_releases(&body, CURRENT_VERSION)
}
