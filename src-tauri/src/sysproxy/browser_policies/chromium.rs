//! Chromium-family browser catalog, policy domain lists, and platform policy specs.

use super::{
    KEY_DOH_MODE, KEY_PROXY_MODE, KEY_PROXY_PAC_URL, KEY_QUIC_ALLOWED, PROXY_MODE_PAC_SCRIPT,
    PolicySpec, PolicyValue,
};

/// Metadata for one supported Chromium-family browser across macOS, Windows, and Linux.
#[derive(Clone, Copy, Debug)]
pub struct ChromiumBrowserDef {
    /// Canonical identifier (matches the macOS bundle identifier).
    pub id: &'static str,
    /// Human-friendly display name shown in UI / coverage lists.
    pub display_name: &'static str,
    /// macOS `.app` bundle directory names (e.g. `"Google Chrome.app"`).
    pub macos_bundles: &'static [&'static str],
    /// Relative paths under `~/Library/Application Support` holding Chromium User Data.
    pub macos_user_data_rels: &'static [&'static str],
    /// Relative paths under `~/.config` holding Chromium User Data on Linux.
    pub linux_config_rels: &'static [&'static str],
    /// Lowercase executable names for macOS/Linux (`ps`) process matching.
    pub process_names: &'static [&'static str],
}

/// All 15 Chromium-family browsers supported by Zastava's policy + `Preferences` PAC enforcement.
pub const CHROMIUM_BROWSERS: [ChromiumBrowserDef; 15] = [
    ChromiumBrowserDef {
        id: "com.google.Chrome",
        display_name: "Google Chrome",
        macos_bundles: &["Google Chrome.app"],
        macos_user_data_rels: &["Google/Chrome"],
        linux_config_rels: &["google-chrome"],
        process_names: &["chrome.exe", "google-chrome", "chrome"],
    },
    ChromiumBrowserDef {
        id: "com.google.Chrome.beta",
        display_name: "Google Chrome Beta",
        macos_bundles: &["Google Chrome Beta.app"],
        macos_user_data_rels: &["Google/Chrome Beta"],
        linux_config_rels: &["google-chrome-beta"],
        process_names: &["chrome.exe", "google-chrome-beta"],
    },
    ChromiumBrowserDef {
        id: "com.google.Chrome.canary",
        display_name: "Google Chrome Canary",
        macos_bundles: &["Google Chrome Canary.app"],
        macos_user_data_rels: &["Google/Chrome Canary"],
        linux_config_rels: &["google-chrome-unstable"],
        process_names: &["chrome.exe", "google-chrome-unstable"],
    },
    ChromiumBrowserDef {
        id: "ai.perplexity.comet",
        display_name: "Comet",
        macos_bundles: &["Comet.app"],
        macos_user_data_rels: &["Comet"],
        linux_config_rels: &["comet"],
        process_names: &["comet.exe", "comet"],
    },
    ChromiumBrowserDef {
        id: "ru.yandex.desktop.yandex-browser",
        display_name: "Yandex Browser",
        macos_bundles: &["Yandex.app", "Yandex Browser.app"],
        macos_user_data_rels: &["Yandex/YandexBrowser"],
        linux_config_rels: &["yandex-browser", "yandex-browser-beta"],
        process_names: &["browser.exe", "yandex.exe", "yandex-browser"],
    },
    ChromiumBrowserDef {
        id: "com.brave.Browser",
        display_name: "Brave",
        macos_bundles: &["Brave Browser.app"],
        macos_user_data_rels: &["BraveSoftware/Brave-Browser"],
        linux_config_rels: &["BraveSoftware/Brave-Browser"],
        process_names: &["brave.exe", "brave-browser", "brave"],
    },
    ChromiumBrowserDef {
        id: "com.brave.Browser.beta",
        display_name: "Brave Beta",
        macos_bundles: &["Brave Browser Beta.app"],
        macos_user_data_rels: &["BraveSoftware/Brave-Browser-Beta"],
        linux_config_rels: &["BraveSoftware/Brave-Browser-Beta"],
        process_names: &["brave.exe", "brave-browser-beta"],
    },
    ChromiumBrowserDef {
        id: "com.microsoft.edgemac",
        display_name: "Microsoft Edge",
        macos_bundles: &["Microsoft Edge.app"],
        macos_user_data_rels: &["Microsoft Edge"],
        linux_config_rels: &["microsoft-edge"],
        process_names: &["msedge.exe", "microsoft-edge", "msedge"],
    },
    ChromiumBrowserDef {
        id: "company.thebrowser.Browser",
        display_name: "Arc",
        macos_bundles: &["Arc.app"],
        macos_user_data_rels: &["Arc/User Data", "Arc"],
        linux_config_rels: &[],
        process_names: &["arc.exe", "arc"],
    },
    ChromiumBrowserDef {
        id: "company.thebrowser.dia",
        display_name: "Dia",
        macos_bundles: &["Dia.app"],
        macos_user_data_rels: &["Dia/User Data", "Dia"],
        linux_config_rels: &[],
        process_names: &["dia.exe", "dia"],
    },
    ChromiumBrowserDef {
        id: "com.operasoftware.Opera",
        display_name: "Opera",
        macos_bundles: &["Opera.app"],
        macos_user_data_rels: &["com.operasoftware.Opera", "Opera"],
        linux_config_rels: &["opera"],
        process_names: &["opera.exe", "opera"],
    },
    ChromiumBrowserDef {
        id: "com.operasoftware.OperaGX",
        display_name: "Opera GX",
        macos_bundles: &["Opera GX.app"],
        macos_user_data_rels: &["com.operasoftware.OperaGX", "Opera GX"],
        linux_config_rels: &["opera-gx"],
        process_names: &["opera.exe", "opera-gx"],
    },
    ChromiumBrowserDef {
        id: "com.vivaldi.Vivaldi",
        display_name: "Vivaldi",
        macos_bundles: &["Vivaldi.app"],
        macos_user_data_rels: &["Vivaldi"],
        linux_config_rels: &["vivaldi"],
        process_names: &["vivaldi.exe", "vivaldi-bin", "vivaldi"],
    },
    ChromiumBrowserDef {
        id: "org.chromium.Chromium",
        display_name: "Chromium",
        macos_bundles: &["Chromium.app"],
        macos_user_data_rels: &["Chromium"],
        linux_config_rels: &["chromium", "chromium-browser"],
        process_names: &["chrome.exe", "chromium", "chromium-browser"],
    },
    ChromiumBrowserDef {
        id: "com.openai.atlas",
        display_name: "ChatGPT Atlas",
        macos_bundles: &["ChatGPT Atlas.app"],
        macos_user_data_rels: &["ChatGPT Atlas", "com.openai.atlas", "OpenAI/ChatGPT Atlas"],
        linux_config_rels: &[],
        process_names: &["chatgpt atlas.exe", "atlas.exe"],
    },
];

/// Chromium-family preference domains on macOS.
pub const MACOS_CHROMIUM_DOMAIN_NAMES: [&str; 15] = [
    "com.google.Chrome",
    "com.google.Chrome.beta",
    "com.google.Chrome.canary",
    "com.brave.Browser",
    "com.brave.Browser.beta",
    "com.microsoft.edgemac",
    "org.chromium.Chromium",
    "com.vivaldi.Vivaldi",
    "com.operasoftware.Opera",
    "com.operasoftware.OperaGX",
    "ru.yandex.desktop.yandex-browser",
    "company.thebrowser.Browser",
    "company.thebrowser.dia",
    "ai.perplexity.comet",
    "com.openai.atlas",
];

/// Chromium-family HKCU policy subkeys on Windows.
#[cfg(any(target_os = "windows", test))]
pub const WINDOWS_CHROMIUM_DOMAIN_NAMES: [&str; 12] = [
    r"Software\Policies\Google\Chrome",
    r"Software\Policies\Microsoft\Edge",
    r"Software\Policies\BraveSoftware\Brave",
    r"Software\Policies\Chromium",
    r"Software\Policies\Vivaldi",
    r"Software\Policies\YandexBrowser",
    r"Software\Policies\Yandex\YandexBrowser",
    r"Software\Policies\Perplexity\Comet",
    r"Software\Policies\Opera Software\Opera Stable",
    r"Software\Policies\Opera Software\Opera GX Stable",
    r"Software\Policies\TheBrowserCompany\Arc",
    r"Software\Policies\TheBrowserCompany\Dia",
];

/// Mapping from Windows Chromium HKCU policy subkeys to human-friendly browser names.
pub const WINDOWS_CHROMIUM_POLICY_BROWSERS: [(&str, &str); 12] = [
    (r"Software\Policies\Google\Chrome", "Google Chrome"),
    (r"Software\Policies\Microsoft\Edge", "Microsoft Edge"),
    (r"Software\Policies\BraveSoftware\Brave", "Brave"),
    (r"Software\Policies\Chromium", "Chromium"),
    (r"Software\Policies\Vivaldi", "Vivaldi"),
    (r"Software\Policies\YandexBrowser", "Yandex Browser"),
    (r"Software\Policies\Yandex\YandexBrowser", "Yandex Browser"),
    (r"Software\Policies\Perplexity\Comet", "Comet"),
    (r"Software\Policies\Opera Software\Opera Stable", "Opera"),
    (
        r"Software\Policies\Opera Software\Opera GX Stable",
        "Opera GX",
    ),
    (r"Software\Policies\TheBrowserCompany\Arc", "Arc"),
    (r"Software\Policies\TheBrowserCompany\Dia", "Dia"),
];

pub(super) fn clean_pac_url(pac_url: Option<&str>) -> Option<&str> {
    pac_url.map(str::trim).filter(|u| !u.is_empty())
}

pub(super) fn same_pac_url(a: &str, b: &str) -> bool {
    a.trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(b.trim().trim_end_matches('/'))
}

/// Builds Chromium-family (plus Firefox DoH on Windows) policy specs for Windows.
#[cfg(any(target_os = "windows", test))]
pub fn policy_specs_for_windows(pac_url: Option<&str>) -> Vec<PolicySpec> {
    let pac = clean_pac_url(pac_url);
    let mut specs = Vec::new();
    for subkey in WINDOWS_CHROMIUM_DOMAIN_NAMES {
        specs.push(PolicySpec::new(
            subkey,
            KEY_QUIC_ALLOWED,
            PolicyValue::Dword(0),
        ));
        specs.push(PolicySpec::new(
            subkey,
            KEY_DOH_MODE,
            PolicyValue::Sz("off".to_string()),
        ));
        if let Some(url) = pac {
            specs.push(PolicySpec::new(
                subkey,
                KEY_PROXY_MODE,
                PolicyValue::Sz(PROXY_MODE_PAC_SCRIPT.to_string()),
            ));
            specs.push(PolicySpec::new(
                subkey,
                KEY_PROXY_PAC_URL,
                PolicyValue::Sz(url.to_string()),
            ));
        }
    }
    specs.push(PolicySpec::new(
        r"Software\Policies\Mozilla\Firefox\DNSOverHTTPS",
        "Enabled",
        PolicyValue::Dword(0),
    ));
    specs
}

/// Builds Chromium-family policy specs for macOS.
#[cfg(any(target_os = "macos", test))]
pub fn policy_specs_for_macos(pac_url: Option<&str>) -> Vec<PolicySpec> {
    let pac = clean_pac_url(pac_url);
    let mut specs = Vec::new();
    for domain in MACOS_CHROMIUM_DOMAIN_NAMES {
        specs.push(PolicySpec::new(
            domain,
            KEY_QUIC_ALLOWED,
            PolicyValue::Bool(false),
        ));
        specs.push(PolicySpec::new(
            domain,
            KEY_DOH_MODE,
            PolicyValue::Sz("off".to_string()),
        ));
        if let Some(url) = pac {
            specs.push(PolicySpec::new(
                domain,
                KEY_PROXY_MODE,
                PolicyValue::Sz(PROXY_MODE_PAC_SCRIPT.to_string()),
            ));
            specs.push(PolicySpec::new(
                domain,
                KEY_PROXY_PAC_URL,
                PolicyValue::Sz(url.to_string()),
            ));
        }
    }
    specs
}

/// Returns the platform-appropriate Chromium/Firefox QUIC, DoH, and optional PAC policy specs.
pub fn policy_specs_with_pac(pac_url: Option<&str>) -> Vec<PolicySpec> {
    #[cfg(target_os = "windows")]
    {
        policy_specs_for_windows(pac_url)
    }
    #[cfg(target_os = "macos")]
    {
        policy_specs_for_macos(pac_url)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = pac_url;
        Vec::new()
    }
}
