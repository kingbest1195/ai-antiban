//! Host information trait (`SystemInfo`) and real OS implementation (`RealSystem`).

use std::net::{IpAddr, Ipv6Addr, UdpSocket};

/// Why a host setting could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemReadError {
    /// This operating system has no such source.
    Unsupported,
    /// The source exists, but reading it failed (command missing, non-zero exit, empty output).
    Failed,
}

/// Everything the checks read from the host.
pub trait SystemInfo: Send + Sync {
    /// Whether the host has a global IPv6 address and a route for it. `None`: could not tell.
    fn has_global_ipv6(&self) -> Option<bool>;
    /// IANA name of the system time zone.
    fn system_timezone(&self) -> Result<String, String>;
    /// Current UTC offset of the host (seconds east).
    fn local_utc_offset_secs(&self) -> Option<i32>;
    /// Current UTC offset of an IANA zone (seconds east); `None` when it cannot be computed here.
    fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32>;
    /// Environment variable of this process.
    fn env_var(&self, name: &str) -> Option<String>;
    /// User locale tags from the OS settings (macOS `AppleLocale`/`AppleLanguages`, Windows
    /// regional settings).
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError>;
    /// Text of the OS DNS configuration (`scutil --dns` / `ipconfig /all`).
    fn dns_listing(&self) -> Result<String, SystemReadError>;
    /// Output of `reg query` of the location consent value (Windows only).
    fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError>;
    /// Whether the independent time zone / locale switch is on and really applied: a zone is being
    /// synced and the AI tools' environment carries `LANG` and `LC_TIME` (`en_US.UTF-8`). Unrelated
    /// to the CLI / IDE proxy protection.
    fn sync_ai_tz_active(&self) -> bool;
}

/// The real host.
pub struct RealSystem;

/// `2000::/3`: addresses that are routed on the Internet.
pub fn is_global_unicast_v6(addr: &Ipv6Addr) -> bool {
    (addr.octets()[0] & 0xe0) == 0x20
}

/// `"+0100"` / `"-0330"` (the output of `date +%z`) to seconds east of UTC.
pub fn parse_utc_offset(text: &str) -> Option<i32> {
    let t = text.trim();
    let (sign, digits) = match t.as_bytes().first()? {
        b'+' => (1, &t[1..]),
        b'-' => (-1, &t[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits[2..].parse().ok()?;
    if hours > 14 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3600 + minutes * 60))
}

/// Values of a `defaults read` output: `ru_RU` or `(\n    "ru-RU",\n    "en-RU"\n)`.
pub fn parse_defaults_values(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| {
            l.trim()
                .trim_matches(|c: char| matches!(c, '(' | ')' | ',' | '"' | ' '))
        })
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// A zone name taken from a remote service is checked before it is used on a command line.
#[cfg_attr(not(unix), allow(dead_code))]
pub(super) fn is_plain_zone_name(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && !zone.starts_with('/')
        && !zone.contains("..")
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'+'))
}

impl SystemInfo for RealSystem {
    fn has_global_ipv6(&self) -> Option<bool> {
        use std::io::ErrorKind::{
            AddrNotAvailable, HostUnreachable, NetworkUnreachable, Unsupported,
        };
        // A connected UDP socket sends nothing: the kernel only picks the route and the source
        // address, so no global IPv6 route means no global source address.
        let sock = match UdpSocket::bind("[::]:0") {
            Ok(s) => s,
            Err(e) if matches!(e.kind(), AddrNotAvailable | Unsupported) => return Some(false),
            Err(_) => return None,
        };
        match sock.connect("[2606:4700:4700::1111]:53") {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    NetworkUnreachable | HostUnreachable | AddrNotAvailable | Unsupported
                ) =>
            {
                return Some(false);
            }
            Err(_) => return None,
        }
        match sock.local_addr().ok()?.ip() {
            IpAddr::V6(v6) => Some(is_global_unicast_v6(&v6)),
            IpAddr::V4(_) => None,
        }
    }

    fn system_timezone(&self) -> Result<String, String> {
        iana_time_zone::get_timezone().map_err(|e| e.to_string())
    }

    fn local_utc_offset_secs(&self) -> Option<i32> {
        Some(chrono::Local::now().offset().local_minus_utc())
    }

    #[cfg(unix)]
    fn zone_utc_offset_secs(&self, zone: &str) -> Option<i32> {
        if !is_plain_zone_name(zone) {
            return None;
        }
        // An unknown zone name makes `date` print UTC without any error: look the zone up first.
        let known = [
            "/usr/share/zoneinfo",
            "/var/db/timezone/zoneinfo",
            "/usr/lib/zoneinfo",
        ]
        .iter()
        .any(|root| std::path::Path::new(root).join(zone).is_file());
        if !known {
            return None;
        }
        let out = crate::sysproxy::silent_command("/bin/date")
            .arg("+%z")
            .env("TZ", zone)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_utc_offset(&String::from_utf8_lossy(&out.stdout))
    }

    #[cfg(not(unix))]
    fn zone_utc_offset_secs(&self, _zone: &str) -> Option<i32> {
        // No time zone database on this OS: the offset of an IANA name cannot be computed.
        None
    }

    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    #[cfg(target_os = "macos")]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        let mut found = Vec::new();
        for key in ["AppleLocale", "AppleLanguages"] {
            let out = crate::sysproxy::silent_command("/usr/bin/defaults")
                .args(["read", "-g", key])
                .output()
                .ok()
                .filter(|o| o.status.success());
            if let Some(out) = out {
                found.extend(parse_defaults_values(&String::from_utf8_lossy(&out.stdout)));
            }
        }
        if found.is_empty() {
            Err(SystemReadError::Failed)
        } else {
            Ok(found)
        }
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        let mut found = Vec::new();
        if let Ok(Some(locale)) = crate::win_reg::get_string(
            crate::win_reg::RootKey::HkeyCurrentUser,
            r"Control Panel\International",
            "LocaleName",
        ) {
            let trimmed = locale.trim();
            if !trimmed.is_empty() {
                found.push(trimmed.to_string());
            }
        }
        if let Ok(Some(langs)) = crate::win_reg::get_multi_sz(
            crate::win_reg::RootKey::HkeyCurrentUser,
            r"Control Panel\International\User Profile",
            "Languages",
        ) {
            found.extend(langs);
        }
        if found.is_empty() {
            Err(SystemReadError::Failed)
        } else {
            Ok(found)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn os_locales(&self) -> Result<Vec<String>, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    #[cfg(target_os = "macos")]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        run_for_text(crate::sysproxy::silent_command("scutil").arg("--dns"))
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        run_for_text(crate::sysproxy::silent_command("ipconfig").arg("/all"))
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    fn dns_listing(&self) -> Result<String, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    // Not built locally (cfg(windows)): verified by the Windows CI only.
    #[cfg(target_os = "windows")]
    fn location_consent(&self, machine_wide: bool) -> Result<String, SystemReadError> {
        let (root, subkey) = if machine_wide {
            (
                crate::win_reg::RootKey::HkeyLocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            )
        } else {
            (
                crate::win_reg::RootKey::HkeyCurrentUser,
                r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
            )
        };
        match crate::win_reg::get_string(root, subkey, "Value") {
            Ok(Some(val)) if !val.trim().is_empty() => Ok(val),
            _ => Err(SystemReadError::Failed),
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn location_consent(&self, _machine_wide: bool) -> Result<String, SystemReadError> {
        Err(SystemReadError::Unsupported)
    }

    fn sync_ai_tz_active(&self) -> bool {
        crate::sysproxy::sync_ai_tz_active()
    }
}

/// Stdout of a finished command; a spawn error, a non-zero exit or an empty output is `Failed`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn run_for_text(cmd: &mut std::process::Command) -> Result<String, SystemReadError> {
    match cmd.output() {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            if text.trim().is_empty() {
                Err(SystemReadError::Failed)
            } else {
                Ok(text)
            }
        }
        _ => Err(SystemReadError::Failed),
    }
}

/// Values of `reg query` lines: `    LocaleName    REG_SZ    ru-RU` and
/// `    Languages    REG_MULTI_SZ    ru-RU\0en-US`.
#[cfg(any(test, target_os = "windows"))]
pub fn parse_reg_string_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(idx) = line.find("REG_") else {
            continue;
        };
        let after = &line[idx..];
        let mut parts = after.splitn(2, char::is_whitespace);
        let _kind = parts.next();
        let value = parts.next().unwrap_or("").trim();
        for item in value.split("\\0") {
            let item = item.trim();
            if !item.is_empty() {
                out.push(item.to_string());
            }
        }
    }
    out
}
