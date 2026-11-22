use std::fs;

fn collect_rs_files_sorted(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files_sorted(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn is_test_only_rust_file(rel: &str) -> bool {
    rel == "tests.rs"
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_tests.rs")
        || rel.contains("/tests/")
        || rel == "fakes.rs"
        || rel.ends_with("/fakes.rs")
}

fn strip_rust_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut in_string = false;
    let mut in_raw_hashes: Option<usize> = None;
    let mut block_depth = 0usize;

    while i < bytes.len() {
        if block_depth > 0 {
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                block_depth += 1;
                i += 2;
                continue;
            }
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                block_depth -= 1;
                i += 2;
                out.push(' ');
                continue;
            }
            if bytes[i] == b'\n' {
                out.push('\n');
            }
            i += 1;
            continue;
        }
        if let Some(hashes) = in_raw_hashes {
            let ch = src[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            if ch == '"'
                && bytes[i..].len() >= hashes
                && bytes[i..i + hashes].iter().all(|&b| b == b'#')
            {
                for _ in 0..hashes {
                    out.push('#');
                }
                i += hashes;
                in_raw_hashes = None;
            }
            continue;
        }
        if in_string {
            let ch = src[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            if ch == '\\' && i < bytes.len() {
                let next = src[i..].chars().next().unwrap();
                out.push(next);
                i += next.len_utf8();
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            block_depth = 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'r' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                j += 1;
            }
            if j < bytes.len()
                && bytes[j] == b'"'
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_')
            {
                let hashes = j - (i + 1);
                out.push_str(&src[i..=j]);
                i = j + 1;
                in_raw_hashes = Some(hashes);
                continue;
            }
        }
        if bytes[i] == b'\'' {
            // Handle char literals (`'"'`, `'\\'`, `'\x7f'`, etc.) without confusing them with lifetimes (`'a`).
            let rest = &bytes[i + 1..];
            let char_len = if rest.starts_with(b"\\") {
                let mut k = 2;
                while k < rest.len() && k < 12 && rest[k] != b'\'' && rest[k] != b'\n' {
                    k += 1;
                }
                if k < rest.len() && rest[k] == b'\'' {
                    Some(k + 2)
                } else {
                    None
                }
            } else {
                let mut chars = src[i + 1..].chars();
                if let Some(c) = chars.next()
                    && c != '\''
                    && c != '\n'
                    && chars.next() == Some('\'')
                {
                    Some(1 + c.len_utf8() + 1)
                } else {
                    None
                }
            };
            if let Some(len) = char_len {
                out.push_str(&src[i..i + len]);
                i += len;
                continue;
            }
        }
        if bytes[i] == b'"' {
            in_string = true;
            out.push('"');
            i += 1;
            continue;
        }
        let ch = src[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Folds `concat!("a", "b", ...)` string-literal calls so split LOLBin literals cannot hide.
fn fold_literal_concats(src: &str) -> String {
    let mut out = src.to_string();
    while let Some(pos) = out.find("concat!(") {
        let args_start = pos + "concat!(".len();
        let bytes = out.as_bytes();
        let mut i = args_start;
        let mut depth = 1usize;
        let mut in_str = false;
        while i < bytes.len() && depth > 0 {
            if in_str {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            match bytes[i] {
                b'"' => in_str = true,
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        if depth != 0 {
            break;
        }
        let inner = &out[args_start..i - 1];
        let mut folded = String::new();
        let mut only_literals = true;
        for part in inner.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if p.starts_with('"')
                && p.ends_with('"')
                && p.len() >= 2
                && !p[1..p.len() - 1].contains('"')
            {
                folded.push_str(&p[1..p.len() - 1]);
            } else {
                only_literals = false;
                break;
            }
        }
        if only_literals {
            out.replace_range(pos..i, &format!("\"{folded}\""));
        } else {
            // Avoid infinite loop on mixed `concat!("v", env!(...))` (keep remaining args scanned).
            out.replace_range(pos..args_start, "concat_checked!(");
        }
    }
    out
}

fn collapse_rust_tokens(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut prev_space = false;
    for ch in src.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.replace(" :: ", "::")
        .replace(":: ", "::")
        .replace(" ::", "::")
        .replace(" (", "(")
        .replace("( ", "(")
        .replace(" )", ")")
        .to_ascii_lowercase()
}

fn extract_include_str_paths(src: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut rest = src;
    while let Some(pos) = rest.find("include_str!(") {
        let after = &rest[pos + "include_str!(".len()..];
        let trimmed = after.trim_start();
        if let Some(stripped) = trimmed.strip_prefix('"')
            && let Some(end) = stripped.find('"')
        {
            paths.push(stripped[..end].to_string());
        }
        rest = after;
    }
    paths
}

#[test]
fn all_windows_prod_sources_and_nsis_hooks_have_zero_lolbin_regressions() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_root = manifest_dir.join("src");
    let mut rs_files = Vec::new();
    collect_rs_files_sorted(&src_root, &mut rs_files);
    assert!(!rs_files.is_empty());

    // Strict zero-tolerance LOLBin/obfuscation patterns that trigger Windows Defender heuristics.
    const STRICT: &[&str] = &[
        "pwsh",
        "cmd.exe",
        "netsh",
        "reg.exe",
        "\"reg\"",
        "wmic",
        "bitsadmin",
        "certutil",
        "mshta",
        "rundll32",
        "cscript",
        "wscript",
        "\"schtasks\"",
        "\"sc.exe\"",
        "\"ipconfig\"",
        "\"netstat\"",
        "\"tasklist\"",
        "\"taskkill\"",
        "\"tzutil\"",
        "-encodedcommand",
        "-executionpolicy",
        "get-ciminstance",
        "compress-archive",
        "schedule.service",
    ];
    let mut violations = Vec::new();
    for path in rs_files {
        let rel = path
            .strip_prefix(&src_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_only_rust_file(&rel) {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Stop at the first `#[cfg(test)] mod ...` boundary (matching check-architecture.mjs).
        let prod_end = (0..lines.len())
            .find(|&i| {
                let t = lines[i].trim();
                t.starts_with("#[cfg(test)]")
                    && (t.contains("mod ")
                        || lines[i + 1..lines.len().min(i + 5)].iter().any(|n| {
                            let nt = n.trim();
                            !nt.is_empty()
                                && !nt.starts_with("//")
                                && !nt.starts_with("#[")
                                && nt.contains("mod ")
                        }))
            })
            .unwrap_or(lines.len());
        let prod_raw = lines[..prod_end].join("\n");
        let prod_no_comments = strip_rust_comments(&prod_raw);
        let prod_folded = fold_literal_concats(&prod_no_comments);

        for (idx, raw) in prod_folded.lines().enumerate() {
            let t = raw.trim();
            if t.is_empty() {
                continue;
            }
            let lower = t.to_ascii_lowercase();
            for pat in STRICT {
                let xml_guard = rel == "cowork_guard/task_xml.rs"
                    && (*pat == "pwsh" || *pat == "cmd.exe")
                    && lower.contains(".contains(");
                if lower.contains(pat) && !xml_guard {
                    violations.push(format!("src/{rel}:{}: `{pat}` -> {t}", idx + 1));
                }
            }
            if lower.contains("powershell") {
                // Narrow allowlist: user `$PROFILE` helpers/UI strings and the Task XML rejector; NEVER process spawn.
                let profile_ctx = matches!(
                    rel.as_str(),
                    "sysproxy/shell_rc.rs"
                        | "sysproxy/cli_protection/files.rs"
                        | "sysproxy/cli_protection/legacy.rs"
                        | "sysproxy/cli_protection/mod.rs"
                        | "sysproxy/state.rs"
                        | "sysproxy/mod.rs"
                        | "diagnostics/preview.rs"
                        | "state/schema.rs"
                ) || (rel == "cowork_guard/task_xml.rs"
                    && lower.contains(".contains("));
                if !profile_ctx
                    || lower.contains("command::new")
                    || lower.contains("silent_command")
                {
                    violations.push(format!("src/{rel}:{}: `powershell` -> {t}", idx + 1));
                }
            }
            if lower.contains("\"cmd\"") {
                let allowed_dry_run_stub = rel == "sysproxy/mod.rs"
                    && t == "let mut cmd = std::process::Command::new(\"cmd\");";
                if !allowed_dry_run_stub {
                    violations.push(format!("src/{rel}:{}: `\"cmd\"` -> {t}", idx + 1));
                }
            }
            for pat in ["getsecuritydescriptor", "setsecuritydescriptor"] {
                if lower.contains(pat)
                    && (rel != "win_native/task_scheduler.rs"
                        || lower.contains(&format!("\"{pat}")))
                {
                    violations.push(format!("src/{rel}:{}: `{pat}` -> {t}", idx + 1));
                }
            }
        }

        // Multi-line scan across collapsed production code (catches `Command::new(\n "powershell"\n)`,
        // `silent_command(\n "netsh"\n)`, non-literal `concat!` inside process spawns, etc.).
        let collapsed = collapse_rust_tokens(&prod_folded);
        for spawn in ["command::new(", "silent_command("] {
            for suspicious in [
                "powershell",
                "pwsh",
                "cmd.exe",
                "\"cmd\"",
                "netsh",
                "reg.exe",
                "\"reg\"",
                "wmic",
                "bitsadmin",
                "certutil",
                "mshta",
                "rundll32",
                "cscript",
                "wscript",
                "schtasks",
                "sc.exe",
                "ipconfig",
                "netstat",
                "tasklist",
                "taskkill",
                "tzutil",
                "concat_checked!(",
            ] {
                let needle = format!("{spawn}{suspicious}");
                if collapsed.contains(&needle) {
                    let allowed_dry_run_stub =
                        rel == "sysproxy/mod.rs" && needle == "command::new(\"cmd\"";
                    if !allowed_dry_run_stub {
                        violations.push(format!("src/{rel}: multi-line/obfuscated `{needle}`"));
                    }
                }
            }
        }

        // Scan any `include_str!(...)` embedded files referenced by production code.
        for inc_rel in extract_include_str_paths(&prod_folded) {
            let inc_path = path.parent().unwrap().join(&inc_rel);
            if let Ok(inc_text) = fs::read_to_string(&inc_path) {
                let inc_lower = inc_text.to_ascii_lowercase();
                for pat in STRICT.iter().copied().chain(["powershell", "\"cmd\""]) {
                    if inc_lower.contains(pat) {
                        violations.push(format!("src/{rel} include_str!({inc_rel}): `{pat}`"));
                    }
                }
            }
        }
    }

    let sysproxy_mod = fs::read_to_string(src_root.join("sysproxy/mod.rs")).unwrap();
    assert_eq!(
        sysproxy_mod.matches("\"cmd\"").count(),
        1,
        "only the test-support dry-run stub may mention \"cmd\""
    );
    assert!(
        sysproxy_mod.contains(
            "#[cfg(all(target_os = \"windows\", any(test, feature = \"test-support\")))]"
        )
    );

    let nsh = fs::read_to_string(manifest_dir.join("windows/hooks.nsh")).unwrap();
    for (idx, line) in nsh.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with(';') {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        for pat in STRICT.iter().copied().chain([
            "powershell",
            "\"cmd\"",
            "schtasks",
            "getsecuritydescriptor",
            "setsecuritydescriptor",
        ]) {
            if lower.contains(pat) {
                violations.push(format!("windows/hooks.nsh:{}: `{pat}` -> {t}", idx + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "Static AV / LOLBin scan failed:\n{}",
        violations.join("\n")
    );
}

#[test]
fn lolbin_scanner_catches_multiline_concat_and_preserves_char_literals() {
    let sample = r#"
        // comment mentioning reg.exe and netsh must be ignored
        let q = '"';
        let _ = q;
        let c = std::process::Command::new(
            concat!("pow", "ershell")
        );
        let s = silent_command(
            "netsh"
        );
    "#;
    let stripped = strip_rust_comments(sample);
    assert!(!stripped.contains("reg.exe"));
    let folded = fold_literal_concats(&stripped);
    assert!(folded.contains("\"powershell\""));
    let collapsed = collapse_rust_tokens(&folded);
    assert!(collapsed.contains("command::new(\"powershell\""));
    assert!(collapsed.contains("silent_command(\"netsh\""));
}
