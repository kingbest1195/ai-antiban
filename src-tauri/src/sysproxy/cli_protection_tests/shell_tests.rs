use super::*;
use crate::sysproxy::ZASTAVA_RC_START;
use crate::sysproxy::ide::{ide_candidates, ide_env_key};
use crate::sysproxy::platform::FakePlatform;
use crate::sysproxy::shell_rc::{
    build_powershell_guard_block_with_tz, build_shell_rc_guard_block_with_tz,
};
use std::sync::Arc;

// --- shell and PowerShell profiles -------------------------------------------------------

fn apply_block(e: &Env, file: &Path, block: &str) -> Result<(), String> {
    let mut j = e.journal();
    apply_profile_block(&mut j, &e.p, &*e.ctx.fs, file, block)
}

#[test]
fn a_profile_with_bom_and_crlf_round_trips_and_new_lines_use_crlf() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    let original = "\u{feff}export A=1\r\nalias ll='ls -l'\r\n";
    e.fs.put(&rc, original.as_bytes(), 0o644);
    apply_block(&e, &rc, &shell_block()).unwrap();
    let t = e.text(&rc);
    assert!(t.starts_with(original), "the user's bytes are a prefix");
    assert!(
        !t.replace("\r\n", "").contains('\n'),
        "the block uses CRLF too"
    );
    assert_eq!(e.fs.mode(&rc).unwrap(), Some(0o644));
    e.disable();
    assert_eq!(e.text(&rc), original);
}

#[test]
fn a_profile_without_a_final_line_end_is_restored_byte_for_byte() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    let original = "export A=1\nalias ll='ls -l'";
    e.fs.put(&rc, original.as_bytes(), 0o644);
    apply_block(&e, &rc, &shell_block()).unwrap();
    assert!(e.text(&rc).starts_with(original));
    e.disable();
    assert_eq!(e.text(&rc), original, "no line end added, none lost");
}

#[test]
fn text_the_user_appended_after_the_block_survives_the_restore() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    let original = "export A=1\n";
    e.fs.put(&rc, original.as_bytes(), 0o644);
    apply_block(&e, &rc, &shell_block()).unwrap();
    let appended = format!("{}alias x=y\n", e.text(&rc));
    e.user_writes(&rc, &appended);
    e.disable();
    assert_eq!(e.text(&rc), "export A=1\nalias x=y\n");
}

#[test]
fn a_block_the_user_edited_after_us_is_not_removed() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    e.fs.put(&rc, b"export A=1\n", 0o644);
    apply_block(&e, &rc, &shell_block()).unwrap();
    let edited = e.text(&rc).replace(
        "  export NO_PROXY=",
        "  export MY_OWN=1\n  export NO_PROXY=",
    );
    e.user_writes(&rc, &edited);
    let report = e.disable();
    assert_eq!(report.external(), 1, "{}", report.summary());
    assert_eq!(
        e.text(&rc),
        edited,
        "the file is exactly as the user left it"
    );
}

#[test]
fn partial_repeated_or_embedded_markers_and_non_utf8_are_not_touched() {
    let start = ZASTAVA_RC_START;
    let end = crate::sysproxy::ZASTAVA_RC_END;
    let block = shell_block();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "start only",
            format!("export A=1\n{start}\nexport B=2\n").into_bytes(),
        ),
        ("end only", format!("export A=1\n{end}\n").into_bytes()),
        (
            "end before start",
            format!("{end}\nx\n{start}\n").into_bytes(),
        ),
        ("two blocks", format!("{block}\n{block}\n").into_bytes()),
        (
            "marker inside a line",
            format!("echo \"{start}\"\n").into_bytes(),
        ),
        (
            "unfinished block",
            format!("{start}\nif true; then\n").into_bytes(),
        ),
        ("not utf-8", b"export A=\"\xff\"\n".to_vec()),
    ];
    for (name, bytes) in cases {
        let e = env();
        let rc = e.ctx.home.join(".zshrc");
        e.fs.put(&rc, &bytes, 0o644);
        assert!(apply_block(&e, &rc, &block).is_err(), "{name}");
        assert_eq!(e.fs.get(&rc).unwrap(), bytes, "{name}");
        e.disable();
        assert_eq!(
            e.fs.get(&rc).unwrap(),
            bytes,
            "{name}: restore does not guess either"
        );
        assert!(e.journal_is_empty(), "{name}");
    }
}

#[test]
fn the_dangerous_old_powershell_else_is_migrated_inside_our_markers_only() {
    let e = env();
    let ps = e
        .ctx
        .home
        .join("Documents")
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    let start = ZASTAVA_RC_START;
    let end = crate::sysproxy::ZASTAVA_RC_END;
    let old_block = format!(
        "{start}\n$__zastavaUp = $false\ntry {{\n  $__zastavaUp = [bool]([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object {{ $_.Port -eq 8899 }})\n}} catch {{}}\nif ($__zastavaUp) {{\n  $env:HTTP_PROXY = \"{URL}\"\n  $env:LANG = \"en_US.UTF-8\"\n}} else {{\n  Remove-Item Env:HTTP_PROXY,Env:HTTPS_PROXY,Env:ALL_PROXY,Env:http_proxy,Env:https_proxy,Env:all_proxy,Env:TZ,Env:LANG,Env:LC_TIME,Env:LC_ALL -ErrorAction SilentlyContinue\n}}\n{end}"
    );
    let before = "Write-Host 'hi'\nif ($x) { 1 } else { Remove-Item Env:MINE }\n";
    let after_text = "Set-Alias a b\n";
    e.fs.put(
        &ps,
        format!("{before}\n{old_block}\n{after_text}").as_bytes(),
        0o644,
    );
    let block = build_powershell_guard_block_with_tz(URL, None);
    apply_block(&e, &ps, &block).unwrap();
    let t = e.text(&ps);
    assert!(t.contains(before) && t.contains(after_text));
    assert!(!t.contains(&old_block));
    let inside = &t[t.find(start).unwrap()..t.find(end).unwrap()];
    assert!(
        !inside.contains("else") && !inside.contains("Remove-Item"),
        "{inside}"
    );
    assert!(
        t.contains("else { Remove-Item Env:MINE }"),
        "outside the markers nothing is touched"
    );
    e.disable();
    assert_eq!(
        e.text(&ps),
        format!("{before}{after_text}"),
        "the old block is gone for good"
    );
}

#[test]
fn a_block_the_user_edited_and_the_journal_does_not_know_is_refused() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    let start = ZASTAVA_RC_START;
    let end = crate::sysproxy::ZASTAVA_RC_END;
    let edited = format!("{start}\nexport HTTPS_PROXY=\"http://corp:3128\"\n{end}\n");
    e.fs.put(&rc, edited.as_bytes(), 0o644);
    assert!(apply_block(&e, &rc, &shell_block()).is_err());
    e.disable();
    assert_eq!(e.text(&rc), edited);
}

#[test]
fn a_profile_that_did_not_exist_is_created_and_removed_again() {
    let e = env();
    let rc = e.ctx.home.join(".zshenv");
    apply_block(&e, &rc, &shell_block()).unwrap();
    assert!(e.text(&rc).starts_with(ZASTAVA_RC_START));
    e.disable();
    assert!(e.fs.get(&rc).is_none());
}

#[test]
fn a_profile_that_existed_empty_stays_as_an_empty_file() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    e.fs.put(&rc, b"", 0o644);
    apply_block(&e, &rc, &shell_block()).unwrap();
    e.disable();
    assert_eq!(e.fs.get(&rc), Some(Vec::new()));
    assert_eq!(e.fs.mode(&rc).unwrap(), Some(0o644));
}

#[test]
fn user_text_without_a_final_newline_is_kept_and_only_whitespace_may_differ() {
    let e = env();
    let rc = e.ctx.home.join(".zshrc");
    e.fs.put(&rc, b"export A=1", 0o644);
    apply_block(&e, &rc, &shell_block()).unwrap();
    e.disable();
    assert_eq!(e.text(&rc).trim_end(), "export A=1");
}

#[test]
fn status_sees_a_block_or_the_proxy_in_agent_settings_and_nothing_else() {
    let e = env();
    assert!(!files_show_protection(&e.ctx));
    let rc = e.ctx.home.join(".zshrc");
    e.fs.put(&rc, b"export A=1\n", 0o644);
    assert!(!files_show_protection(&e.ctx));
    apply_block(&e, &rc, &shell_block()).unwrap();
    assert!(files_show_protection(&e.ctx));
    e.disable();
    assert!(!files_show_protection(&e.ctx));
    e.fs.put(
        &e.ctx.claude_settings(),
        format!("{{\"env\": {{\"HTTPS_PROXY\": \"{URL}\"}}}}").as_bytes(),
        0o644,
    );
    assert!(files_show_protection(&e.ctx));
}

#[test]
fn editor_candidates_come_from_the_context_roots_and_need_an_existing_user_dir() {
    let e = env();
    assert!(ide_candidates(&e.ctx).is_empty());
    e.fs.create_private_dir_all(Path::new(IDE_DIR)).unwrap();
    e.fs.create_private_dir_all(Path::new("/home/u/AppSup/Cursor/User"))
        .unwrap();
    let found = ide_candidates(&e.ctx);
    let labels: Vec<&str> = found.iter().map(|(l, _)| *l).collect();
    assert_eq!(labels, ["VS Code", "Cursor"]);
    assert_eq!(found[0].1, Path::new(IDE_FILE));
}

#[test]
fn enable_on_unix_writes_the_profiles_and_disable_puts_them_back() {
    if !cfg!(unix) {
        return;
    }
    let e = env();
    let zshrc = e.ctx.home.join(".zshrc");
    e.fs.put(&zshrc, b"# mine\n", 0o600);
    let bash = e.ctx.home.join(".bash_profile");
    let targets = e.enable(None);
    assert!(
        targets.iter().any(|t| t.starts_with("Терминал")),
        "{targets:?}"
    );
    assert!(e.text(&zshrc).contains(ZASTAVA_RC_START));
    assert!(
        e.fs.get(&e.ctx.home.join(".zshenv")).is_none(),
        "~/.zshenv is never written"
    );
    assert!(
        e.fs.get(&bash).is_none(),
        ".bash_profile is only edited when it exists"
    );
    e.disable();
    assert_eq!(e.text(&zshrc), "# mine\n");
    assert_eq!(e.fs.mode(&zshrc).unwrap(), Some(0o600));
}

#[cfg(unix)]
#[test]
fn on_a_real_disk_in_a_tempdir_modes_symlinks_and_bytes_survive() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let user = home.join("AppSup").join("Code").join("User");
    std::fs::create_dir_all(&user).unwrap();
    let real = tmp.path().join("dotfiles").join("settings.json");
    std::fs::create_dir_all(real.parent().unwrap()).unwrap();
    let original = "\u{feff}{\r\n  // mine\r\n  \"a\": \"é\"\r\n}\r\n";
    std::fs::write(&real, original).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o640)).unwrap();
    symlink(&real, user.join("settings.json")).unwrap();
    let rc = home.join(".zshrc");
    std::fs::write(&rc, "export A=1\n").unwrap();
    std::fs::set_permissions(&rc, std::fs::Permissions::from_mode(0o644)).unwrap();

    let fs: Arc<dyn crate::sysproxy::fs::Fs> = Arc::new(crate::sysproxy::fs::RealFs);
    let ctx = FileCtx::new(fs.clone(), home.clone(), vec![home.join("AppSup")]);
    let p = FakePlatform::new();
    let mut j = Journal::open(fs, &tmp.path().join("data")).unwrap();
    let plan = FilePlan {
        proxy_url: Some(URL),
        port: 8899,
        tz: Some("Europe/Berlin"),
        mode: CliMode::GlobalTerminal,
        os: HostOs::Unix,
        strip_unjournaled_blocks: false,
    };
    let targets = apply_files(&mut j, &p, &ctx, &plan).targets;
    assert!(targets.contains(&"VS Code".to_string()), "{targets:?}");
    let link = user.join("settings.json");
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let edited = std::fs::read_to_string(&real).unwrap();
    assert!(
        edited.starts_with('\u{feff}')
            && edited.contains("// mine")
            && edited.contains("http.proxy")
    );
    assert_eq!(
        std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert!(
        std::fs::read_to_string(&rc)
            .unwrap()
            .contains(ZASTAVA_RC_START)
    );

    let report = disable_files(&mut j, &p, Some(&ctx), CliMode::GlobalTerminal);
    assert!(!report.has_failures(), "{}", report.summary());
    assert_eq!(std::fs::read_to_string(&real).unwrap(), original);
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::metadata(&real).unwrap().permissions().mode() & 0o7777,
        0o640
    );
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), "export A=1\n");
    assert_eq!(
        std::fs::metadata(&rc).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert!(
        !home.join(".zshenv").exists(),
        "the file Zastava created is gone"
    );
    assert!(!home.join(".claude").join("settings.json").exists());
    assert!(j.is_empty());
}

// --- WP-23: the GUI session is not touched, the NO_PROXY of 2.0.0 stays recognised -------

#[test]
fn enable_never_touches_the_user_environment_with_or_without_a_timezone() {
    for tz in [None, Some("Europe/Berlin")] {
        let e = env();
        e.p.seed_env("HTTPS_PROXY", "http://corp:3128");
        e.enable(tz);
        assert_eq!(e.p.os_writes(), 0, "no launchctl / registry write");
        assert!(
            e.p.calls()
                .iter()
                .all(|c| !c.contains("user_env") && !c.contains("broadcast")),
            "{:?}",
            e.p.calls()
        );
        assert_eq!(e.p.env_of("HTTPS_PROXY"), Some("http://corp:3128".into()));
        assert_eq!(e.p.env_of("TZ"), None);
    }
}

#[test]
fn every_writer_uses_the_one_no_proxy_constant() {
    let e = env();
    let ide = e.ide_with("{\n  \"a\": 1\n}\n", 0o644);
    e.enable(None);
    assert_eq!(
        raw(&e.text(&ide), &[ide_env_key(), "NO_PROXY"]),
        Some(json_str(NO_PROXY_VALUE))
    );
    let block = build_shell_rc_guard_block_with_tz(URL, 8899, None);
    assert!(block.contains(&format!("NO_PROXY=\"{NO_PROXY_VALUE}\"")));
    let ps = build_powershell_guard_block_with_tz(URL, None);
    assert!(ps.contains(NO_PROXY_VALUE));
}

#[test]
fn a_profile_block_with_the_2_0_0_no_proxy_is_still_ours_and_gets_replaced() {
    let e = env();
    let new_block = build_shell_rc_guard_block_with_tz(URL, 8899, None);
    let old_block = new_block.replace(NO_PROXY_VALUE, crate::sysproxy::NO_PROXY_VALUE_2_0);
    assert_ne!(new_block, old_block);
    assert!(is_generated_block(&old_block));
    assert!(is_generated_block(&new_block));
    let zshrc = Path::new("/home/u/.zshrc");
    e.fs.put(zshrc, format!("# mine\n\n{old_block}\n").as_bytes(), 0o644);
    let targets = e.enable(None);
    assert!(!targets.is_empty());
    let after = e.text(zshrc);
    assert!(after.starts_with("# mine\n"));
    // zsh/bash profiles are only written on Unix; Windows has the PowerShell profile instead.
    if cfg!(unix) {
        assert!(after.contains(NO_PROXY_VALUE), "refreshed to the new value");
        assert_eq!(after.matches(ZASTAVA_RC_START).count(), 1);
    }
}

#[test]
fn a_settings_file_with_the_2_0_0_no_proxy_is_cleaned_by_its_signature() {
    let e = env();
    let key = ide_env_key();
    let text = format!(
        "{{\n  \"{key}\": {{\n    \"HTTP_PROXY\": \"{URL}\",\n    \"HTTPS_PROXY\": \"{URL}\",\n    \"NO_PROXY\": \"{}\"\n  }},\n  \"a\": 1\n}}\n",
        crate::sysproxy::NO_PROXY_VALUE_2_0
    );
    let ide = e.ide_with(&text, 0o644);
    e.disable();
    let after = e.text(&ide);
    assert_eq!(raw(&after, &[key]), None, "{after}");
    assert_eq!(raw(&after, &["a"]), Some("1".into()));
}
