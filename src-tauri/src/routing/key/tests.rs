use super::*;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

fn zkey(json: &str) -> String {
    format!("zastava://{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

#[test]
fn test_v2_full_key() {
    let key = zkey(
        r#"{"v":2,"id":"nl-ams-01","label":"NL · Claude","country":"nl","exit_ip":"185.10.10.1","expires_at":1767225600,
           "entry":[{"proto":"https","host":"entry1.example.net","port":443,"username":"u1","password":"p1","sni":"cdn.example.net"},
                    {"proto":"socks5","host":"185.10.10.2","port":1080,"username":"u2","password":"p2"}]}"#,
    );
    let r = parse_route_key(&key, 7).expect("v2 parse");
    assert_eq!(r.id, "nl-ams-01");
    assert_eq!(r.label, "NL · Claude");
    assert_eq!(r.country.as_deref(), Some("NL"));
    assert_eq!(r.exit_ip.as_deref(), Some("185.10.10.1"));
    assert_eq!(r.expires_at, Some(1767225600));
    assert_eq!(r.entries.len(), 2);
    assert_eq!(r.entries[0].proto, EntryProto::Https);
    assert_eq!(r.entries[0].sni.as_deref(), Some("cdn.example.net"));
    assert_eq!(r.entries[1].proto, EntryProto::Socks5);
    assert_eq!(r.added_at, 7);
    assert!(r.enabled);
    assert_eq!(r.raw_key, key);
}

#[test]
fn test_v2_rejections() {
    let unknown = zkey(r#"{"v":3,"entry":[]}"#);
    let err = parse_route_key(&unknown, 0).unwrap_err();
    assert!(err.contains("v=3"), "{err}");

    let empty = zkey(r#"{"v":2,"entry":[]}"#);
    assert!(parse_route_key(&empty, 0).is_err());

    let private = zkey(r#"{"v":2,"entry":[{"proto":"https","host":"10.0.0.5","port":443}]}"#);
    assert!(parse_route_key(&private, 0).is_err());

    let port0 = zkey(r#"{"v":2,"entry":[{"proto":"https","host":"a.example.net","port":0}]}"#);
    assert!(parse_route_key(&port0, 0).is_err());

    let sni_socks = zkey(
        r#"{"v":2,"entry":[{"proto":"socks5","host":"a.example.net","port":1080,"sni":"x.example.net"}]}"#,
    );
    assert!(parse_route_key(&sni_socks, 0).is_err());

    let bad_id = zkey(
        r#"{"v":2,"id":"../etc","entry":[{"proto":"https","host":"a.example.net","port":443}]}"#,
    );
    assert!(parse_route_key(&bad_id, 0).is_err());

    let bad_exit = zkey(
        r#"{"v":2,"exit_ip":"127.0.0.1","entry":[{"proto":"https","host":"a.example.net","port":443}]}"#,
    );
    assert!(parse_route_key(&bad_exit, 0).is_err());

    let crlf = zkey(
        r#"{"v":2,"entry":[{"proto":"http","host":"a.example.net","port":80,"username":"a\r\nX-Evil: 1","password":"p"}]}"#,
    );
    assert!(parse_route_key(&crlf, 0).is_err());

    let long_label = zkey(&format!(
        r#"{{"v":2,"label":"{}","entry":[{{"proto":"https","host":"a.example.net","port":443}}]}}"#,
        "x".repeat(100)
    ));
    assert!(parse_route_key(&long_label, 0).is_err());
}

#[test]
fn test_errors_never_contain_password() {
    // Password given with a wrong type: serde would normally quote the value.
    let k =
        zkey(r#"{"v":2,"entry":[{"proto":"https","host":"a.example.net","port":"TopSecret42"}]}"#);
    let err = parse_route_key(&k, 0).unwrap_err();
    assert!(!err.contains("TopSecret42"), "{err}");

    let err = parse_route_key("socks5://user:TopSecret42@169.254.169.254:1080", 0).unwrap_err();
    assert!(!err.contains("TopSecret42"), "{err}");

    let err = parse_route_key("ftp://user:TopSecret42@1.2.3.4:21", 0).unwrap_err();
    assert!(!err.contains("TopSecret42"), "{err}");

    let err = parse_route_key("https://user:TopSecret42@[::1:443", 0).unwrap_err();
    assert!(!err.contains("TopSecret42"), "{err}");
}

#[test]
fn test_https_url_form() {
    let r = parse_route_key("https://bob:p%40ss@entry.example.net:8443#Мой ключ", 0).unwrap();
    assert_eq!(r.entries[0].proto, EntryProto::Https);
    assert_eq!(r.entries[0].host, "entry.example.net");
    assert_eq!(r.entries[0].port, 8443);
    assert_eq!(r.entries[0].username.as_deref(), Some("bob"));
    assert_eq!(r.entries[0].password.as_deref(), Some("p@ss"));
    assert_eq!(r.label, "Мой ключ");
    assert!(r.id.starts_with("r-"));

    let default_port = parse_route_key("https://entry.example.net", 0).unwrap();
    assert_eq!(default_port.entries[0].port, 443);
}

#[test]
fn test_v1_json_and_host_rules() {
    let k = format!(
        "zastava://{}",
        STANDARD.encode(br#"{"protocol":"socks5","host":"45.1.2.3","port":1080,"username":"u1","password":"p1","label":"NL-Fast"}"#)
    );
    let r = parse_route_key(&k, 0).unwrap();
    assert_eq!(r.entries[0].proto, EntryProto::Socks5);
    assert_eq!(r.label, "NL-Fast");

    // Internal names / single-label hosts are never accepted.
    assert!(parse_route_key("http://router.local:8080", 0).is_err());
    assert!(parse_route_key("http://intranet:8080", 0).is_err());
    assert!(parse_route_key("socks5://[2a01:4f8::1]:1080", 0).is_ok());
    // Local addresses are for the user's own URL keys only (see test_local_policy_*).
    assert!(parse_route_key("socks5://[fd00::1]:1080", 0).is_ok());
    assert!(parse_route_key("socks5://169.254.169.254:1080", 0).is_err());
}

#[test]
fn test_local_policy_manual_url_keys_allow_local_proxy() {
    for k in [
        "socks5://127.0.0.1:10808",
        "socks5://localhost:10808",
        "http://10.0.0.1:8080",
        "http://192.168.1.5:3128#Router",
        "https://172.16.0.9:8443",
        "socks5://[::1]:10808",
        "socks5://100.64.1.2:1080",
    ] {
        let r = parse_route_key(k, 0).unwrap_or_else(|e| panic!("{k}: {e}"));
        assert!(r.allows_local_entries(), "{k}");
    }
    // The gateway itself is never allowed (loop) ...
    for k in [
        "socks5://127.0.0.1:8899",
        "http://localhost:8900",
        "socks5://[::1]:8899",
    ] {
        assert!(parse_route_key(k, 0).is_err(), "{k}");
    }
    // ... nor reserved / link-local / unspecified ranges.
    for k in [
        "socks5://0.0.0.0:1080",
        "socks5://169.254.1.1:1080",
        "socks5://240.0.0.1:1080",
    ] {
        assert!(parse_route_key(k, 0).is_err(), "{k}");
    }
}

#[test]
fn test_local_policy_zastava_keys_are_public_only() {
    for h in [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "localhost",
        "::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "::10.0.0.1",
    ] {
        let k = zkey(&format!(
            r#"{{"v":2,"entry":[{{"proto":"socks5","host":"{h}","port":1080}}]}}"#
        ));
        assert!(parse_route_key(&k, 0).is_err(), "v2 {h}");
    }
    let v1 = zkey(r#"{"protocol":"socks5","host":"127.0.0.1","port":1080}"#);
    assert!(parse_route_key(&v1, 0).is_err());
    // A URL wrapped into zastava:// is still external.
    let wrapped = format!(
        "zastava://{}",
        URL_SAFE_NO_PAD.encode(b"socks5://127.0.0.1:10808")
    );
    assert!(parse_route_key(&wrapped, 0).is_err());
    let ok = zkey(r#"{"v":2,"entry":[{"proto":"socks5","host":"185.1.1.1","port":1080}]}"#);
    assert!(!parse_route_key(&ok, 0).unwrap().allows_local_entries());
}

#[test]
fn test_numeric_and_hex_host_spellings_rejected() {
    for h in [
        "127.1",
        "0x7f.1",
        "0x7f000001.example.net",
        "10.1",
        "2130706433",
        "1.2.3",
        "a.0x1f.example.net",
        "localtest.123",
    ] {
        let k = zkey(&format!(
            r#"{{"v":2,"entry":[{{"proto":"socks5","host":"{h}","port":1080}}]}}"#
        ));
        assert!(parse_route_key(&k, 0).is_err(), "v2 {h}");
    }
    // Not even for the user's own URL keys: write the dotted address.
    for u in [
        "socks5://127.1:1080",
        "socks5://0x7f.1:1080",
        "socks5://2130706433:1080",
    ] {
        assert!(parse_route_key(u, 0).is_err(), "{u}");
    }
    // Ordinary names are untouched.
    assert!(parse_route_key("socks5://nl-1.node-2.example.net:1080", 0).is_ok());
}

#[test]
fn test_plus_in_password_is_not_a_space() {
    let r = parse_route_key("socks5://user:a+b@185.1.1.1:1080", 0).unwrap();
    assert_eq!(r.entries[0].password.as_deref(), Some("a+b"));
    let r = parse_route_key("http://us+er:a%2Bb%20c%zz@185.1.1.1:8080#A+B%20C", 0).unwrap();
    assert_eq!(r.entries[0].username.as_deref(), Some("us+er"));
    assert_eq!(r.entries[0].password.as_deref(), Some("a+b c%zz"));
    assert_eq!(r.label, "A+B C");
}

#[test]
fn parses_commercial_host_port_user_pass_and_schemeless_formats() {
    let r1 = parse_route_key("socks5://proxy.example.com:10000:demo_user:demo_pass", 0).unwrap();
    assert_eq!(r1.entries[0].proto, EntryProto::Socks5);
    assert_eq!(r1.entries[0].host, "proxy.example.com");
    assert_eq!(r1.entries[0].port, 10000);
    assert_eq!(r1.entries[0].username.as_deref(), Some("demo_user"));
    assert_eq!(r1.entries[0].password.as_deref(), Some("demo_pass"));

    // Scheme-less defaults to socks5://
    let r2 = parse_route_key("proxy.example.com:10000:demo_user:demo_pass", 0).unwrap();
    assert_eq!(r2.entries[0].proto, EntryProto::Socks5);
    assert_eq!(r2.entries[0].host, "proxy.example.com");
    assert_eq!(r2.entries[0].port, 10000);
    assert_eq!(r2.entries[0].username.as_deref(), Some("demo_user"));
    assert_eq!(r2.entries[0].password.as_deref(), Some("demo_pass"));

    // Colons inside password in host:port:user:pass
    let r3 = parse_route_key("http://proxy.example.com:8080:demo_user:pa:ss:123", 0).unwrap();
    assert_eq!(r3.entries[0].proto, EntryProto::Http);
    assert_eq!(r3.entries[0].password.as_deref(), Some("pa:ss:123"));

    // host:port@user:pass
    let r4 = parse_route_key("socks5://proxy.example.com:10000@demo_user:demo_pass", 0).unwrap();
    assert_eq!(r4.entries[0].host, "proxy.example.com");
    assert_eq!(r4.entries[0].port, 10000);
    assert_eq!(r4.entries[0].username.as_deref(), Some("demo_user"));
    assert_eq!(r4.entries[0].password.as_deref(), Some("demo_pass"));

    // Unencoded @ and # inside password in user:pass@host:port
    let r5 = parse_route_key("socks5://demo_user:p@ss#1@proxy.example.com:1080#Work", 0).unwrap();
    assert_eq!(r5.entries[0].host, "proxy.example.com");
    assert_eq!(r5.entries[0].port, 1080);
    assert_eq!(r5.entries[0].username.as_deref(), Some("demo_user"));
    assert_eq!(r5.entries[0].password.as_deref(), Some("p@ss#1"));
    assert_eq!(r5.label, "Work");

    // IPv6 host:port:user:pass
    let r6 = parse_route_key("socks5://[::1]:1080:demo_user:demo_pass", 0).unwrap();
    assert_eq!(r6.entries[0].host, "::1");
    assert_eq!(r6.entries[0].port, 1080);
    assert_eq!(r6.entries[0].username.as_deref(), Some("demo_user"));
    assert_eq!(r6.entries[0].password.as_deref(), Some("demo_pass"));

    // Bare host:port
    let r7 = parse_route_key("127.0.0.1:1080", 0).unwrap();
    assert_eq!(r7.entries[0].proto, EntryProto::Socks5);
    assert_eq!(r7.entries[0].host, "127.0.0.1");
    assert_eq!(r7.entries[0].port, 1080);
    assert!(r7.entries[0].username.is_none());
}

#[test]
fn invalid_proxy_errors_are_russian_and_never_leak_credentials() {
    let err =
        parse_route_key("socks5://demo_user:SecretPass99@169.254.169.254:1080", 0).unwrap_err();
    assert!(!err.contains("SecretPass99"), "{err}");
    assert!(
        err.chars()
            .any(|c| ('а'..='я').contains(&c) || ('А'..='Я').contains(&c)),
        "{err}"
    );

    let bad = parse_route_key(
        "socks5://proxy.example.com:notaport:demo_user:SecretPass99",
        0,
    )
    .unwrap_err();
    assert!(!bad.contains("SecretPass99"), "{bad}");
    assert!(bad.contains("Примеры:"), "{bad}");
}

#[test]
fn accepts_uppercase_zastava_scheme_and_preserves_trailing_slash_in_password() {
    let payload = r#"{"v":2,"entry":[{"proto":"socks5","host":"185.1.1.1","port":1080,"username":"UserA","password":"PassWord/"}]}"#;
    let upper = format!("ZASTAVA://{}", URL_SAFE_NO_PAD.encode(payload.as_bytes()));
    let route = parse_route_key(&upper, 0).unwrap();
    assert_eq!(route.entries[0].username.as_deref(), Some("UserA"));
    assert_eq!(route.entries[0].password.as_deref(), Some("PassWord/"));

    let slash_pass = parse_route_key("socks5://proxy.example.com:1080:demo_user:paSs/", 0).unwrap();
    assert_eq!(slash_pass.entries[0].password.as_deref(), Some("paSs/"));
}

#[test]
fn test_v2_sub_url_validation_and_backwards_compat() {
    let valid = zkey(
        r#"{"v":2,"id":"sub-1","expires_at":1800000000,"sub_url":"https://sub.example.net/keys/sub-1","entry":[{"proto":"https","host":"entry.example.net","port":443}]}"#,
    );
    let r = parse_route_key(&valid, 10).unwrap();
    assert_eq!(
        r.sub_url.as_deref(),
        Some("https://sub.example.net/keys/sub-1")
    );
    assert!(!r.grace_extended);

    // Old KeyV2 without sub_url stays 100% compatible.
    let legacy = zkey(
        r#"{"v":2,"id":"old-1","entry":[{"proto":"socks5","host":"185.10.10.2","port":1080}]}"#,
    );
    let r_old = parse_route_key(&legacy, 10).unwrap();
    assert!(r_old.sub_url.is_none());

    // Reject http://, private/loopback IP, and embedded credentials in sub_url.
    for bad_sub in [
        "http://sub.example.net/keys/1",
        "https://127.0.0.1/keys/1",
        "https://10.0.0.5/keys/1",
        "https://user:pass@sub.example.net/keys/1",
    ] {
        let k = zkey(&format!(
            r#"{{"v":2,"sub_url":"{bad_sub}","entry":[{{"proto":"https","host":"entry.example.net","port":443}}]}}"#
        ));
        assert!(parse_route_key(&k, 10).is_err(), "must reject {bad_sub}");
    }
}
