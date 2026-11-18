use super::*;

#[test]
fn global_unicast_is_2000_slash_3() {
    let g: Ipv6Addr = "2606:4700::1".parse().unwrap();
    let ula: Ipv6Addr = "fd00::1".parse().unwrap();
    let ll: Ipv6Addr = "fe80::1".parse().unwrap();
    assert!(is_global_unicast_v6(&g));
    assert!(!is_global_unicast_v6(&ula));
    assert!(!is_global_unicast_v6(&ll));
    assert!(!is_global_unicast_v6(&Ipv6Addr::UNSPECIFIED));
}

#[test]
fn utc_offset_parsing() {
    assert_eq!(parse_utc_offset("+0100\n"), Some(3600));
    assert_eq!(parse_utc_offset("-0330"), Some(-12600));
    assert_eq!(parse_utc_offset("+0000"), Some(0));
    assert_eq!(parse_utc_offset("CET"), None);
    assert_eq!(parse_utc_offset("+01"), None);
    assert_eq!(parse_utc_offset("+9900"), None);
}

#[test]
fn defaults_output_parsing() {
    assert_eq!(parse_defaults_values("ru_RU\n"), vec!["ru_RU"]);
    assert_eq!(
        parse_defaults_values("(\n    \"ru-RU\",\n    \"en-RU\"\n)\n"),
        vec!["ru-RU", "en-RU"]
    );
    assert!(parse_defaults_values("\n").is_empty());
}

#[test]
fn reg_output_parsing() {
    let one = "\nHKEY_CURRENT_USER\\Control Panel\\International\n    LocaleName    REG_SZ    ru-RU\n";
    assert_eq!(parse_reg_string_values(one), vec!["ru-RU"]);
    let many = "    Languages    REG_MULTI_SZ    ru-RU\\0en-US\n";
    assert_eq!(parse_reg_string_values(many), vec!["ru-RU", "en-US"]);
}

#[test]
fn zone_names_from_remote_services_are_validated() {
    assert!(is_plain_zone_name("Europe/Amsterdam"));
    assert!(is_plain_zone_name("America/Port-au-Prince"));
    assert!(is_plain_zone_name("Etc/GMT+3"));
    assert!(!is_plain_zone_name(""));
    assert!(!is_plain_zone_name("/etc/passwd"));
    assert!(!is_plain_zone_name("../../etc/passwd"));
    assert!(!is_plain_zone_name("Europe/Amsterdam; rm -rf"));
}

#[test]
fn not_found_is_told_apart_from_a_broken_resolver() {
    use std::io::Error;
    let nx = Error::other(
        "failed to lookup address information: nodename nor servname provided, or not known",
    );
    assert!(is_name_not_found(&nx));
    let glibc = Error::other("Name or service not known");
    assert!(is_name_not_found(&glibc));
    let broken = Error::other(
        "failed to lookup address information: Temporary failure in name resolution",
    );
    assert!(!is_name_not_found(&broken));
}

// The real probe against a loopback listener only (no traffic leaves this machine).
async fn loopback(response: Option<&'static str>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                match response {
                    Some(r) => {
                        let _ = sock.write_all(r.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    }
                    None => tokio::time::sleep(Duration::from_secs(30)).await,
                }
            });
        }
    });
    format!("http://{addr}/cdn-cgi/trace")
}

#[tokio::test]
async fn reqwest_probe_tells_timeout_from_refused_from_a_response() {
    let silent = loopback(None).await;
    assert_eq!(
        ReqwestProbe.get(&silent, Duration::from_millis(50)).await,
        HttpProbeOutcome::Timeout
    );
    let ok = loopback(Some("HTTP/1.1 200 OK\r\ncontent-length: 6\r\n\r\nloc=NL")).await;
    assert_eq!(
        ReqwestProbe.get(&ok, Duration::from_secs(2)).await,
        HttpProbeOutcome::Response {
            status: 200,
            body: "loc=NL".into()
        }
    );
    // A port nobody listens on.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/", l.local_addr().unwrap())
    };
    let refused = ReqwestProbe.get(&closed, Duration::from_secs(2)).await;
    if cfg!(windows) {
        // Windows retries a refused loopback connect for about two seconds, so the short
        // limit can expire first; either way the probe reports a failure, never a response.
        assert!(
            matches!(
                refused,
                HttpProbeOutcome::ConnectFailed | HttpProbeOutcome::Timeout
            ),
            "{refused:?}"
        );
    } else {
        assert_eq!(refused, HttpProbeOutcome::ConnectFailed);
    }
}

#[test]
fn usable_nameserver_filters_unspecified_multicast_link_local_and_fec0_placeholders() {
    use std::net::IpAddr;
    assert!(is_usable_nameserver(&"1.1.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_usable_nameserver(&"10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_usable_nameserver(
        &"2606:4700:4700::1111".parse::<IpAddr>().unwrap()
    ));
    assert!(!is_usable_nameserver(&"0.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(!is_usable_nameserver(&"::".parse::<IpAddr>().unwrap()));
    assert!(!is_usable_nameserver(
        &"224.0.0.251".parse::<IpAddr>().unwrap()
    ));
    assert!(!is_usable_nameserver(&"fe80::1".parse::<IpAddr>().unwrap()));
    assert!(!is_usable_nameserver(
        &"fec0:0:0:ffff::1".parse::<IpAddr>().unwrap()
    ));
    assert!(!is_usable_nameserver(
        &"fec0:0:0:ffff::2".parse::<IpAddr>().unwrap()
    ));
}

#[test]
fn parse_scutil_dns_prioritizes_reachable_default_resolvers_and_skips_domain_or_unreachable() {
    use std::net::IpAddr;
    let sample = "\
DNS configuration

resolver #1
  nameserver[0] : 10.8.0.1
  nameserver[1] : fec0:0:0:ffff::1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #2
  domain   : corp.local
  nameserver[0] : 10.99.0.1
  flags    : Request A records
  reach    : 0x00000002 (Reachable)

resolver #3
  nameserver[0] : 198.51.100.9
  flags    : Request A records
  reach    : 0x00000000 (Not Reachable)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
";
    let got = parse_scutil_dns_nameservers(sample);
    assert_eq!(got, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);

    let scoped_only = "\
DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.168.1.1
  if_index : 6 (en0)
  flags    : Scoped, Request A records
  reach    : 0x00000002 (Reachable)
";
    assert_eq!(
        parse_scutil_dns_nameservers(scoped_only),
        vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
    );
}
