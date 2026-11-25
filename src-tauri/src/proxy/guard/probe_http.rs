//! Egress IP HTTP probes with concurrent race and structured diagnostics.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::diag;
use super::types::{Env, NetworkGuard};

const CF_TRACE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const IPIFY_URL: &str = "https://api.ipify.org";

pub(super) fn build_probe_client(
    proxy: Option<reqwest::Proxy>,
) -> Result<reqwest::Client, reqwest::Error> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(2500))
        .timeout(Duration::from_millis(4000))
        .tcp_nodelay(true)
        .pool_max_idle_per_host(0)
        .user_agent(crate::auditor::network::NEUTRAL_USER_AGENT);
    if let Some(p) = proxy {
        builder = builder.proxy(p);
    }
    builder.build()
}

async fn probe_cf_trace(client: &reqwest::Client, url: &str) -> Option<String> {
    let t0 = Instant::now();
    match client.get(url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                for line in text.lines() {
                    if let Some(val) = line.strip_prefix("ip=") {
                        let val = val.trim();
                        if val.parse::<IpAddr>().is_ok() {
                            return Some(val.to_string());
                        }
                    }
                }
                diag::record_probe_failure(
                    "1.1.1.1",
                    "invalid trace body",
                    t0.elapsed().as_millis(),
                    0,
                );
                None
            }
            Err(err) => {
                diag::record_probe_failure(
                    "1.1.1.1",
                    &err.to_string(),
                    t0.elapsed().as_millis(),
                    0,
                );
                None
            }
        },
        Err(err) => {
            diag::record_probe_failure("1.1.1.1", &err.to_string(), t0.elapsed().as_millis(), 0);
            None
        }
    }
}

async fn probe_ipify(client: &reqwest::Client, url: &str) -> Option<String> {
    let t0 = Instant::now();
    match client.get(url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(text) => {
                let val = text.trim();
                if val.parse::<IpAddr>().is_ok() {
                    return Some(val.to_string());
                }
                diag::record_probe_failure(
                    "api.ipify.org",
                    "invalid ipify body",
                    t0.elapsed().as_millis(),
                    0,
                );
                None
            }
            Err(err) => {
                diag::record_probe_failure(
                    "api.ipify.org",
                    &err.to_string(),
                    t0.elapsed().as_millis(),
                    0,
                );
                None
            }
        },
        Err(err) => {
            diag::record_probe_failure(
                "api.ipify.org",
                &err.to_string(),
                t0.elapsed().as_millis(),
                0,
            );
            None
        }
    }
}

pub(super) async fn probe_ip_urls(
    client: &reqwest::Client,
    trace_url: &str,
    ipify_url: &str,
) -> Option<String> {
    let mut cf_fut = std::pin::pin!(probe_cf_trace(client, trace_url));
    let mut ipify_fut = std::pin::pin!(probe_ipify(client, ipify_url));
    tokio::select! {
        res = &mut cf_fut => match res {
            Some(ip) => Some(ip),
            None => ipify_fut.await,
        },
        res = &mut ipify_fut => match res {
            Some(ip) => Some(ip),
            None => cf_fut.await,
        },
    }
}

impl NetworkGuard {
    /// Fetches the current egress IP by racing Cloudflare trace and ipify concurrently,
    /// honoring an active external `chained_proxy` when configured (caching its `reqwest::Client`).
    pub(super) async fn probe_ip(&self) -> Option<String> {
        let proxied = match crate::sysproxy::get_chained_proxy() {
            Some(cp) => {
                let cached = {
                    let cache = self
                        .chained_client
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    cache
                        .as_ref()
                        .filter(|(cached_cp, _)| *cached_cp == cp)
                        .map(|(_, client)| client.clone())
                };
                if let Some(client) = cached {
                    Some(client)
                } else {
                    reqwest::Proxy::all(&cp).ok().and_then(|proxy| {
                        let client = build_probe_client(Some(proxy)).ok()?;
                        let mut cache = self
                            .chained_client
                            .lock()
                            .unwrap_or_else(|p| p.into_inner());
                        *cache = Some((cp, client.clone()));
                        Some(client)
                    })
                }
            }
            None => {
                let mut cache = self
                    .chained_client
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                *cache = None;
                None
            }
        };
        let client = proxied.as_ref().unwrap_or(&self.client);
        probe_ip_urls(client, CF_TRACE_URL, IPIFY_URL).await
    }

    pub(super) async fn probe(&self, env: &Env) -> Option<String> {
        match &env.probe {
            Some(probe) => probe().await,
            None => self.probe_ip().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn concurrent_probe_races_trace_and_ipify_without_sequential_stall() {
        // Slow CF trace (500ms) + fast ipify (instant) -> resolves in <250ms.
        let slow_cf = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_cf_addr = slow_cf.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = slow_cf.accept().await {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nip=1.1.1.1\n")
                    .await;
            }
        });

        let fast_ipify = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fast_ipify_addr = fast_ipify.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = fast_ipify.accept().await {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n203.0.113.42\n")
                    .await;
            }
        });

        let client = build_probe_client(None).unwrap();
        let t0 = Instant::now();
        let ip = probe_ip_urls(
            &client,
            &format!("http://{slow_cf_addr}/cdn-cgi/trace"),
            &format!("http://{fast_ipify_addr}/"),
        )
        .await;
        assert_eq!(ip.as_deref(), Some("203.0.113.42"));
        assert!(t0.elapsed() < Duration::from_millis(300));

        // Fast failing CF trace + slower valid ipify -> still awaits ipify!
        let fail_cf = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fail_cf_addr = fail_cf.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = fail_cf.accept().await {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });
        let slow_ipify = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_ipify_addr = slow_ipify.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = slow_ipify.accept().await {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(40)).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n198.51.100.7\n")
                    .await;
            }
        });

        let ip2 = probe_ip_urls(
            &client,
            &format!("http://{fail_cf_addr}/cdn-cgi/trace"),
            &format!("http://{slow_ipify_addr}/"),
        )
        .await;
        assert_eq!(ip2.as_deref(), Some("198.51.100.7"));
    }
}
