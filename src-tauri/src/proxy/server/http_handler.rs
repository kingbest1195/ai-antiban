use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::auditor::geo_matrix::ProviderId;
use crate::proxy::http_forward::{
    MAX_HEAD_BYTES, ParsedRequest, RequestForm, find_head_end, parse_request, relay_exchange,
    split_authority,
};
use crate::proxy::pac::generate_pac_script;
use crate::proxy::upstream::connect_chained_tcp;

use super::responses::{
    KILLSWITCH_MESSAGE, is_absolute_http_target, is_peer_gone, killswitch_engaged,
    killswitch_stopped, send_bad_gateway, send_forbidden, send_gateway_info, send_status,
};
use super::ssrf::validate_tunnel_target;
use super::{
    CHAINED_CONNECT_TIMEOUT_SECS, FIRST_REQUEST_TIMEOUT_SECS, PLAIN_HTTP_IDLE_TIMEOUT_SECS,
    ProxyServer,
};

impl ProxyServer {
    /// Builds the live PAC script excluding domains of any disabled providers.
    pub async fn build_pac_script(&self) -> String {
        let matrix = self.auditor.rules.provider_matrix.read().await;
        let st = self.state.get_data().await;
        let domains = crate::proxy::pac::get_all_ai_domains_filtered(
            &matrix,
            &st.custom_ai_domains,
            &st.disabled_providers,
        );

        let gateway_port = self.bound_addr.port();
        let chained_proxy = crate::sysproxy::get_chained_proxy().filter(|cp| {
            let port = cp
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .unwrap_or(0);
            port != gateway_port && port != 0
        });

        generate_pac_script(
            &domains,
            &self.bound_addr.to_string(),
            chained_proxy.as_deref(),
        )
    }

    pub(super) async fn handle_pac_request(&self, client: &mut TcpStream) -> Result<(), std::io::Error> {
        let pac_script = self.build_pac_script().await;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            pac_script.len(),
            pac_script
        );

        client.write_all(response.as_bytes()).await?;
        client.flush().await?;
        Ok(())
    }

    /// True for `/proxy.pac` / `/pac.js` asked of the gateway: origin-form, or an absolute URI whose
    /// authority is the gateway.
    pub(super) fn is_pac_target(&self, target: &str) -> bool {
        let path = if is_absolute_http_target(target) {
            let rest = &target[7..];
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, ""),
            };
            if !self.is_gateway_authority(authority) {
                return false;
            }
            path
        } else {
            target
        };
        path.starts_with("/proxy.pac")
            || path.contains("/proxy.pac")
            || path.starts_with("/pac.js")
            || path.contains("/pac.js")
    }

    /// True when `authority` (`host[:port]`) addresses this gateway (loopback name / address with
    /// the bound port).
    fn is_gateway_authority(&self, authority: &str) -> bool {
        let Some((host, port)) = split_authority(authority) else {
            return false;
        };
        if port.unwrap_or(80) != self.bound_addr.port() {
            return false;
        }
        host == "localhost"
            || host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip == self.bound_addr.ip())
    }

    /// Plain HTTP forwarding (`GET http://host/path`, POST, HEAD, ...) for public non-AI hosts.
    /// Hosts of AI services are never forwarded this way: they work over HTTPS and must pass the
    /// gateway's policy (audit, route, gate). Requests addressed to the gateway itself are not
    /// forwarded (loop) and get the info page.
    pub(super) async fn handle_plain_http(
        &self,
        client: &mut TcpStream,
        first: &[u8],
        _peer_port: u16,
    ) -> Result<(), std::io::Error> {
        let mut buf = first.to_vec();
        let head_end = loop {
            if let Some(n) = find_head_end(&buf) {
                break n;
            }
            if buf.len() >= MAX_HEAD_BYTES {
                return send_status(
                    client,
                    "431 Request Header Fields Too Large",
                    "Request head is too large.",
                )
                .await;
            }
            let mut chunk = [0u8; 4096];
            let n = match tokio::time::timeout(
                Duration::from_secs(FIRST_REQUEST_TIMEOUT_SECS),
                client.read(&mut chunk),
            )
            .await
            {
                Ok(res) => res?,
                Err(_) => return Ok(()),
            };
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };

        let req = match parse_request(&buf[..head_end]) {
            Ok(r) => r,
            Err(e) => {
                let status = match e {
                    crate::proxy::http_forward::HeadError::Malformed(_) => "400 Bad Request",
                    crate::proxy::http_forward::HeadError::Unsupported(_) => "501 Not Implemented",
                };
                return send_status(client, status, e.message()).await;
            }
        };
        let (host, port) = (req.host.clone(), req.port);

        // A request for the gateway's own address: the info page, never a forward (no loop).
        let own_authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        if self.is_gateway_authority(&own_authority) {
            return send_gateway_info(client).await;
        }

        // Same policy as a CONNECT to this host: port, internal names, loopback / private IPs.
        // The port list (80 / 443 / 8443) is deliberately not widened for plain HTTP: the gateway
        // must not become a port scanner or a bridge to arbitrary local-style services.
        if let Err(reason) = validate_tunnel_target(&host, port, self.bound_addr.port()) {
            return send_forbidden(client, reason).await;
        }

        let custom_domains = self.state.get_custom_ai_domains().await;
        if let Some(provider) = ProviderId::from_host_with_custom(&host, &custom_domains)
            && !self.state.is_provider_disabled(provider.as_str()).await
        {
            self.state
                .stats()
                .record_intercepted(&host, provider.as_str(), "BLOCKED", "??");
            return send_forbidden(
                client,
                "AI services are reachable over HTTPS only: Zastava does not forward plain HTTP requests to them.",
            )
            .await;
        }

        self.state.stats().record_direct_bypassed_host(&host);
        self.forward_plain_http(client, &req, &buf[head_end..])
            .await
    }

    /// Connects to the chained proxy and sends the absolute-form request head. `None` when there
    /// is no chained proxy or it cannot be reached (the caller then goes direct, once).
    async fn open_chained_plain(&self, req: &ParsedRequest) -> Option<TcpStream> {
        if self.upstream_redirect.is_some() {
            return None;
        }
        let gateway_port = self.bound_addr.port();
        let cp = self.transit.chained_proxy(gateway_port)?;
        let mut s = connect_chained_tcp(
            &cp,
            Duration::from_secs(CHAINED_CONNECT_TIMEOUT_SECS),
            gateway_port,
        )
        .await
        .ok()?;
        s.write_all(&req.build_head(RequestForm::Absolute))
            .await
            .ok()?;
        Some(s)
    }

    async fn forward_plain_http(
        &self,
        client: &mut TcpStream,
        req: &ParsedRequest,
        body_prefix: &[u8],
    ) -> Result<(), std::io::Error> {
        // The manual kill-switch ("СТОП СЕТИ") stops everything that goes through Zastava.
        let mut kill_rx = self.guard.subscribe_killswitch();
        if *kill_rx.borrow_and_update() {
            return send_status(client, "503 Service Unavailable", KILLSWITCH_MESSAGE).await;
        }

        // Through the chained proxy first (absolute-form, the proxy does the rest). Only a failure
        // to connect / send the head counts as "unreachable": the answer of the proxy is final.
        let chained_stream = self.open_chained_plain(req).await;

        let mut upstream = match chained_stream {
            Some(s) => s,
            None => {
                let connected = if let Some(redirect_addr) = self.upstream_redirect {
                    self.direct_connects.fetch_add(1, Ordering::SeqCst);
                    TcpStream::connect(redirect_addr).await
                } else {
                    self.connect_direct(&req.host, req.port).await
                };
                let mut s = match connected {
                    Ok(s) => s,
                    Err(e) => {
                        let msg =
                            format!("Failed to connect to target {}:{}: {e}", req.host, req.port);
                        send_bad_gateway(client, &msg).await?;
                        return Err(e);
                    }
                };
                if let Err(e) = s.write_all(&req.build_head(RequestForm::Origin)).await {
                    send_bad_gateway(client, "Failed to send the request to the target.").await?;
                    return Err(e);
                }
                s
            }
        };

        // Transit traffic is not tied to the gate: a network re-check never cuts a transfer.
        // Only the manual kill-switch cuts it (and the idle timeout).
        let relay = relay_exchange(
            client,
            &mut upstream,
            &req.body,
            body_prefix,
            Duration::from_secs(PLAIN_HTTP_IDLE_TIMEOUT_SECS),
        );
        let res = tokio::select! {
            res = relay => res,
            _ = killswitch_engaged(&mut kill_rx) => Err(killswitch_stopped()),
        };
        match res {
            Err(e) if is_peer_gone(&e) => Ok(()),
            other => other,
        }
    }
}
