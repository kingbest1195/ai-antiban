//! Direct HTTP GET probe trait and reqwest implementation.

use std::time::Duration;

use super::BoxFuture;

/// Raw outcome of one HTTP GET probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpProbeOutcome {
    Response {
        status: u16,
        body: String,
    },
    Timeout,
    /// The connection could not be established (no route, refused, TLS failure...).
    ConnectFailed,
    /// The connection worked, but the body could not be read.
    ReadFailed,
    /// The HTTP client could not be built.
    ClientError,
}

/// Performs a plain GET from the host's own network stack (used for the IPv6 leak probe).
pub trait IpProbe: Send + Sync {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome>;
}

/// `reqwest` without any proxy: the probe must show what the OS network stack does, not what an
/// `HTTPS_PROXY` of this process would do.
pub struct ReqwestProbe;

/// [`IpProbe`] backed by a pre-built `reqwest::Client` (e.g. routed through a Zastava key exit).
pub struct ClientIpProbe(pub reqwest::Client);

async fn fetch_with_client(
    client: &reqwest::Client,
    url: &str,
    limit: Duration,
) -> HttpProbeOutcome {
    let resp = match client.get(url).timeout(limit).send().await {
        Ok(r) => r,
        Err(e) if e.is_timeout() => return HttpProbeOutcome::Timeout,
        Err(_) => return HttpProbeOutcome::ConnectFailed,
    };
    let status = resp.status().as_u16();
    match resp.text().await {
        Ok(body) => HttpProbeOutcome::Response { status, body },
        Err(e) if e.is_timeout() => HttpProbeOutcome::Timeout,
        Err(_) => HttpProbeOutcome::ReadFailed,
    }
}

impl IpProbe for ReqwestProbe {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        Box::pin(async move {
            let Ok(client) = reqwest::Client::builder().timeout(limit).no_proxy().build() else {
                return HttpProbeOutcome::ClientError;
            };
            fetch_with_client(&client, url, limit).await
        })
    }
}

impl IpProbe for ClientIpProbe {
    fn get<'a>(&'a self, url: &'a str, limit: Duration) -> BoxFuture<'a, HttpProbeOutcome> {
        let client = self.0.clone();
        Box::pin(async move { fetch_with_client(&client, url, limit).await })
    }
}
