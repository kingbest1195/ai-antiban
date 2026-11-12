//! Plain HTTP forwarding for transit (non-AI) traffic: absolute-form request parsing, hop-by-hop
//! header removal, request-line rewriting and the body / response relay.
//!
//! The upstream connection is never reused (`Connection: close`), so there is no keep-alive pool
//! and no response parsing: the response is streamed back as is until the upstream closes.

use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

/// Largest accepted request head (request line + headers).
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest accepted chunk-size line / trailer section.
const MAX_CHUNK_LINE: usize = 4096;
const MAX_TRAILER_BYTES: usize = 16 * 1024;

/// Headers that describe a single connection and are never forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    // Re-added from the parsed framing, so a client cannot smuggle a different one.
    "transfer-encoding",
    "content-length",
    "host",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyKind {
    None,
    Length(u64),
    Chunked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadError {
    /// 400
    Malformed(&'static str),
    /// 501: valid HTTP that the gateway does not forward.
    Unsupported(&'static str),
}

impl HeadError {
    pub fn message(&self) -> &'static str {
        match self {
            HeadError::Malformed(m) | HeadError::Unsupported(m) => m,
        }
    }
}

/// A parsed `GET http://host[:port]/path HTTP/1.x` request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    pub method: String,
    /// Lower-case host without the trailing dot and without IPv6 brackets.
    pub host: String,
    pub port: u16,
    /// `/path?query` as the client sent it (no normalization), `/` when empty.
    pub path: String,
    /// Headers worth forwarding (hop-by-hop, framing and `Host` removed).
    pub headers: Vec<(String, String)>,
    pub body: BodyKind,
}

/// Position right after the blank line that ends the head.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Splits an authority (`[userinfo@]host[:port]`) into a lower-case host (brackets and trailing dot
/// removed) and an optional port. `None` when it is not a valid authority.
pub fn split_authority(authority: &str) -> Option<(String, Option<u16>)> {
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if hostport.is_empty() {
        return None;
    }
    let (host, port_str) = if let Some(rest) = hostport.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            a => Some(a.strip_prefix(':')?),
        };
        (h, port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            Some(_) => return None, // unbracketed IPv6
            None => (hostport, None),
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':'))
    {
        return None;
    }
    let port = match port_str {
        None => None,
        Some(p) => match p.parse::<u16>() {
            Ok(0) | Err(_) => return None,
            Ok(n) => Some(n),
        },
    };
    Some((host, port))
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parses the request head (the bytes up to and including the blank line).
pub fn parse_request(head: &[u8]) -> Result<ParsedRequest, HeadError> {
    if !head.ends_with(b"\r\n\r\n") {
        return Err(HeadError::Malformed("request head is not terminated"));
    }
    let text = std::str::from_utf8(head)
        .map_err(|_| HeadError::Malformed("request head is not valid text"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if parts.next().is_some() || !is_token(method) || target.is_empty() {
        return Err(HeadError::Malformed("malformed request line"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(HeadError::Unsupported(
            "only HTTP/1.0 and HTTP/1.1 are supported",
        ));
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err(HeadError::Malformed("CONNECT is not a plain HTTP request"));
    }

    let rest = match target.get(..7) {
        Some(p) if p.eq_ignore_ascii_case("http://") => &target[7..],
        _ => {
            return Err(HeadError::Malformed(
                "the proxy request needs an absolute http:// URI",
            ));
        }
    };
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) =
        split_authority(authority).ok_or(HeadError::Malformed("invalid target authority"))?;
    let path = match path {
        "" => "/".to_string(),
        p if p.starts_with('?') => format!("/{p}"),
        p => p.to_string(),
    };
    // The fragment never goes on the wire.
    let path = path.split('#').next().unwrap_or("/").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut connection_tokens: Vec<String> = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut transfer_encoding: Option<String> = None;
    let mut seen_end = false;
    for line in lines {
        if line.is_empty() {
            seen_end = true;
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HeadError::Malformed(
                "obsolete header folding is not accepted",
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HeadError::Malformed("malformed header line"))?;
        if !is_token(name) {
            return Err(HeadError::Malformed("invalid header name"));
        }
        if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return Err(HeadError::Malformed("invalid header value"));
        }
        let value = value.trim_matches([' ', '\t']);
        let lname = name.to_ascii_lowercase();
        match lname.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(HeadError::Malformed("invalid Content-Length"));
                }
                let n: u64 = value
                    .parse()
                    .map_err(|_| HeadError::Malformed("invalid Content-Length"))?;
                if content_length.is_some_and(|prev| prev != n) {
                    return Err(HeadError::Malformed("conflicting Content-Length headers"));
                }
                content_length = Some(n);
            }
            "transfer-encoding" => {
                if transfer_encoding.is_some() {
                    return Err(HeadError::Malformed("repeated Transfer-Encoding"));
                }
                transfer_encoding = Some(value.to_ascii_lowercase());
            }
            "connection" => {
                connection_tokens.extend(
                    value
                        .split(',')
                        .map(|t| t.trim().to_ascii_lowercase())
                        .filter(|t| !t.is_empty()),
                );
            }
            _ => {}
        }
        if !HOP_BY_HOP.contains(&lname.as_str()) {
            headers.push((name.to_string(), value.to_string()));
        }
    }
    if !seen_end {
        return Err(HeadError::Malformed("request head is not terminated"));
    }
    // Headers named by `Connection` are hop-by-hop too.
    headers.retain(|(n, _)| !connection_tokens.contains(&n.to_ascii_lowercase()));

    let body = match (transfer_encoding.as_deref(), content_length) {
        (Some(_), Some(_)) => {
            return Err(HeadError::Malformed(
                "Transfer-Encoding together with Content-Length is refused",
            ));
        }
        (Some("chunked"), None) => BodyKind::Chunked,
        (Some(_), None) => {
            return Err(HeadError::Unsupported(
                "only the chunked transfer coding is supported",
            ));
        }
        (None, Some(n)) if n > 0 => BodyKind::Length(n),
        (None, _) => BodyKind::None,
    };

    Ok(ParsedRequest {
        method: method.to_string(),
        host,
        port: port.unwrap_or(80),
        path,
        headers,
        body,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestForm {
    /// `GET /path HTTP/1.1` for an origin server.
    Origin,
    /// `GET http://host/path HTTP/1.1` for a chained HTTP proxy.
    Absolute,
}

impl ParsedRequest {
    /// `Host` value: the default port is omitted, IPv6 literals are bracketed.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The request head as it is sent upstream: new request line and `Host`, no hop-by-hop
    /// headers, the framing re-added, `Connection: close`.
    pub fn build_head(&self, form: RequestForm) -> Vec<u8> {
        let host = self.host_header();
        let target = match form {
            RequestForm::Origin => self.path.clone(),
            RequestForm::Absolute => format!("http://{host}{}", self.path),
        };
        let mut out = format!("{} {target} HTTP/1.1\r\nHost: {host}\r\n", self.method);
        for (n, v) in &self.headers {
            out.push_str(n);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
        match self.body {
            BodyKind::Chunked => out.push_str("Transfer-Encoding: chunked\r\n"),
            BodyKind::Length(n) => out.push_str(&format!("Content-Length: {n}\r\n")),
            BodyKind::None => {}
        }
        out.push_str("Connection: close\r\n\r\n");
        out.into_bytes()
    }
}

/// Tracks the framing of a chunked body so the relay knows where the message ends without
/// re-encoding anything.
#[derive(Debug)]
pub struct ChunkedTracker {
    state: ChunkState,
}

#[derive(Debug, Clone, Copy)]
enum ChunkState {
    /// Reading the hex size (and extensions) of a chunk.
    Size {
        value: u64,
        digits: u8,
        in_ext: bool,
        line: usize,
    },
    Data {
        remaining: u64,
    },
    /// After the chunk data: `CRLF`.
    DataEnd {
        saw_cr: bool,
    },
    /// Trailer section: lines until an empty one.
    Trailer {
        line: usize,
        total: usize,
    },
    Done,
}

impl Default for ChunkedTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkedTracker {
    pub fn new() -> Self {
        Self {
            state: ChunkState::Size {
                value: 0,
                digits: 0,
                in_ext: false,
                line: 0,
            },
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, ChunkState::Done)
    }

    /// Consumes `data`. `Ok(Some(n))`: the message ended after the first `n` bytes; `Ok(None)`: all
    /// of `data` belongs to the message, more is needed; `Err`: the framing is broken.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<usize>, &'static str> {
        let mut i = 0;
        while i < data.len() {
            match self.state {
                ChunkState::Done => return Ok(Some(i)),
                ChunkState::Data { remaining } => {
                    let take = remaining.min((data.len() - i) as u64) as usize;
                    i += take;
                    let left = remaining - take as u64;
                    self.state = if left == 0 {
                        ChunkState::DataEnd { saw_cr: false }
                    } else {
                        ChunkState::Data { remaining: left }
                    };
                }
                ChunkState::DataEnd { saw_cr } => {
                    let b = data[i];
                    i += 1;
                    match (saw_cr, b) {
                        (false, b'\r') => self.state = ChunkState::DataEnd { saw_cr: true },
                        (_, b'\n') => {
                            self.state = ChunkState::Size {
                                value: 0,
                                digits: 0,
                                in_ext: false,
                                line: 0,
                            };
                        }
                        _ => return Err("chunk data is not followed by CRLF"),
                    }
                }
                ChunkState::Size {
                    value,
                    digits,
                    in_ext,
                    line,
                } => {
                    let b = data[i];
                    i += 1;
                    if line >= MAX_CHUNK_LINE {
                        return Err("chunk size line is too long");
                    }
                    let line = line + 1;
                    self.state = match b {
                        b'\n' => {
                            if digits == 0 {
                                return Err("empty chunk size");
                            }
                            if value == 0 {
                                ChunkState::Trailer { line: 0, total: 0 }
                            } else {
                                ChunkState::Data { remaining: value }
                            }
                        }
                        b'\r' => ChunkState::Size {
                            value,
                            digits,
                            in_ext,
                            line,
                        },
                        b';' | b' ' | b'\t' => ChunkState::Size {
                            value,
                            digits,
                            in_ext: true,
                            line,
                        },
                        _ if in_ext => ChunkState::Size {
                            value,
                            digits,
                            in_ext,
                            line,
                        },
                        _ => {
                            let d = (b as char).to_digit(16).ok_or("invalid chunk size")?;
                            if digits >= 15 {
                                return Err("chunk size is too large");
                            }
                            ChunkState::Size {
                                value: value * 16 + u64::from(d),
                                digits: digits + 1,
                                in_ext,
                                line,
                            }
                        }
                    };
                }
                ChunkState::Trailer { line, total } => {
                    let b = data[i];
                    i += 1;
                    let total = total + 1;
                    if total > MAX_TRAILER_BYTES {
                        return Err("chunked trailer is too large");
                    }
                    self.state = match b {
                        b'\n' if line == 0 => ChunkState::Done,
                        b'\n' => ChunkState::Trailer { line: 0, total },
                        b'\r' => ChunkState::Trailer { line, total },
                        _ => ChunkState::Trailer {
                            line: line + 1,
                            total,
                        },
                    };
                    if self.is_done() {
                        return Ok(Some(i));
                    }
                }
            }
        }
        Ok(if self.is_done() { Some(i) } else { None })
    }
}

fn unexpected_eof(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, what)
}

/// Copies the request body from the client to the upstream. `prefix` holds body bytes that were
/// already read together with the head.
pub async fn relay_request_body<R, W>(
    kind: &BodyKind,
    prefix: &[u8],
    from_client: &mut R,
    to_upstream: &mut W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match kind {
        BodyKind::None => {}
        BodyKind::Length(total) => {
            let have = (prefix.len() as u64).min(*total) as usize;
            to_upstream.write_all(&prefix[..have]).await?;
            let mut remaining = *total - have as u64;
            let mut buf = vec![0u8; 16 * 1024];
            while remaining > 0 {
                let want = remaining.min(buf.len() as u64) as usize;
                let n = from_client.read(&mut buf[..want]).await?;
                if n == 0 {
                    return Err(unexpected_eof(
                        "client closed before the request body was complete",
                    ));
                }
                to_upstream.write_all(&buf[..n]).await?;
                to_upstream.flush().await?;
                remaining -= n as u64;
            }
        }
        BodyKind::Chunked => {
            let mut tracker = ChunkedTracker::new();
            let bad = |m: &'static str| io::Error::new(io::ErrorKind::InvalidData, m);
            if !prefix.is_empty() {
                match tracker.feed(prefix).map_err(bad)? {
                    Some(n) => {
                        to_upstream.write_all(&prefix[..n]).await?;
                        return to_upstream.flush().await;
                    }
                    None => to_upstream.write_all(prefix).await?,
                }
            }
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = from_client.read(&mut buf).await?;
                if n == 0 {
                    return Err(unexpected_eof(
                        "client closed before the chunked body was complete",
                    ));
                }
                match tracker.feed(&buf[..n]).map_err(bad)? {
                    Some(end) => {
                        to_upstream.write_all(&buf[..end]).await?;
                        return to_upstream.flush().await;
                    }
                    None => {
                        to_upstream.write_all(&buf[..n]).await?;
                        to_upstream.flush().await?;
                    }
                }
            }
        }
    }
    to_upstream.flush().await
}

/// An `AsyncRead` that records the time of every successful read.
struct Touch<'a, R> {
    inner: R,
    last: &'a Mutex<Instant>,
}

impl<R: AsyncRead + Unpin> AsyncRead for Touch<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            *self.last.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
        }
        res
    }
}

/// Runs one request/response exchange on an already connected upstream whose request head has been
/// written: the body goes client -> upstream while the response is streamed upstream -> client
/// until the upstream closes. A response that arrives before the body is finished (an early 4xx)
/// ends the exchange. The exchange is abandoned (`TimedOut`) when no byte has arrived from either
/// side for `idle`, so a client is never left hanging on an upstream that neither answers nor closes.
pub async fn relay_exchange<C, U>(
    client: &mut C,
    upstream: &mut U,
    kind: &BodyKind,
    prefix: &[u8],
    idle: Duration,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let last = Mutex::new(Instant::now());
    let seen = || *last.lock().unwrap_or_else(|p| p.into_inner());
    let (cr, mut cw) = tokio::io::split(client);
    let (ur, mut uw) = tokio::io::split(upstream);
    let mut cr = Touch {
        inner: cr,
        last: &last,
    };
    let mut ur = Touch {
        inner: ur,
        last: &last,
    };

    let request = async {
        match relay_request_body(kind, prefix, &mut cr, &mut uw).await {
            Ok(()) => std::future::pending::<io::Result<()>>().await,
            Err(e) => Err(e),
        }
    };
    let response = async {
        tokio::io::copy(&mut ur, &mut cw).await?;
        let _ = cw.shutdown().await;
        Ok::<(), io::Error>(())
    };
    let watchdog = async {
        loop {
            let deadline = seen() + idle;
            tokio::time::sleep_until(deadline).await;
            if seen() + idle <= Instant::now() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "plain HTTP exchange idle timeout",
                ));
            }
        }
    };
    tokio::select! {
        res = response => res,
        res = request => res,
        res = watchdog => res,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn parses_absolute_get_and_rewrites_to_origin_form() {
        let raw = "GET http://Example.ORG:8080/a/b?x=1&y=%20 HTTP/1.1\r\nHost: wrong.example\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n";
        let r = parse_request(raw.as_bytes()).unwrap();
        assert_eq!((r.host.as_str(), r.port), ("example.org", 8080));
        assert_eq!(r.path, "/a/b?x=1&y=%20");
        assert_eq!(r.body, BodyKind::None);
        let out = String::from_utf8(r.build_head(RequestForm::Origin)).unwrap();
        assert!(
            out.starts_with("GET /a/b?x=1&y=%20 HTTP/1.1\r\nHost: example.org:8080\r\n"),
            "{out}"
        );
        assert!(out.contains("User-Agent: curl/8\r\n"));
        assert!(!out.contains("wrong.example"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn default_port_is_left_out_of_host_and_path_defaults_to_slash() {
        let r = parse_request(&head("GET http://example.org HTTP/1.1\r\n\r\n")).unwrap();
        assert_eq!(r.port, 80);
        assert_eq!(r.path, "/");
        assert_eq!(r.host_header(), "example.org");
        let r = parse_request(&head("GET http://example.org?q=1 HTTP/1.1\r\n\r\n")).unwrap();
        assert_eq!(r.path, "/?q=1");
        let r = parse_request(&head("GET http://[2606:2800::1]:80/x HTTP/1.1\r\n\r\n")).unwrap();
        assert_eq!(r.host, "2606:2800::1");
        assert_eq!(r.host_header(), "[2606:2800::1]");
    }

    #[test]
    fn userinfo_and_fragment_are_dropped_and_trailing_dot_normalized() {
        let r = parse_request(&head(
            "GET http://user:pw@Example.org./p#frag HTTP/1.1\r\n\r\n",
        ))
        .unwrap();
        assert_eq!(r.host, "example.org");
        assert_eq!(r.path, "/p");
        let out = String::from_utf8(r.build_head(RequestForm::Origin)).unwrap();
        assert!(!out.contains("pw") && !out.contains("frag"));
    }

    #[test]
    fn hop_by_hop_headers_and_connection_tokens_are_removed() {
        let raw = "GET http://example.org/ HTTP/1.1\r\n\
Host: example.org\r\n\
Connection: keep-alive, X-Secret-Hop\r\n\
Proxy-Connection: keep-alive\r\n\
Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\
Keep-Alive: timeout=5\r\n\
TE: trailers\r\n\
Trailer: X-Foo\r\n\
Upgrade: websocket\r\n\
X-Secret-Hop: 1\r\n\
X-Keep: yes\r\n\
\r\n";
        let r = parse_request(raw.as_bytes()).unwrap();
        let out = String::from_utf8(r.build_head(RequestForm::Origin))
            .unwrap()
            .to_ascii_lowercase();
        for gone in [
            "keep-alive",
            "proxy-connection",
            "proxy-authorization",
            "te:",
            "trailer:",
            "upgrade",
            "x-secret-hop",
            "zm9v",
        ] {
            assert!(!out.contains(gone), "{gone} leaked: {out}");
        }
        assert!(out.contains("x-keep: yes"));
        assert_eq!(out.matches("connection:").count(), 1);
        assert!(out.contains("connection: close"));
    }

    #[test]
    fn framing_is_determined_and_reemitted() {
        let r = parse_request(&head(
            "POST http://example.org/u HTTP/1.1\r\nContent-Length:  12 \r\n\r\n",
        ))
        .unwrap();
        assert_eq!(r.body, BodyKind::Length(12));
        assert!(
            String::from_utf8(r.build_head(RequestForm::Origin))
                .unwrap()
                .contains("Content-Length: 12\r\n")
        );

        let r = parse_request(&head(
            "POST http://example.org/u HTTP/1.1\r\nTransfer-Encoding: Chunked\r\n\r\n",
        ))
        .unwrap();
        assert_eq!(r.body, BodyKind::Chunked);
        assert!(
            String::from_utf8(r.build_head(RequestForm::Origin))
                .unwrap()
                .contains("Transfer-Encoding: chunked\r\n")
        );

        let r = parse_request(&head(
            "POST http://example.org/u HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ))
        .unwrap();
        assert_eq!(r.body, BodyKind::None);
    }

    #[test]
    fn absolute_form_for_chained_proxy_keeps_the_full_uri() {
        let r = parse_request(&head("GET http://example.org:8080/p?q=1 HTTP/1.1\r\n\r\n")).unwrap();
        let out = String::from_utf8(r.build_head(RequestForm::Absolute)).unwrap();
        assert!(out.starts_with(
            "GET http://example.org:8080/p?q=1 HTTP/1.1\r\nHost: example.org:8080\r\n"
        ));
    }

    #[test]
    fn smuggling_shapes_and_garbage_are_refused() {
        let bad = [
            "POST http://e.org/ HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST http://e.org/ HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
            "POST http://e.org/ HTTP/1.1\r\nContent-Length: +3\r\n\r\n",
            "POST http://e.org/ HTTP/1.1\r\nContent-Length: 3, 3\r\n\r\n",
            "GET http://e.org/ HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n",
            "GET http://e.org/ HTTP/1.1\r\nBad Name: 1\r\n\r\n",
            "GET http://e.org/ HTTP/1.1\r\nHost : e.org\r\n\r\n",
            "GET ftp://e.org/ HTTP/1.1\r\n\r\n",
            "GET /relative HTTP/1.1\r\n\r\n",
            "GET http://e.org:0/ HTTP/1.1\r\n\r\n",
            "GET http://e.org:99999/ HTTP/1.1\r\n\r\n",
            "GET http:///path HTTP/1.1\r\n\r\n",
            "GET http://::1/ HTTP/1.1\r\n\r\n",
            "GET http://e.org/ HTTP/1.1 extra\r\n\r\n",
            "CONNECT http://e.org/ HTTP/1.1\r\n\r\n",
            "GET http://e.org/ HTTP/1.1\r\nX: a\r\n",
        ];
        for raw in bad {
            assert!(parse_request(raw.as_bytes()).is_err(), "accepted: {raw:?}");
        }
        assert!(matches!(
            parse_request(&head("GET http://e.org/ HTTP/2.0\r\n\r\n")),
            Err(HeadError::Unsupported(_))
        ));
        assert!(matches!(
            parse_request(&head(
                "POST http://e.org/ HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
            )),
            Err(HeadError::Unsupported(_))
        ));
    }

    #[test]
    fn head_end_is_found() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nbody"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn authority_splitting() {
        assert_eq!(split_authority("a.b"), Some(("a.b".into(), None)));
        assert_eq!(split_authority("a.b:81"), Some(("a.b".into(), Some(81))));
        assert_eq!(
            split_authority("[::1]:8899"),
            Some(("::1".into(), Some(8899)))
        );
        assert_eq!(split_authority("u@A.B."), Some(("a.b".into(), None)));
        assert_eq!(split_authority(""), None);
        assert_eq!(split_authority("a b"), None);
    }

    #[test]
    fn chunked_tracker_finds_the_end_and_ignores_what_follows() {
        let msg = b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-T: v\r\n\r\nGET /next";
        let mut t = ChunkedTracker::new();
        let end = t.feed(msg).unwrap().unwrap();
        assert_eq!(&msg[end..], b"GET /next");
        assert!(t.is_done());
    }

    #[test]
    fn chunked_tracker_works_byte_by_byte() {
        let msg = b"A\r\n0123456789\r\n1\r\nx\r\n0\r\n\r\n";
        let mut t = ChunkedTracker::new();
        for (i, b) in msg.iter().enumerate() {
            let r = t.feed(std::slice::from_ref(b)).unwrap();
            if i + 1 == msg.len() {
                assert_eq!(r, Some(1));
            } else {
                assert_eq!(r, None, "ended early at {i}");
            }
        }
    }

    #[test]
    fn chunked_tracker_rejects_broken_framing() {
        for bad in [
            &b"zz\r\n"[..],
            b"\r\n",
            b"3\r\nabcXX",
            b"fffffffffffffffff\r\n",
        ] {
            assert!(ChunkedTracker::new().feed(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn content_length_body_is_copied_exactly_with_prefix() {
        let (mut client_side, mut test_client) = tokio::io::duplex(1024);
        let (mut up_a, mut up_b) = tokio::io::duplex(1024);
        let kind = BodyKind::Length(10);
        let task = tokio::spawn(async move {
            relay_request_body(&kind, b"01234", &mut client_side, &mut up_a).await
        });
        test_client.write_all(b"56789EXTRA").await.unwrap();
        task.await.unwrap().unwrap();
        let mut got = vec![0u8; 10];
        up_b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"0123456789");
    }

    #[tokio::test]
    async fn content_length_body_fails_when_the_client_disappears() {
        let (mut client_side, test_client) = tokio::io::duplex(64);
        let (mut up_a, _up_b) = tokio::io::duplex(64);
        drop(test_client);
        let err = relay_request_body(&BodyKind::Length(5), b"ab", &mut client_side, &mut up_a)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn chunked_body_is_copied_raw_up_to_the_last_chunk() {
        let (mut client_side, mut test_client) = tokio::io::duplex(1024);
        let (mut up_a, mut up_b) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            relay_request_body(&BodyKind::Chunked, b"3\r\nab", &mut client_side, &mut up_a).await
        });
        test_client
            .write_all(b"c\r\n0\r\n\r\nLEFTOVER")
            .await
            .unwrap();
        task.await.unwrap().unwrap();
        let mut got = vec![0u8; 13];
        up_b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"3\r\nabc\r\n0\r\n\r\n");
    }

    #[tokio::test(start_paused = true)]
    async fn silent_exchange_times_out_but_activity_extends_the_deadline() {
        let idle = Duration::from_secs(60);
        // Upstream never answers and never closes.
        let (mut client_side, _test_client) = tokio::io::duplex(1024);
        let (mut up_side, _test_up) = tokio::io::duplex(1024);
        let started = Instant::now();
        let err = relay_exchange(&mut client_side, &mut up_side, &BodyKind::None, b"", idle)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= idle && started.elapsed() < idle + Duration::from_secs(1));

        // A byte every 40 s keeps it alive past 60 s; then the upstream goes quiet.
        let (mut client_side, mut test_client) = tokio::io::duplex(1024);
        let (mut up_side, mut test_up) = tokio::io::duplex(1024);
        let feeder = tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_secs(40)).await;
                test_up.write_all(b"x").await.unwrap();
            }
            std::future::pending::<()>().await;
        });
        let started = Instant::now();
        let err = relay_exchange(&mut client_side, &mut up_side, &BodyKind::None, b"", idle)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() >= Duration::from_secs(180),
            "{:?}",
            started.elapsed()
        );
        let mut got = [0u8; 3];
        test_client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"xxx");
        feeder.abort();
    }
}
