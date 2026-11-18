/// Largest accepted request head (request line + headers).
pub const MAX_HEAD_BYTES: usize = 64 * 1024;
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
