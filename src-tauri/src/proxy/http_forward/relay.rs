use std::io;
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

use super::head::BodyKind;

/// Largest accepted chunk-size line / trailer section.
const MAX_CHUNK_LINE: usize = 4096;
const MAX_TRAILER_BYTES: usize = 16 * 1024;

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
