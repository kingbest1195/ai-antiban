//! Plain HTTP forwarding for transit (non-AI) traffic: absolute-form request parsing, hop-by-hop
//! header removal, request-line rewriting and the body / response relay.
//!
//! The upstream connection is never reused (`Connection: close`), so there is no keep-alive pool
//! and no response parsing: the response is streamed back as is until the upstream closes.

mod head;
mod relay;

pub use head::{
    BodyKind, HeadError, MAX_HEAD_BYTES, ParsedRequest, RequestForm, find_head_end, parse_request,
    split_authority,
};
pub use relay::{ChunkedTracker, relay_exchange, relay_request_body};

#[cfg(test)]
#[path = "../http_forward_tests.rs"]
mod tests;
