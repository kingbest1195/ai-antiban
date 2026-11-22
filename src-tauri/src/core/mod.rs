//! Layer 0 foundational primitives with zero dependencies on `tauri`, `commands`, `tray`,
//! `app`, `proxy`, `sysproxy`, `auditor`, or `state`.

pub mod country;
pub mod net_safety;
pub mod redact;
pub mod sanctions;
pub mod sanitize;
pub mod shutdown;
pub mod timing;
