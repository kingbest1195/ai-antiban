//! Layer 0 foundational primitives with zero dependencies on `tauri`, `commands`, `tray`,
//! `app`, `proxy`, `sysproxy`, `auditor`, or `state`.

pub mod net_safety;
pub mod redact;
pub mod sanctions;
pub mod shutdown;
pub mod timing;
