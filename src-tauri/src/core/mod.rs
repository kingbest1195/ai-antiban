//! Layer 0 foundational primitives with zero dependencies on `tauri`, `commands`, `tray`,
//! `app`, `proxy`, `sysproxy`, `auditor`, or `state`.

pub mod bin_radar;
pub mod country;
pub mod net_safety;
pub mod payment_advisor;
mod payment_advisor_scenarios;
pub mod providers_manifest;
pub mod redact;
pub mod sanctions;
pub mod sanitize;
pub mod shutdown;
pub mod timing;
