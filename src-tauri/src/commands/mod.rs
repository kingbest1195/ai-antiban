//! Tauri command handlers, grouped by domain. Registered in `app::run()` via `generate_handler!`.

pub mod audit;
pub mod claude;
pub mod coverage;
pub mod crash_test;
pub mod deeplink;
pub mod domains;
pub mod interception;
pub mod payment;
pub mod restart_app;
pub mod routes;
pub mod sysproxy;
pub mod updates;
pub mod upstream;

use crate::state;

pub type AppContext = state::AppState;
