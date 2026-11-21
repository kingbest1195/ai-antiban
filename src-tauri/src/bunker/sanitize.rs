//! Secret sanitization and private file/directory permission helpers for Data Bunker.

use std::fs;
use std::path::Path;

#[allow(unused_imports)]
pub use crate::core::sanitize::{
    copy_private_dir_filtered, copy_private_file, copy_sanitized_json_file, ensure_private_dir,
    is_excluded_secret_name, restrict_file_to_owner, sanitize_json_value, write_private_file,
};

/// Extracts `mcpServers` keys from a Claude Desktop or Cursor `mcp.json` file.
pub fn extract_mcp_server_names(path: &Path) -> Vec<String> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let mut names: Vec<String> = val
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    names.sort();
    names
}
