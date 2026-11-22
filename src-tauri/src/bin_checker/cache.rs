//! 7-day local TTL cache in `app_data_dir` keyed by 6..=8 digit BIN prefix (Zero PCI-DSS Scope).

use super::model::{BinReport, BinSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const BIN_CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const CACHE_FILE_NAME: &str = "bin_cache.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedBinEntry {
    cached_at: u64,
    report: BinReport,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheDiskStore {
    entries: HashMap<String, CachedBinEntry>,
}

pub struct BinCache {
    path: PathBuf,
    guard: Mutex<()>,
}

impl BinCache {
    pub fn in_dir(app_data_dir: &Path) -> Self {
        Self {
            path: app_data_dir.join(CACHE_FILE_NAME),
            guard: Mutex::new(()),
        }
    }

    pub fn current_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn get(&self, bin_prefix: &str) -> Option<BinReport> {
        self.get_at(bin_prefix, Self::current_unix_secs())
    }

    pub fn get_at(&self, bin_prefix: &str, now_secs: u64) -> Option<BinReport> {
        if !is_valid_cache_key(bin_prefix) {
            return None;
        }
        let _lock = self.guard.lock().ok()?;
        let store = self.read_store_locked();
        let entry = store.entries.get(bin_prefix)?;
        if now_secs.saturating_sub(entry.cached_at) >= BIN_CACHE_TTL_SECS {
            return None;
        }
        let mut report = entry.report.clone();
        report.source = BinSource::Cache;
        report.warnings.clear();
        Some(report)
    }

    pub fn put(&self, report: &BinReport) {
        self.put_at(report, Self::current_unix_secs());
    }

    pub fn put_at(&self, report: &BinReport, now_secs: u64) {
        if !is_valid_cache_key(&report.bin_prefix) {
            return;
        }
        if matches!(
            report.source,
            BinSource::FallbackUnknown | BinSource::LocalOverlay
        ) {
            return;
        }
        let Ok(_lock) = self.guard.lock() else {
            return;
        };
        let mut store = self.read_store_locked();
        store
            .entries
            .retain(|_, entry| now_secs.saturating_sub(entry.cached_at) < BIN_CACHE_TTL_SECS);
        store.entries.insert(
            report.bin_prefix.clone(),
            CachedBinEntry {
                cached_at: now_secs,
                report: report.clone(),
            },
        );
        self.write_store_locked(&store);
    }

    fn read_store_locked(&self) -> CacheDiskStore {
        let Ok(raw) = std::fs::read_to_string(&self.path) else {
            return CacheDiskStore::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn write_store_locked(&self, store: &CacheDiskStore) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(store) {
            let _ = std::fs::write(&self.path, json);
        }
    }
}

fn is_valid_cache_key(bin_prefix: &str) -> bool {
    (6..=8).contains(&bin_prefix.len()) && bin_prefix.bytes().all(|b| b.is_ascii_digit())
}
