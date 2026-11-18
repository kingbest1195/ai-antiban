//! Atomic baseline storage (`os_tz_baseline.json`).

use super::{BASELINE_FILE_NAME, OsTzBaseline};
use crate::sysproxy::fs::{Fs, RealFs, WriteMode};
use std::io;
use std::path::{Path, PathBuf};

pub fn baseline_path(data_dir: &Path) -> PathBuf {
    data_dir.join(BASELINE_FILE_NAME)
}

pub fn read_baseline(data_dir: &Path) -> Result<Option<OsTzBaseline>, String> {
    let path = baseline_path(data_dir);
    let bytes = RealFs
        .read(&path)
        .map_err(|e| format!("Не удалось прочитать os_tz_baseline.json: {e}"))?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let parsed: OsTzBaseline = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Повреждённый os_tz_baseline.json: {e}"))?;
    Ok(Some(parsed))
}

pub fn write_baseline_atomic(data_dir: &Path, baseline: &OsTzBaseline) -> Result<(), String> {
    RealFs
        .create_private_dir_all(data_dir)
        .map_err(|e| format!("Не удалось создать каталог данных: {e}"))?;
    let path = baseline_path(data_dir);
    let json = serde_json::to_vec_pretty(baseline)
        .map_err(|e| format!("Ошибка сериализации os_tz_baseline.json: {e}"))?;
    RealFs
        .write_atomic(&path, &json, WriteMode::Private)
        .map_err(|e| format!("Не удалось сохранить os_tz_baseline.json: {e}"))
}

pub fn remove_baseline(data_dir: &Path) -> Result<(), String> {
    let path = baseline_path(data_dir);
    match RealFs.remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Не удалось удалить os_tz_baseline.json: {e}")),
    }
}
