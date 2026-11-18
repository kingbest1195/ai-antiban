//! File-system abstraction for the ownership journal and (later) config-file edits.
//!
//! `Fs` is a small trait so that every durable-write / lock / permission decision can be tested
//! against the in-memory `FakeFs` without touching the disk. `RealFs` is the std implementation.
//! The inter-process lock is `std::fs::File::try_lock` (stable since Rust 1.89); the only `unsafe`
//! is the Windows write-through rename.

use std::io;
use std::path::{Path, PathBuf};

/// Why a lock could not be taken. Never carries paths or values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockError {
    /// Another process (or another holder in this process) owns the lock.
    Held,
    /// The lock file itself could not be opened.
    Io(io::ErrorKind),
}

/// RAII lock guard: the lock is released when the guard is dropped.
pub struct FsLock {
    _guard: Box<dyn Send>,
}

impl FsLock {
    pub fn new(guard: Box<dyn Send>) -> Self {
        Self { _guard: guard }
    }
}

/// Permission applied to a file written by [`Fs::write_atomic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Owner-only (0600 on unix, default ACLs elsewhere), also forced on an existing target.
    Private,
    /// Keep the permissions of the existing target; a new file becomes owner-only.
    KeepExisting,
}

pub trait Fs: Send + Sync {
    /// `Ok(None)` when the file does not exist.
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>>;
    fn exists(&self, path: &Path) -> bool;
    /// Creates the directory chain; the leaf directory is owner-only (0700 on unix).
    fn create_private_dir_all(&self, path: &Path) -> io::Result<()>;
    /// Durable atomic replace: write temp file in the same directory -> fsync -> rename ->
    /// fsync of the directory. A symlink at `path` is never replaced: the link target is.
    fn write_atomic(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()>;
    /// Unix permission bits (`None` if the file does not exist or on non-unix).
    fn mode(&self, path: &Path) -> io::Result<Option<u32>>;
    fn set_mode(&self, path: &Path, mode: u32) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    /// Non-blocking exclusive inter-process lock on `path` (created if missing).
    fn try_lock(&self, path: &Path) -> Result<FsLock, LockError>;
    /// Direct child paths of `dir` (best effort; empty when missing or unreadable).
    fn list_dir(&self, _dir: &Path) -> Vec<PathBuf> {
        Vec::new()
    }
    /// Removes the temp files of [`Fs::write_atomic`] that a killed process left in `dir`
    /// (`.<name>.zastava-tmp.<pid>.<n>`). Best effort; returns how many were removed. Call it
    /// only while holding the lock of the files in `dir`, so no writer of ours is mid-write.
    fn sweep_stale_tmp(&self, _dir: &Path) -> usize {
        0
    }
}

/// Marker in the name of a temp file of `write_atomic`.
const TMP_MARKER: &str = ".zastava-tmp.";

/// Whether `name` is a temp file of `write_atomic` (`.<name>.zastava-tmp.<pid>.<n>`).
pub(super) fn is_stale_tmp_name(name: &str) -> bool {
    name.starts_with('.') && name.contains(TMP_MARKER)
}

/// `rename` that is durable on Windows: `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` returns
/// only after the move is on disk (`std::fs::rename` does not ask for write-through).
#[cfg(windows)]
fn rename_durable(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    let wide = |p: &Path| -> Vec<u16> { p.as_os_str().encode_wide().chain(Some(0)).collect() };
    let (a, b) = (wide(from), wide(to));
    // SAFETY: both buffers are NUL-terminated UTF-16 and live until the call returns.
    let ok = unsafe {
        MoveFileExW(
            a.as_ptr(),
            b.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(windows))]
fn rename_durable(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::rename(from, to)
}

// ---------------------------------------------------------------------------------------------
// RealFs
// ---------------------------------------------------------------------------------------------

/// The std-backed implementation. Touches only the paths it is given.
pub struct RealFs;

static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Follows a symlink at `path` so that the link itself survives an atomic replace.
fn resolve_write_target(path: &Path) -> io::Result<PathBuf> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

#[cfg(unix)]
fn open_new_private(path: &Path, mode: u32) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

#[cfg(not(unix))]
fn open_new_private(path: &Path, _mode: u32) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

impl Fs for RealFs {
    fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn create_private_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn write_atomic(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()> {
        use std::io::Write;
        let target = resolve_write_target(path)?;
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let name = target
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?
            .to_string_lossy()
            .into_owned();
        let bits = match mode {
            WriteMode::Private => 0o600,
            WriteMode::KeepExisting => self.mode(&target)?.unwrap_or(0o600),
        };
        let n = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let tmp = parent.join(format!(".{name}.zastava-tmp.{}.{n}", std::process::id()));
        let result = (|| {
            let mut f = open_new_private(&tmp, bits)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // `mode()` at creation is filtered by the umask; force the exact bits.
                f.set_permissions(std::fs::Permissions::from_mode(bits))?;
            }
            f.write_all(data)?;
            f.sync_all()?;
            drop(f);
            rename_durable(&tmp, &target)
        })();
        if let Err(e) = result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        #[cfg(unix)]
        if let Ok(dir) = std::fs::File::open(&parent) {
            dir.sync_all()?;
        }
        Ok(())
    }

    fn mode(&self, path: &Path) -> io::Result<Option<u32>> {
        match std::fs::metadata(path) {
            Ok(m) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    Ok(Some(m.permissions().mode() & 0o7777))
                }
                #[cfg(not(unix))]
                {
                    let _ = m;
                    Ok(None)
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn set_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode);
            Ok(())
        }
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn try_lock(&self, path: &Path) -> Result<FsLock, LockError> {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path).map_err(|e| LockError::Io(e.kind()))?;
        match file.try_lock() {
            Ok(()) => Ok(FsLock::new(Box::new(file))),
            Err(std::fs::TryLockError::WouldBlock) => Err(LockError::Held),
            Err(std::fs::TryLockError::Error(e)) => Err(LockError::Io(e.kind())),
        }
    }

    fn sweep_stale_tmp(&self, dir: &Path) -> usize {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return 0;
        };
        rd.flatten()
            .filter(|e| {
                e.file_type().is_ok_and(|t| t.is_file())
                    && e.file_name().to_str().is_some_and(is_stale_tmp_name)
            })
            .filter(|e| std::fs::remove_file(e.path()).is_ok())
            .count()
    }

    fn list_dir(&self, dir: &Path) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        out.sort();
        out
    }
}


#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
mod fakes;
#[cfg(any(test, feature = "test-support"))]
pub use fakes::{FakeFs, FsOp};
