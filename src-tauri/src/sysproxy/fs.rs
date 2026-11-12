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
fn is_stale_tmp_name(name: &str) -> bool {
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
}

// ---------------------------------------------------------------------------------------------
// FakeFs
// ---------------------------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
pub use fake::{FakeFs, FsOp};

#[cfg(any(test, feature = "test-support"))]
mod fake {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    /// Operations that [`FakeFs::fail_next`] can break.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum FsOp {
        Read,
        WriteAtomic,
        CreateDir,
        SetMode,
        Remove,
        Lock,
    }

    struct FailRule {
        skip: usize,
        count: usize,
    }

    #[derive(Clone)]
    struct File {
        data: Vec<u8>,
        mode: u32,
    }

    #[derive(Default)]
    struct State {
        files: BTreeMap<PathBuf, File>,
        links: BTreeMap<PathBuf, PathBuf>,
        dirs: BTreeMap<PathBuf, u32>,
        locks: BTreeSet<PathBuf>,
        fail: BTreeMap<FsOp, FailRule>,
        writes: usize,
        leftover_tmp: usize,
    }

    /// In-memory file system. `Clone` shares the state (like several processes on one disk).
    #[derive(Clone, Default)]
    pub struct FakeFs {
        st: Arc<Mutex<State>>,
    }

    struct FakeLockGuard {
        st: Arc<Mutex<State>>,
        path: PathBuf,
    }

    impl Drop for FakeLockGuard {
        fn drop(&mut self) {
            if let Ok(mut s) = self.st.lock() {
                s.locks.remove(&self.path);
            }
        }
    }

    fn injected() -> io::Error {
        io::Error::other("injected fs failure")
    }

    impl FakeFs {
        pub fn new() -> Self {
            Self::default()
        }

        /// Next call of `op` fails (once).
        pub fn fail_next(&self, op: FsOp) {
            self.fail_after(op, 0);
        }

        /// The call of `op` after `skip` successful ones fails (once).
        pub fn fail_after(&self, op: FsOp, skip: usize) {
            self.st
                .lock()
                .unwrap()
                .fail
                .insert(op, FailRule { skip, count: 1 });
        }

        /// The `count` calls of `op` after `skip` successful ones fail (e.g. a write and the
        /// clean-up write that follows it: the process "dies" in between).
        pub fn fail_range(&self, op: FsOp, skip: usize, count: usize) {
            self.st
                .lock()
                .unwrap()
                .fail
                .insert(op, FailRule { skip, count });
        }

        fn check(&self, op: FsOp) -> io::Result<()> {
            let mut s = self.st.lock().unwrap();
            if let Some(rule) = s.fail.get_mut(&op) {
                if rule.skip > 0 {
                    rule.skip -= 1;
                } else if rule.count > 0 {
                    rule.count -= 1;
                    if rule.count == 0 {
                        s.fail.remove(&op);
                    }
                    return Err(injected());
                }
            }
            Ok(())
        }

        /// Number of successful durable writes so far.
        pub fn write_count(&self) -> usize {
            self.st.lock().unwrap().writes
        }

        /// Temp files left behind by a simulated crash during a write.
        pub fn leftover_tmp(&self) -> usize {
            self.st.lock().unwrap().leftover_tmp
        }

        /// Puts a file directly (test setup; not counted as a write).
        pub fn put(&self, path: &Path, data: &[u8], mode: u32) {
            self.st.lock().unwrap().files.insert(
                path.to_path_buf(),
                File {
                    data: data.to_vec(),
                    mode,
                },
            );
        }

        pub fn get(&self, path: &Path) -> Option<Vec<u8>> {
            self.st
                .lock()
                .unwrap()
                .files
                .get(path)
                .map(|f| f.data.clone())
        }

        /// Makes `link` a symlink to `target`.
        pub fn symlink(&self, link: &Path, target: &Path) {
            self.st
                .lock()
                .unwrap()
                .links
                .insert(link.to_path_buf(), target.to_path_buf());
        }

        pub fn is_symlink(&self, path: &Path) -> bool {
            self.st.lock().unwrap().links.contains_key(path)
        }

        pub fn dir_mode(&self, path: &Path) -> Option<u32> {
            self.st.lock().unwrap().dirs.get(path).copied()
        }

        /// Simulates another process holding the lock on `path`.
        pub fn hold_lock_externally(&self, path: &Path) {
            self.st.lock().unwrap().locks.insert(path.to_path_buf());
        }

        pub fn release_external_lock(&self, path: &Path) {
            self.st.lock().unwrap().locks.remove(path);
        }

        /// Simulates a crash in the middle of `write_atomic`: the target keeps its old content and
        /// a temp file is left behind.
        pub fn crash_mid_write_next(&self) {
            self.st
                .lock()
                .unwrap()
                .fail
                .insert(FsOp::WriteAtomic, FailRule { skip: 0, count: 1 });
            self.st.lock().unwrap().leftover_tmp += 1;
        }

        fn resolve(&self, path: &Path) -> PathBuf {
            let s = self.st.lock().unwrap();
            let mut cur = path.to_path_buf();
            for _ in 0..8 {
                match s.links.get(&cur) {
                    Some(t) => cur = t.clone(),
                    None => break,
                }
            }
            cur
        }
    }

    impl Fs for FakeFs {
        fn read(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
            self.check(FsOp::Read)?;
            let p = self.resolve(path);
            Ok(self
                .st
                .lock()
                .unwrap()
                .files
                .get(&p)
                .map(|f| f.data.clone()))
        }

        fn exists(&self, path: &Path) -> bool {
            let p = self.resolve(path);
            let s = self.st.lock().unwrap();
            s.files.contains_key(&p) || s.dirs.contains_key(&p)
        }

        fn create_private_dir_all(&self, path: &Path) -> io::Result<()> {
            self.check(FsOp::CreateDir)?;
            self.st
                .lock()
                .unwrap()
                .dirs
                .insert(path.to_path_buf(), 0o700);
            Ok(())
        }

        fn write_atomic(&self, path: &Path, data: &[u8], mode: WriteMode) -> io::Result<()> {
            self.check(FsOp::WriteAtomic)?;
            let target = self.resolve(path);
            let mut s = self.st.lock().unwrap();
            let bits = match mode {
                WriteMode::Private => 0o600,
                WriteMode::KeepExisting => s.files.get(&target).map(|f| f.mode).unwrap_or(0o600),
            };
            s.files.insert(
                target,
                File {
                    data: data.to_vec(),
                    mode: bits,
                },
            );
            s.writes += 1;
            Ok(())
        }

        fn mode(&self, path: &Path) -> io::Result<Option<u32>> {
            let p = self.resolve(path);
            Ok(self.st.lock().unwrap().files.get(&p).map(|f| f.mode))
        }

        fn set_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
            self.check(FsOp::SetMode)?;
            let p = self.resolve(path);
            match self.st.lock().unwrap().files.get_mut(&p) {
                Some(f) => {
                    f.mode = mode;
                    Ok(())
                }
                None => Err(io::ErrorKind::NotFound.into()),
            }
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.check(FsOp::Remove)?;
            match self.st.lock().unwrap().files.remove(path) {
                Some(_) => Ok(()),
                None => Err(io::ErrorKind::NotFound.into()),
            }
        }

        fn try_lock(&self, path: &Path) -> Result<FsLock, LockError> {
            self.check(FsOp::Lock)
                .map_err(|e| LockError::Io(e.kind()))?;
            let mut s = self.st.lock().unwrap();
            if !s.locks.insert(path.to_path_buf()) {
                return Err(LockError::Held);
            }
            drop(s);
            Ok(FsLock::new(Box::new(FakeLockGuard {
                st: self.st.clone(),
                path: path.to_path_buf(),
            })))
        }

        fn sweep_stale_tmp(&self, dir: &Path) -> usize {
            let mut s = self.st.lock().unwrap();
            let stale: Vec<PathBuf> = s
                .files
                .keys()
                .filter(|p| {
                    p.parent() == Some(dir)
                        && p.file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(is_stale_tmp_name)
                })
                .cloned()
                .collect();
            let removed = stale.len() + std::mem::take(&mut s.leftover_tmp);
            for p in stale {
                s.files.remove(&p);
            }
            removed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_fs_atomic_write_is_private_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.json");
        RealFs.write_atomic(&p, b"one", WriteMode::Private).unwrap();
        RealFs.write_atomic(&p, b"two", WriteMode::Private).unwrap();
        assert_eq!(RealFs.read(&p).unwrap().unwrap(), b"two");
        #[cfg(unix)]
        assert_eq!(RealFs.mode(&p).unwrap(), Some(0o600));
        // No temp files are left behind.
        let n = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(n, 1);
    }

    #[test]
    fn real_fs_private_dir_is_0700() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("a").join("b");
        RealFs.create_private_dir_all(&d).unwrap();
        #[cfg(unix)]
        assert_eq!(RealFs.mode(&d).unwrap(), Some(0o700));
        assert!(RealFs.exists(&d));
    }

    #[cfg(unix)]
    #[test]
    fn real_fs_write_keeps_a_symlink_and_updates_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        let link = dir.path().join("link.txt");
        std::fs::write(&target, b"old").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        RealFs
            .write_atomic(&link, b"new", WriteMode::KeepExisting)
            .unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn real_fs_keep_existing_preserves_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").unwrap();
        RealFs.set_mode(&p, 0o640).unwrap();
        RealFs
            .write_atomic(&p, b"y", WriteMode::KeepExisting)
            .unwrap();
        assert_eq!(RealFs.mode(&p).unwrap(), Some(0o640));
    }

    #[test]
    fn real_fs_lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("l.lock");
        let first = RealFs.try_lock(&p).unwrap();
        assert!(matches!(RealFs.try_lock(&p), Err(LockError::Held)));
        drop(first);
        // A concurrently forked child (other tests spawn processes) may keep the open file
        // description, and with it the flock, for a few milliseconds until it execs.
        let mut again = RealFs.try_lock(&p);
        for _ in 0..200 {
            if again.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            again = RealFs.try_lock(&p);
        }
        assert!(again.is_ok(), "{:?}", again.err());
    }

    #[test]
    fn fake_fs_failure_injection_leaves_target_intact() {
        let fs = FakeFs::new();
        let p = Path::new("/d/j");
        fs.write_atomic(p, b"a", WriteMode::Private).unwrap();
        fs.fail_next(FsOp::WriteAtomic);
        assert!(fs.write_atomic(p, b"b", WriteMode::Private).is_err());
        assert_eq!(fs.get(p).unwrap(), b"a");
        fs.write_atomic(p, b"c", WriteMode::Private).unwrap();
        assert_eq!(fs.get(p).unwrap(), b"c");
        assert_eq!(fs.write_count(), 2);
    }

    #[test]
    fn fake_fs_symlink_write_updates_target_not_link() {
        let fs = FakeFs::new();
        fs.put(Path::new("/d/real"), b"old", 0o644);
        fs.symlink(Path::new("/d/link"), Path::new("/d/real"));
        fs.write_atomic(Path::new("/d/link"), b"new", WriteMode::KeepExisting)
            .unwrap();
        assert!(fs.is_symlink(Path::new("/d/link")));
        assert_eq!(fs.get(Path::new("/d/real")).unwrap(), b"new");
        assert_eq!(fs.mode(Path::new("/d/real")).unwrap(), Some(0o644));
    }

    #[test]
    fn fake_fs_lock_shared_across_clones() {
        let fs = FakeFs::new();
        let other = fs.clone();
        let g = fs.try_lock(Path::new("/l")).unwrap();
        assert!(matches!(
            other.try_lock(Path::new("/l")),
            Err(LockError::Held)
        ));
        drop(g);
        assert!(other.try_lock(Path::new("/l")).is_ok());
    }

    #[test]
    fn real_fs_sweeps_only_stale_temp_files_of_write_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let tmp1 = dir.path().join(".journal.json.zastava-tmp.4242.0");
        let tmp2 = dir.path().join(".other.zastava-tmp.1.9");
        let keep = dir.path().join("journal.json");
        let hidden = dir.path().join(".hidden");
        for f in [&tmp1, &tmp2, &keep, &hidden] {
            std::fs::write(f, b"x").unwrap();
        }
        assert_eq!(RealFs.sweep_stale_tmp(dir.path()), 2);
        assert!(!tmp1.exists() && !tmp2.exists());
        assert!(keep.exists() && hidden.exists());
        assert_eq!(RealFs.sweep_stale_tmp(dir.path()), 0);
        assert_eq!(RealFs.sweep_stale_tmp(&dir.path().join("missing")), 0);
    }

    #[test]
    fn a_write_replaces_the_target_without_leaving_a_temp_file() {
        // `rename_durable` is a plain rename off Windows and MoveFileExW(WRITE_THROUGH) on it.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.json");
        for n in 0..3 {
            RealFs
                .write_atomic(&p, format!("v{n}").as_bytes(), WriteMode::Private)
                .unwrap();
        }
        assert_eq!(RealFs.read(&p).unwrap().unwrap(), b"v2");
        assert_eq!(RealFs.sweep_stale_tmp(dir.path()), 0);
    }
}
