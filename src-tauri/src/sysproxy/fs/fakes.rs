#![cfg(any(test, feature = "test-support"))]

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

    fn list_dir(&self, dir: &Path) -> Vec<PathBuf> {
        let resolved = self.resolve(dir);
        let s = self.st.lock().unwrap();
        let mut children = BTreeSet::new();
        for p in s.files.keys().chain(s.dirs.keys()) {
            if let Ok(rel) = p.strip_prefix(&resolved)
                && let Some(first) = rel.components().next()
            {
                children.insert(resolved.join(first.as_os_str()));
            }
        }
        children.into_iter().collect()
    }
}
