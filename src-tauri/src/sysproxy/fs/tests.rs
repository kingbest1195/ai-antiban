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
