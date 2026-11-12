//! Local immutable publication, including Unix mounts without no-replace rename.
use std::{
    fs::{self, File},
    io,
    path::Path,
    time::Instant,
};
use tempfile::{NamedTempFile, PersistError};

struct DirectoryGuard(File);
impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(unix)]
fn lock_parent(target: &Path, end: Instant) -> io::Result<Option<DirectoryGuard>> {
    use std::os::unix::fs::MetadataExt;
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    // Some native filesystems support no-replace publication without permitting
    // directory locks. Keep that path, but never enable rename fallback there.
    let file = match File::open(parent) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    loop {
        if Instant::now() >= end {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(
                    std::time::Duration::from_millis(5)
                        .min(end.saturating_duration_since(Instant::now())),
                );
            }
            Err(_) => return Ok(None),
        }
    }
    let guard = DirectoryGuard(file);
    let opened = guard.0.metadata()?;
    let current = fs::symlink_metadata(parent)?;
    if !opened.is_dir()
        || !current.is_dir()
        || current.file_type().is_symlink()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
    {
        return Err(io::Error::other(
            "Sync publication directory changed while locking",
        ));
    }
    Ok(Some(guard))
}

#[cfg(not(unix))]
fn lock_parent(_target: &Path, _end: Instant) -> io::Result<Option<DirectoryGuard>> {
    Ok(None)
}

pub(crate) fn persist(
    candidate: NamedTempFile,
    target: &Path,
    end: Instant,
) -> Result<File, PersistError> {
    persist_with(candidate, target, end, |candidate, target| {
        candidate.persist_noclobber(target)
    })
}

fn persist_with(
    candidate: NamedTempFile,
    target: &Path,
    end: Instant,
    native: impl FnOnce(NamedTempFile, &Path) -> Result<File, PersistError>,
) -> Result<File, PersistError> {
    let guard = match lock_parent(target, end) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(PersistError {
                error,
                file: candidate,
            });
        }
    };
    persist_guarded(candidate, target, end, guard, native)
}

fn persist_guarded(
    candidate: NamedTempFile,
    target: &Path,
    end: Instant,
    guard: Option<DirectoryGuard>,
    native: impl FnOnce(NamedTempFile, &Path) -> Result<File, PersistError>,
) -> Result<File, PersistError> {
    if Instant::now() >= end {
        return Err(PersistError {
            error: io::ErrorKind::TimedOut.into(),
            file: candidate,
        });
    }
    match native(candidate, target) {
        Err(failure)
            if guard.is_some()
                && matches!(
                    failure.error.kind(),
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::Unsupported
                        | io::ErrorKind::InvalidInput
                ) =>
        {
            // All local SDK publishers hold this directory guard, including
            // those using the native path. Recheck after locking; never copy
            // into a final name or reopen an existing publication for writing.
            match fs::symlink_metadata(target) {
                Ok(_) => Err(PersistError {
                    error: io::ErrorKind::AlreadyExists.into(),
                    file: failure.file,
                }),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if Instant::now() >= end {
                        return Err(PersistError {
                            error: io::ErrorKind::TimedOut.into(),
                            file: failure.file,
                        });
                    }
                    failure.file.persist(target)
                }
                Err(error) => Err(PersistError {
                    error,
                    file: failure.file,
                }),
            }
        }
        result => result,
    }
}

pub(crate) fn error(error: io::Error) -> crate::Error {
    if error.kind() == io::ErrorKind::TimedOut {
        super::limit("Sync publication lock deadline exceeded")
    } else {
        crate::io_failure(error)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Barrier},
        time::Duration,
    };

    fn candidate(root: &Path, bytes: &[u8]) -> NamedTempFile {
        let mut file = NamedTempFile::new_in(root).unwrap();
        file.write_all(bytes).unwrap();
        file.as_file().sync_all().unwrap();
        file
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn unsupported(file: NamedTempFile, _target: &Path) -> Result<File, PersistError> {
        Err(PersistError {
            error: io::ErrorKind::PermissionDenied.into(),
            file,
        })
    }

    #[test]
    fn fallback_atomically_publishes_complete_bytes_without_leaving_sidecars() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::Unsupported,
            io::ErrorKind::InvalidInput,
        ] {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("record.json");
            let source = candidate(root.path(), b"complete immutable record");
            let previous = source.path().to_owned();
            persist_with(source, &target, deadline(), |file, _| {
                Err(PersistError {
                    error: kind.into(),
                    file,
                })
            })
            .unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"complete immutable record");
            assert!(!previous.exists());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn fallback_never_replaces_existing_bytes_and_retains_its_private_candidate() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("record.json");
        fs::write(&target, b"the winner").unwrap();
        let source = candidate(root.path(), b"another complete candidate");
        let path = source.path().to_owned();
        let failure = persist_with(source, &target, deadline(), unsupported).unwrap_err();
        assert_eq!(failure.error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&target).unwrap(), b"the winner");
        assert_eq!(fs::read(&path).unwrap(), b"another complete candidate");
        drop(failure);
        assert!(!path.exists());
    }

    #[test]
    fn fallback_refuses_dangling_symlinks_and_directories() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        for directory in [false, true] {
            let target = root
                .path()
                .join(if directory { "directory" } else { "symlink" });
            if directory {
                fs::create_dir(&target).unwrap();
            } else {
                symlink(root.path().join("missing"), &target).unwrap();
            }
            let failure = persist_with(
                candidate(root.path(), b"data"),
                &target,
                deadline(),
                unsupported,
            )
            .unwrap_err();
            assert_eq!(failure.error.kind(), io::ErrorKind::AlreadyExists);
            let metadata = fs::symlink_metadata(&target).unwrap();
            assert_eq!(metadata.is_dir(), directory);
            assert_eq!(metadata.file_type().is_symlink(), !directory);
            assert!(!root.path().join("missing").exists());
        }
    }

    #[test]
    fn native_no_clobber_remains_available_without_directory_lock_support() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("record.json");
        persist_guarded(
            candidate(root.path(), b"native bytes"),
            &target,
            deadline(),
            None,
            |file, target| file.persist_noclobber(target),
        )
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"native bytes");
    }

    #[test]
    fn unsafe_fallback_and_unrelated_native_failures_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("record.json");
        let failure = persist_guarded(
            candidate(root.path(), b"data"),
            &target,
            deadline(),
            None,
            unsupported,
        )
        .unwrap_err();
        assert_eq!(failure.error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!target.exists());
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::Other,
            io::ErrorKind::AlreadyExists,
        ] {
            let failure = persist_with(
                candidate(root.path(), b"data"),
                &target,
                deadline(),
                |file, _| {
                    Err(PersistError {
                        error: kind.into(),
                        file,
                    })
                },
            )
            .unwrap_err();
            assert_eq!(failure.error.kind(), kind);
            assert!(!target.exists());
        }
    }

    #[test]
    fn concurrent_fallback_and_native_publishers_keep_one_complete_winner() {
        for native_second in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("record.json");
            let start = Arc::new(Barrier::new(2));
            let outcomes = std::thread::scope(|scope| {
                let mut workers = Vec::new();
                for index in 0..2 {
                    let source = candidate(root.path(), &[index; 65536]);
                    let target = &target;
                    let start = start.clone();
                    workers.push(scope.spawn(move || {
                        start.wait();
                        persist_with(source, target, deadline(), |file, target| {
                            if index == 1 && native_second {
                                file.persist_noclobber(target)
                            } else {
                                unsupported(file, target)
                            }
                        })
                        .map(|_| ())
                        .map_err(|failure| failure.error.kind())
                    }));
                }
                workers
                    .into_iter()
                    .map(|worker| worker.join().unwrap())
                    .collect::<Vec<_>>()
            });
            assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| **outcome == Err(io::ErrorKind::AlreadyExists))
                    .count(),
                1
            );
            let bytes = fs::read(&target).unwrap();
            assert!(bytes == vec![0; 65536] || bytes == vec![1; 65536]);
        }
    }

    #[test]
    fn contended_directory_locks_respect_the_deadline_and_release_despite_duplicates() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("record.json");
        let guard = lock_parent(&target, deadline()).unwrap().unwrap();
        let inherited = guard.0.try_clone().unwrap();
        let failure = persist_with(
            candidate(root.path(), b"data"),
            &target,
            Instant::now() + Duration::from_millis(20),
            |_, _| panic!("native publication bypassed the directory lock"),
        )
        .unwrap_err();
        assert_eq!(failure.error.kind(), io::ErrorKind::TimedOut);
        assert!(!target.exists());
        drop(guard);
        persist_with(failure.file, &target, deadline(), unsupported).unwrap();
        drop(inherited);
        assert_eq!(fs::read(&target).unwrap(), b"data");
    }
}
