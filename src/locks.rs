//! Whole-file advisory locks from the standard library: `flock(2)` on Unix and
//! `LockFileEx` over the whole file on Windows. Attempts never block.
use std::fs::{File, TryLockError};
use std::io;

fn outcome(result: Result<(), TryLockError>) -> io::Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

/// Contention is reported as `ErrorKind::WouldBlock`.
pub(crate) fn try_exclusive(file: &File) -> io::Result<()> {
    outcome(file.try_lock())
}

/// Contention is reported as `ErrorKind::WouldBlock`.
pub(crate) fn try_shared(file: &File) -> io::Result<()> {
    outcome(file.try_lock_shared())
}

/// Flush an already published regular file to disk. Windows flushes only
/// through a handle opened for writing; Unix-like systems accept a read-only
/// descriptor, which also works for files without write permission.
pub(crate) fn sync_file(path: &std::path::Path) -> io::Result<()> {
    #[cfg(windows)]
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    #[cfg(not(windows))]
    let file = File::open(path)?;
    file.sync_all()
}

/// Release before closing: another descriptor of the same open file description
/// (for example one inherited across fork) would otherwise keep the lock alive.
pub(crate) fn unlock(file: &File) {
    let _ = file.unlock();
}
