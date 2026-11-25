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

/// Release before closing: another descriptor of the same open file description
/// (for example one inherited across fork) would otherwise keep the lock alive.
pub(crate) fn unlock(file: &File) {
    let _ = file.unlock();
}
