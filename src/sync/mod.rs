//! Offline causal replication through an immutable, application-selected folder.
//! Applications own projection code, the cloud client and the local write barrier.
mod exchange;
mod journal;
mod merge;
mod snapshot;
mod wire;

pub use exchange::*;
pub use journal::*;
pub use merge::*;
pub use snapshot::*;
pub use wire::*;

pub const NAMESPACE: &str = "studio.illegal.darkbox.sync";
pub const VERSION: &str = "1.0.0";
pub const PREFIX: &str = "extensions/studio.illegal.darkbox.sync";

pub(crate) type Result<T> = std::result::Result<T, crate::Error>;
pub(crate) fn invalid(message: impl Into<String>) -> crate::Error {
    crate::Error::invalid("sync.invalid", message)
}
pub(crate) fn unsupported(message: impl Into<String>) -> crate::Error {
    crate::Error::new(crate::Status::Unsupported, "sync.unsupported", message)
}
pub(crate) fn sql(error: rusqlite::Error) -> crate::Error {
    crate::Error::new(
        crate::Status::OperationalError,
        "sync.sqlite",
        error.to_string(),
    )
}
pub(crate) fn fork(message: impl Into<String>) -> crate::Error {
    crate::Error::invalid("sync.fork", message)
}

pub(crate) fn limit(message: impl Into<String>) -> crate::Error {
    crate::Error::new(crate::Status::ResourceLimit, "sync.limits", message)
}

pub(crate) fn pending_bytes(message: impl Into<String>) -> crate::Error {
    crate::Error::new(
        crate::Status::OperationalError,
        "sync.pending_bytes",
        message,
    )
}
