//! Offline causal replication through an immutable, application-selected folder.
//! Applications own projection code, the cloud client and the local write barrier.
mod baseline;
mod exchange;
mod journal;
mod merge;
mod publication;
mod retention;
mod snapshot;
mod wire;

pub use baseline::*;
pub use exchange::*;
pub use journal::*;
pub use merge::*;
pub use retention::*;
pub use snapshot::*;
pub use wire::*;

/// Namespace of the official synchronization extension.
pub const NAMESPACE: &str = "studio.illegal.darkbox.sync";
/// mapping.json and the local journal schema keep their own version line.
pub(crate) const MAPPING_VERSION: &str = "1.0.0";
pub(crate) const JOURNAL_SCHEMA_VERSION: &str = "1.0.0";

/// A sync extension version, which is also the `protocolVersion` of every
/// record in a domain or repository. It is fixed when the domain is created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SyncProtocol {
    /// Extension 1.0.0, bound to common version 1.5.0 exactly.
    V1_0,
    /// Extension 1.1.0, for common 1.6.0 and later versions with extension bundles.
    V1_1,
}

impl SyncProtocol {
    /// The newest protocol this build can create.
    pub const LATEST: Self = Self::V1_1;

    /// The extension and record `protocolVersion` string.
    pub fn version(self) -> &'static str {
        match self {
            Self::V1_0 => "1.0.0",
            Self::V1_1 => "1.1.0",
        }
    }

    /// Recognize a supported protocol version string.
    pub fn parse(version: &str) -> Option<Self> {
        match version {
            "1.0.0" => Some(Self::V1_0),
            "1.1.0" => Some(Self::V1_1),
            _ => None,
        }
    }

    /// The lowest common version whose packages can carry this protocol.
    pub fn minimum_common(self) -> &'static str {
        match self {
            Self::V1_0 => "1.5.0",
            Self::V1_1 => "1.6.0",
        }
    }

    /// The protocol a package of this common version uses, if it supports sync.
    pub fn for_common(common_version: &str) -> Option<Self> {
        if common_version == "1.5.0" {
            return Some(Self::V1_0);
        }
        crate::versions::find(common_version)
            .filter(|spec| spec.capabilities.extension_bundles)
            .map(|_| Self::V1_1)
    }

    /// Whether a package of this common version can belong to a domain whose
    /// root records `floor` as its `commonVersion`.
    pub(crate) fn admits(self, floor: &str, common_version: &str) -> bool {
        match self {
            Self::V1_0 => floor == "1.5.0" && common_version == "1.5.0",
            Self::V1_1 => {
                let numbers = crate::versions::numbers;
                Self::for_common(common_version) == Some(Self::V1_1)
                    && matches!(
                        (numbers(floor), numbers(common_version)),
                        (Some(floor), Some(actual)) if floor.0 == actual.0 && floor <= actual
                    )
            }
        }
    }
}
/// Package directory that holds the synchronization metadata.
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
