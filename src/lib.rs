//! Offline Darkbox container SDK: verified snapshots, resource streams, isolated
//! SQLite/resource edits and validated atomic publication. Application-profile
//! semantics are reported separately and validated only by registered application code.

#![warn(missing_docs)]

mod analysis;
mod container;
mod creation;
mod digest;
pub mod extensions;
mod json;
mod live;
mod locks;
pub mod manifest;
mod media;
pub use live::{DirectoryLibrary, HotCapture};
mod model;
mod package;
mod paths;
pub mod profiles;
pub mod protection;
mod resource_inventory;
mod source;
mod sqlite;
pub mod sync;
mod transfer;
pub use media::StoredResource;
pub use transfer::{create_delta, merge, pack, unpack, verify_delta};
mod versions;
mod writer;

pub(crate) use analysis::{AnalysisInput, Staging, analyze_source, read_metadata, stream};
pub use creation::PackageWriter;
pub use extensions::{ExtensionRegistry, ExtensionVerifier, TrustedDigests, VerificationOptions};
pub use manifest::ManifestBuilder;
pub use model::{
    ApplicationValidation, Compression, DatabaseInfo, Diagnostic, EntryInfo, EntryKind,
    Failure as Error, Limits, Mode, Report, Scope, Severity, Status,
};
use model::{Failure, Result};
pub use package::{
    DatabaseReader, DiagnosticPackage, Package, PackageEditor, ResourceReader, ValueAddress,
};
pub use profiles::{ApplicationProfile, ProfileContext, ProfileRegistry};
use std::fs::File;
use std::path::Path;
pub use writer::{PackageUpdate, open, save};

/// Use the same SQLite and JSON types as the SDK without dependency-version ambiguity.
pub use {rusqlite, serde_json, zeroize};

/// One common specification version this build can read and write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpecificationVersion {
    /// The exact `darkbox.version` value.
    pub version: &'static str,
    /// Whether the version is published. Unpublished references may still change.
    pub released: bool,
    /// Whether this software creates new packages in the version. A read-only
    /// version is still read, verified and saved for existing packages.
    pub writable: bool,
}

/// The canonical bundle of one official extension version known to this build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtensionVersion {
    /// The official extension namespace.
    pub namespace: &'static str,
    /// The extension version.
    pub version: &'static str,
    /// Whether the bundle is published. Unpublished references may still change.
    pub released: bool,
    /// The lowest common version that carries this bundle separately.
    pub minimum_common: &'static str,
}

/// Every common specification version embedded in this build, oldest first.
pub fn supported_versions() -> impl Iterator<Item = SpecificationVersion> {
    versions::VERSIONS.iter().map(|spec| SpecificationVersion {
        version: spec.version,
        released: spec.released,
        writable: spec.writable,
    })
}

/// Every separately bundled official extension version embedded in this build.
/// Extensions of common versions before 1.6.0 travel inside the common bundle
/// and are not listed here.
pub fn supported_extensions() -> impl Iterator<Item = ExtensionVersion> {
    versions::EXTENSION_BUNDLES
        .iter()
        .map(|bundle| ExtensionVersion {
            namespace: bundle.namespace,
            version: bundle.version,
            released: bundle.released,
            minimum_common: bundle.min_common,
        })
}

/// Analyze a package in the given mode with default verification options.
pub fn analyze(path: impl AsRef<Path>, mode: Mode, limits: Limits) -> Report {
    analyze_with(path, mode, limits, &VerificationOptions::default())
}

/// Analyze a package with application-supplied extensions, profiles, keys and trust.
pub fn analyze_with(
    path: impl AsRef<Path>,
    mode: Mode,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Report {
    analyze_captured(path.as_ref(), mode, limits, options, false).0
}

pub(crate) fn analyze_captured(
    path: &Path,
    mode: Mode,
    limits: Limits,
    options: &VerificationOptions<'_>,
    capture: bool,
) -> (Report, Option<Staging>) {
    analyze_input(path, mode, limits, options, capture, None)
}

pub(crate) fn analyze_input(
    path: &Path,
    mode: Mode,
    limits: Limits,
    options: &VerificationOptions<'_>,
    capture: bool,
    source_file: Option<File>,
) -> (Report, Option<Staging>) {
    analyze_source(
        path,
        mode,
        limits,
        options,
        capture,
        source_file.map(AnalysisInput::File),
    )
}

/// Fully verify the common machine-checkable rules with default limits.
pub fn verify(path: impl AsRef<Path>) -> Report {
    analyze(path, Mode::Verify, Limits::default())
}

/// Inspect unsigned inventory claims without reading payload bytes.
pub fn inspect_inventory(path: impl AsRef<Path>, limits: Limits) -> Report {
    analyze(path, Mode::Inventory, limits)
}

/// Inspect metadata with default limits, without certifying conformance.
pub fn inspect(path: impl AsRef<Path>) -> Report {
    analyze(path, Mode::Inspect, Limits::default())
}

fn io_failure(error: std::io::Error) -> Failure {
    Failure::new(Status::OperationalError, "io.failure", error.to_string())
}

fn zip_failure(error: zip::result::ZipError) -> Failure {
    match error {
        zip::result::ZipError::Io(error) => read_failure(error),
        error => Failure::invalid("zip.data", error.to_string()),
    }
}

fn read_failure(error: std::io::Error) -> Failure {
    if matches!(
        error.kind(),
        std::io::ErrorKind::InvalidData
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::UnexpectedEof
    ) {
        Failure::invalid("zip.data", error.to_string())
    } else {
        io_failure(error)
    }
}
