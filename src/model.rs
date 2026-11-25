//! Reports, diagnostics, limits and the error type shared by every operation.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Declare a closed vocabulary of machine-readable report identifiers. Each
/// value serializes as its stable snake_case text and compares with `&str`,
/// so callers can match on variants or on the documented identifiers.
macro_rules! report_vocabulary {
    ($(#[$meta:meta])* $name:ident { $($(#[$variant_meta:meta])* $variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
        #[non_exhaustive]
        pub enum $name {
            $($(#[$variant_meta])* #[serde(rename = $text)] $variant),+
        }
        impl $name {
            /// The stable identifier used in machine-readable reports.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.as_str() == *other
            }
        }
        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.as_str() == other
            }
        }
    };
}
pub(crate) use report_vocabulary;

report_vocabulary! {
    /// The kind of analysis a report describes.
    Mode {
        /// Full verification of the common machine-checkable rules.
        Verify => "verify",
        /// Metadata inspection without a conformance claim.
        Inspect => "inspect",
        /// Inspection of unsigned inventory claims without reading payload bytes.
        Inventory => "inventory",
    }
}

report_vocabulary! {
    /// The overall outcome of an analysis or operation.
    Status {
        /// Every performed check passed.
        Passed => "passed",
        /// Metadata was inspected; conformance is not certified.
        Inspected => "inspected",
        /// A rule is violated or data is damaged.
        Invalid => "invalid",
        /// A version, extension or capability is not implemented by this reader.
        Unsupported => "unsupported",
        /// A reader-owned resource limit or deadline was reached.
        ResourceLimit => "resource_limit",
        /// The operation could not be completed, for example after an I/O error.
        OperationalError => "operational_error",
        /// A live directory is active or was interrupted; it is neither valid nor invalid.
        NotQuiescent => "not_quiescent",
    }
}

impl Status {
    /// The conventional process exit status for this outcome.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Passed | Self::Inspected => 0,
            Self::Invalid => 1,
            Self::Unsupported => 3,
            Self::ResourceLimit => 4,
            Self::OperationalError => 5,
            Self::NotQuiescent => 6,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Passed | Self::Inspected => 0,
            Self::Unsupported => 1,
            Self::ResourceLimit => 2,
            Self::Invalid => 3,
            Self::OperationalError => 4,
            Self::NotQuiescent => 5,
        }
    }
}

report_vocabulary! {
    /// What a report's status covers.
    Scope {
        /// Complete common machine checks over every byte.
        CommonMachineChecks => "common_machine_checks",
        /// Structure and declared sizes of the unsigned inventory only.
        InventoryClaims => "inventory_claims",
        /// Metadata inspection without verification.
        Inspection => "inspection",
        /// Common checks in which application-trusted digests replaced some byte reads.
        CommonChecksWithTrustedResources => "common_checks_with_trusted_resources",
        /// Creation of a delta transfer between two editions.
        DeltaCreation => "delta_creation",
        /// Verification of a delta against its exact base edition.
        DeltaAgainstBase => "delta_against_base",
        /// A pack, unpack, delta or merge operation that failed before analysis.
        Transfer => "transfer",
    }
}

report_vocabulary! {
    /// Whether application-profile semantics were validated.
    ApplicationValidation {
        /// No registered application profile validated the data.
        NotPerformed => "not_performed",
        /// A registered application profile accepted the data.
        Passed => "passed",
        /// A registered application profile rejected the data.
        Failed => "failed",
        /// Application policy required a profile verifier that is not registered.
        Unsupported => "unsupported",
    }
}

report_vocabulary! {
    /// The weight of one diagnostic.
    Severity {
        /// The finding determines the report status.
        Error => "error",
        /// The operation succeeded with a caveat, such as uncertain durability.
        Warning => "warning",
        /// Context that does not change the status.
        Info => "info",
    }
}

report_vocabulary! {
    /// The type of a container entry.
    EntryKind {
        /// A regular file.
        File => "file",
        /// A directory.
        Directory => "directory",
    }
}

report_vocabulary! {
    /// How an entry's bytes are stored in its container.
    Compression {
        /// ZIP STORE.
        Store => "store",
        /// ZIP DEFLATE.
        Deflate => "deflate",
        /// A directory package or directory entry, without ZIP compression.
        None => "none",
    }
}

/// One finding or note in a report.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct Diagnostic {
    /// Whether the finding affects the status.
    pub severity: Severity,
    /// Stable dotted identifier, such as `bundle.file`.
    pub code: String,
    /// Package-relative path the finding concerns, when there is one.
    pub path: Option<String>,
    /// Human-readable explanation in English.
    pub message: String,
}

impl Diagnostic {
    /// A diagnostic without a path.
    pub fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            severity,
            code: code.into(),
            path: None,
            message: message.into(),
        }
    }
}

/// The error type of every fallible operation, exported as `darkbox::Error`.
#[derive(Debug)]
#[non_exhaustive]
pub struct Failure {
    /// The outcome class this failure produces in a report.
    pub status: Status,
    /// Stable dotted identifier, such as `zip.crc`.
    pub code: &'static str,
    /// Package-relative path the failure concerns, when there is one.
    pub path: Option<String>,
    /// Human-readable explanation in English.
    pub message: String,
    /// Full checked candidate/opening report when verification blocks an operation.
    /// No secret keys or decrypted bytes are added by built-in checks.
    pub report: Option<Box<Report>>,
}

impl Failure {
    /// A failure with an explicit outcome class.
    pub fn new(status: Status, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            path: None,
            message: message.into(),
            report: None,
        }
    }

    /// Attach the package-relative path this failure concerns.
    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Attach the complete report that explains this failure.
    pub fn with_report(mut self, report: Report) -> Self {
        self.report = Some(Box::new(report));
        self
    }

    /// A rule violation or damaged data.
    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Status::Invalid, code, message)
    }

    /// A reader-owned resource limit or deadline was reached. Raise the
    /// matching field of [`Limits`] or start from [`Limits::large`].
    pub fn limit(message: impl Into<String>) -> Self {
        Self::new(Status::ResourceLimit, LIMIT_CODE, message)
    }
}

/// Diagnostic code of every resource-limit failure.
pub(crate) const LIMIT_CODE: &str = "limits.exceeded";

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Failure {}

pub(crate) type Result<T> = std::result::Result<T, Failure>;

/// Reader-owned bounds on input sizes, counts and processing time. They are
/// external policy: nothing inside a package can raise them.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct Limits {
    /// Largest accepted container file, in bytes.
    pub max_archive_bytes: u64,
    /// Largest accepted uncompressed entry, in bytes.
    pub max_entry_bytes: u64,
    /// Largest accepted sum of uncompressed entries, in bytes.
    pub max_total_bytes: u64,
    /// Largest accepted number of entries.
    pub max_entries: usize,
    /// Largest accepted manifest or documentation file held in memory, in bytes.
    pub max_metadata_bytes: u64,
    /// Deadline for one operation, in seconds.
    pub timeout_seconds: u64,
    /// Private staging storage. None uses the operating-system temporary directory.
    pub staging_directory: Option<PathBuf>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 512 * 1024 * 1024,
            max_entry_bytes: 256 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            max_entries: 10_000,
            max_metadata_bytes: 4 * 1024 * 1024,
            timeout_seconds: 60,
            staging_directory: None,
        }
    }
}

impl Limits {
    /// Reader-owned policy for media libraries, including individual 4 GiB videos.
    pub fn large() -> Self {
        Self {
            max_archive_bytes: 1024 * 1024 * 1024 * 1024,
            max_entry_bytes: 64 * 1024 * 1024 * 1024,
            max_total_bytes: 2 * 1024 * 1024 * 1024 * 1024,
            max_entries: 1_000_000,
            max_metadata_bytes: 64 * 1024 * 1024,
            timeout_seconds: 3600,
            staging_directory: None,
        }
    }
    /// Set the largest accepted container file, in bytes.
    pub fn with_max_archive_bytes(mut self, bytes: u64) -> Self {
        self.max_archive_bytes = bytes;
        self
    }
    /// Set the largest accepted uncompressed entry, in bytes.
    pub fn with_max_entry_bytes(mut self, bytes: u64) -> Self {
        self.max_entry_bytes = bytes;
        self
    }
    /// Set the largest accepted sum of uncompressed entries, in bytes.
    pub fn with_max_total_bytes(mut self, bytes: u64) -> Self {
        self.max_total_bytes = bytes;
        self
    }
    /// Set the largest accepted number of entries.
    pub fn with_max_entries(mut self, entries: usize) -> Self {
        self.max_entries = entries;
        self
    }
    /// Set the largest accepted in-memory metadata file, in bytes.
    pub fn with_max_metadata_bytes(mut self, bytes: u64) -> Self {
        self.max_metadata_bytes = bytes;
        self
    }
    /// Set the deadline for one operation, in seconds.
    pub fn with_timeout_seconds(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }
    /// Use private staging storage instead of the system temporary directory.
    pub fn with_staging_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.staging_directory = Some(directory.into());
        self
    }
    pub(crate) fn tempdir(&self, prefix: &str) -> Result<tempfile::TempDir> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix);
        match &self.staging_directory {
            Some(parent) => builder.tempdir_in(parent),
            None => builder.tempdir(),
        }
        .map_err(crate::io_failure)
    }
    pub(crate) fn tempfile(&self, prefix: &str) -> Result<tempfile::NamedTempFile> {
        let mut builder = tempfile::Builder::new();
        builder.prefix(prefix);
        match &self.staging_directory {
            Some(parent) => builder.tempfile_in(parent),
            None => builder.tempfile(),
        }
        .map_err(crate::io_failure)
    }
    /// Every bound must be positive.
    pub(crate) fn check(&self) -> Result<()> {
        if self.max_entries == 0
            || self.max_entry_bytes == 0
            || self.max_archive_bytes == 0
            || self.max_total_bytes == 0
            || self.max_metadata_bytes == 0
            || self.timeout_seconds == 0
        {
            return Err(Failure::limit("Resource limits must be positive"));
        }
        Ok(())
    }
}

/// One entry of the analyzed container.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct EntryInfo {
    /// Package-relative path; directories end in `/`.
    pub path: String,
    /// File or directory.
    pub kind: EntryKind,
    /// Stored size in the container, in bytes.
    pub compressed_bytes: u64,
    /// Uncompressed size, in bytes.
    pub bytes: u64,
    /// How the bytes are stored.
    pub compression: Compression,
    /// Whether the ZIP CRC was checked against the actual bytes.
    pub crc_verified: bool,
}

/// What was learned about one declared SQLite database.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct DatabaseInfo {
    /// Package-relative path of the database.
    pub path: String,
    /// SQLite `PRAGMA user_version`.
    pub user_version: i64,
    /// SQLite journal mode of the snapshot.
    pub journal_mode: String,
    /// Logical application tables found in the database.
    pub tables: Vec<String>,
    /// Whether `PRAGMA integrity_check` ran and passed.
    pub integrity_checked: bool,
    /// Whether `PRAGMA foreign_key_check` ran and passed.
    pub foreign_keys_checked: bool,
}

/// The machine-readable result of one analysis or operation. Its JSON form is
/// versioned by `report_version`.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct Report {
    /// Version of this report's JSON shape.
    pub report_version: u32,
    /// The analysis that produced this report.
    pub command: Mode,
    /// The analyzed path, as given.
    pub file: String,
    /// The overall outcome.
    pub status: Status,
    /// What the status covers.
    pub scope: Scope,
    /// Whether application-profile semantics were validated.
    pub application_validation: ApplicationValidation,
    /// Common specification versions this build supports.
    pub supported_versions: Vec<&'static str>,
    /// The parsed manifest, when one could be read.
    pub manifest: Option<Value>,
    /// Every container entry.
    pub entries: Vec<EntryInfo>,
    /// Resources whose complete hashes were supplied by application policy.
    pub trusted_resources: Vec<crate::extensions::EntryDigest>,
    /// Declared databases that could be examined.
    pub databases: Vec<DatabaseInfo>,
    /// Result of the protection extension, when it is declared and was checked.
    pub protection: Option<crate::protection::ProtectionReport>,
    /// Identifiers of the checks that passed, in the order they completed.
    pub checks: Vec<&'static str>,
    /// Findings and notes.
    pub diagnostics: Vec<Diagnostic>,
    /// The limits in force.
    pub limits: Limits,
}

/// Version of the JSON shape of [`Report`].
pub(crate) const REPORT_VERSION: u32 = 2;

impl Report {
    /// An empty report for one analysis, before any check has run.
    pub(crate) fn new(command: Mode, file: impl Into<String>, limits: Limits) -> Self {
        Self {
            report_version: REPORT_VERSION,
            command,
            file: file.into(),
            status: if command == Mode::Verify {
                Status::Passed
            } else {
                Status::Inspected
            },
            scope: match command {
                Mode::Verify => Scope::CommonMachineChecks,
                Mode::Inventory => Scope::InventoryClaims,
                Mode::Inspect => Scope::Inspection,
            },
            application_validation: ApplicationValidation::NotPerformed,
            supported_versions: crate::supported_versions()
                .map(|version| version.version)
                .collect(),
            manifest: None,
            entries: Vec::new(),
            trusted_resources: Vec::new(),
            databases: Vec::new(),
            protection: None,
            checks: Vec::new(),
            diagnostics: Vec::new(),
            limits,
        }
    }

    /// The report of an operation that failed. A failure that carries its own
    /// report yields that report; otherwise the failure becomes the only
    /// diagnostic of a new report with scope [`Scope::Transfer`].
    pub fn from_failure(
        command: Mode,
        file: impl Into<String>,
        limits: Limits,
        mut failure: Failure,
    ) -> Self {
        if let Some(report) = failure.report.take() {
            return *report;
        }
        let mut report = Self::new(command, file, limits);
        report.scope = Scope::Transfer;
        report.status = failure.status;
        report.record(failure);
        report
    }

    /// Record an error and raise the status to the more severe outcome.
    pub fn record(&mut self, error: Failure) {
        if error.status.rank() > self.status.rank() {
            self.status = error.status;
        }
        self.diagnostics.push(Diagnostic {
            severity: Severity::Error,
            code: error.code.into(),
            path: error.path,
            message: error.message,
        });
    }

    /// Record context that does not change the status.
    pub fn note(&mut self, code: &str, message: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::new(Severity::Info, code, message));
    }

    /// Record a caveat about a completed operation.
    #[cfg_attr(not(unix), allow(dead_code))] // Only directory flushing warns so far.
    pub(crate) fn warn(&mut self, code: &str, message: impl Into<String>) {
        self.diagnostics
            .push(Diagnostic::new(Severity::Warning, code, message));
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Application {
    pub id: String,
    pub format_version: String,
    pub profile_path: String,
}

#[derive(Clone, Deserialize)]
pub(crate) struct Folder {
    pub path: String,
}

#[derive(Clone, Deserialize)]
pub(crate) struct Table {
    pub name: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Database {
    pub path: String,
    pub tables: Vec<Table>,
    pub user_version: Option<i64>,
}

#[derive(Clone, Deserialize)]
pub(crate) struct Extension {
    pub required: bool,
    pub version: String,
}

#[derive(Clone, Deserialize)]
pub(crate) struct Manifest {
    pub application: Application,
    pub folders: Vec<Folder>,
    pub databases: Vec<Database>,
    #[serde(default)]
    pub extensions: BTreeMap<String, Extension>,
}
