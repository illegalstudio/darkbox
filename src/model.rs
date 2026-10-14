use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Verify,
    Inspect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Inspected,
    Invalid,
    Unsupported,
    ResourceLimit,
    OperationalError,
}

impl Status {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Passed | Self::Inspected => 0,
            Self::Invalid => 1,
            Self::Unsupported => 3,
            Self::ResourceLimit => 4,
            Self::OperationalError => 5,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Passed | Self::Inspected => 0,
            Self::Unsupported => 1,
            Self::ResourceLimit => 2,
            Self::Invalid => 3,
            Self::OperationalError => 4,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub severity: &'static str,
    pub code: String,
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug)]
pub struct Failure {
    pub status: Status,
    pub code: &'static str,
    pub path: Option<String>,
    pub message: String,
}

impl Failure {
    pub fn new(status: Status, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            path: None,
            message: message.into(),
        }
    }

    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(Status::Invalid, code, message)
    }

    pub fn limit(message: impl Into<String>) -> Self {
        Self::new(Status::ResourceLimit, "limits.exceeded", message)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Failure {}

pub(crate) type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub max_archive_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_entries: usize,
    pub max_metadata_bytes: u64,
    pub timeout_seconds: u64,
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
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EntryInfo {
    pub path: String,
    pub kind: &'static str,
    pub compressed_bytes: u64,
    pub bytes: u64,
    pub compression: &'static str,
    pub crc_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct DatabaseInfo {
    pub path: String,
    pub user_version: i64,
    pub journal_mode: String,
    pub tables: Vec<String>,
    pub integrity_checked: bool,
    pub foreign_keys_checked: bool,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub report_version: u32,
    pub cli_version: &'static str,
    pub command: Mode,
    pub file: String,
    pub status: Status,
    pub scope: &'static str,
    pub application_validation: &'static str,
    pub supported_versions: Vec<&'static str>,
    pub manifest: Option<Value>,
    pub entries: Vec<EntryInfo>,
    pub databases: Vec<DatabaseInfo>,
    pub protection: Option<crate::protection::ProtectionReport>,
    pub checks: Vec<&'static str>,
    pub diagnostics: Vec<Diagnostic>,
    pub limits: Limits,
}

impl Report {
    pub fn record(&mut self, error: Failure) {
        if error.status.rank() > self.status.rank() {
            self.status = error.status;
        }
        self.diagnostics.push(Diagnostic {
            severity: "error",
            code: error.code.into(),
            path: error.path,
            message: error.message,
        });
    }

    pub fn note(&mut self, code: &str, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            severity: "info",
            code: code.into(),
            path: None,
            message: message.into(),
        });
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
