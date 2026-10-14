//! Offline Darkbox container SDK: verified snapshots, resource streams, isolated
//! SQLite/resource edits and validated atomic publication. Application-profile
//! semantics are reported separately and validated only by registered application code.

mod container;
mod creation;
pub mod extensions;
mod json;
pub mod manifest;
mod model;
mod package;
mod paths;
pub mod profiles;
pub mod protection;
mod sqlite;
mod versions;
mod writer;

pub use creation::PackageWriter;
pub use extensions::{ExtensionRegistry, ExtensionVerifier, VerificationOptions};
pub use manifest::ManifestBuilder;
pub use model::{
    DatabaseInfo, Diagnostic, EntryInfo, Failure as Error, Limits, Mode, Report, Status,
};
use model::{Failure, Manifest, Result};
pub use package::{
    DatabaseReader, DiagnosticPackage, Package, PackageEditor, ResourceReader, ValueAddress,
};
pub use profiles::{ApplicationProfile, ProfileContext, ProfileRegistry};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};
use versions::{CATALOG_PATH, Catalog, RuleSet, VersionSpec};
pub use writer::{PackageUpdate, open, save};
use zip::{CompressionMethod, ZipArchive};
/// Use the same SQLite and JSON types as the SDK without dependency-version ambiguity.
pub use {rusqlite, serde_json, zeroize};

pub fn supported_versions() -> impl Iterator<Item = (&'static str, bool)> {
    versions::VERSIONS
        .iter()
        .map(|spec| (spec.version, spec.released))
}

pub fn analyze(path: impl AsRef<Path>, mode: Mode, limits: Limits) -> Report {
    analyze_with(path, mode, limits, &VerificationOptions::default())
}

pub fn analyze_with(
    path: impl AsRef<Path>,
    mode: Mode,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Report {
    analyze_captured(path.as_ref(), mode, limits, options, false).0
}

pub(crate) struct Staging {
    pub _directory: tempfile::TempDir,
    pub files: BTreeMap<String, std::path::PathBuf>,
    pub digests: BTreeMap<String, extensions::EntryDigest>,
}

pub(crate) fn analyze_captured(
    path: &Path,
    mode: Mode,
    limits: Limits,
    options: &VerificationOptions<'_>,
    capture: bool,
) -> (Report, Option<Staging>) {
    let mut report = Report {
        report_version: 2,
        cli_version: env!("CARGO_PKG_VERSION"),
        command: mode,
        file: path.display().to_string(),
        status: if mode == Mode::Verify {
            Status::Passed
        } else {
            Status::Inspected
        },
        scope: if mode == Mode::Verify {
            "common_machine_checks"
        } else {
            "inspection"
        },
        application_validation: "not_performed",
        supported_versions: supported_versions().map(|(version, _)| version).collect(),
        manifest: None,
        entries: Vec::new(),
        databases: Vec::new(),
        protection: None,
        checks: Vec::new(),
        diagnostics: Vec::new(),
        limits,
    };
    let mut staging = None;
    if let Err(error) = run(path, mode, &mut report, options, capture, &mut staging) {
        report.record(error);
    }
    if report.protection.is_none()
        && report
            .manifest
            .as_ref()
            .is_some_and(|manifest| manifest["extensions"].get(protection::NAMESPACE).is_some())
    {
        report.note("protection.not_checked", "Protection signature, inventory and encrypted content authentication were not checked; this report does not authorize ordinary protected opening or saving");
    }
    if report.application_validation == "not_performed" {
        report.note("profile.not_validated", "Application data semantics and the accuracy or completeness of profile documentation have not been validated");
    }
    (report, staging)
}

pub fn verify(path: impl AsRef<Path>) -> Report {
    analyze(path, Mode::Verify, Limits::default())
}

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

fn run(
    path: &Path,
    mode: Mode,
    report: &mut Report,
    options: &VerificationOptions<'_>,
    capture_all: bool,
    captured: &mut Option<Staging>,
) -> Result<()> {
    let limits = report.limits.clone();
    if limits.max_entries == 0
        || limits.max_entry_bytes == 0
        || limits.max_archive_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_metadata_bytes == 0
        || limits.timeout_seconds == 0
    {
        return Err(Failure::limit("Resource limits must be positive"));
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_seconds))
        .ok_or_else(|| Failure::limit("Processing timeout is too large"))?;
    let mut source = File::open(path).map_err(io_failure)?;
    let metadata = source.metadata().map_err(io_failure)?;
    if !metadata.is_file() {
        return Err(Failure::new(
            Status::OperationalError,
            "io.file_type",
            "Input must be a regular file",
        ));
    }
    if metadata.len() > limits.max_archive_bytes {
        return Err(Failure::limit(
            "Compressed archive exceeds the configured byte limit",
        ));
    }
    let directory = container::preflight(&mut source, metadata.len(), &limits, deadline)?;
    let mut archive = ZipArchive::new(source).map_err(zip_failure)?;
    if archive.len() != directory.names.len() {
        return Err(Failure::invalid(
            "zip.directory",
            "ZIP reader and central entry inventory disagree",
        ));
    }
    let mut total_declared = 0u64;
    for (index, name) in directory.names.iter().enumerate() {
        container::check_deadline(deadline)?;
        let file = archive.by_index(index).map_err(zip_failure)?;
        if file.name_raw() != name.as_bytes() {
            return Err(Failure::invalid(
                "zip.directory",
                "ZIP reader and authoritative entry names disagree",
            ));
        }
        let directory_entry = name.ends_with('/');
        if file.is_symlink()
            || file.unix_mode().is_some_and(|mode| {
                let kind = mode & 0o170000;
                kind != 0 && kind != if directory_entry { 0o040000 } else { 0o100000 }
            })
        {
            return Err(Failure::invalid(
                "zip.entry_type",
                "Only regular files and directories are allowed",
            )
            .at(name));
        }
        if directory_entry && file.size() != 0 {
            return Err(Failure::invalid(
                "zip.directory_data",
                "Directory entries cannot contain file data",
            )
            .at(name));
        }
        if file.size() > limits.max_entry_bytes {
            return Err(
                Failure::limit("Uncompressed entry exceeds the configured byte limit").at(name),
            );
        }
        total_declared = total_declared
            .checked_add(file.size())
            .filter(|sum| *sum <= limits.max_total_bytes)
            .ok_or_else(|| {
                Failure::limit("Total uncompressed size exceeds the configured limit")
            })?;
        report.entries.push(EntryInfo {
            path: name.clone(),
            kind: if directory_entry { "directory" } else { "file" },
            compressed_bytes: file.compressed_size(),
            bytes: file.size(),
            compression: match file.compression() {
                CompressionMethod::Stored => "store",
                CompressionMethod::Deflated => "deflate",
                _ => {
                    return Err(Failure::invalid(
                        "zip.compression",
                        "Unsupported compression",
                    ));
                }
            },
            crc_verified: false,
        });
    }
    report.checks.push("zip.structure");
    let manifest_index = directory
        .names
        .iter()
        .position(|name| name == "manifest.json")
        .ok_or_else(|| {
            Failure::invalid("manifest.missing", "Required root manifest.json is missing")
        })?;
    let manifest_bytes = {
        let mut file = archive.by_index(manifest_index).map_err(zip_failure)?;
        if file.size() > limits.max_metadata_bytes {
            return Err(Failure::limit(
                "Manifest exceeds the configured metadata limit",
            ));
        }
        read_metadata(&mut file, &limits, deadline)?
    };
    let value = json::parse(&manifest_bytes)?;
    report.manifest = Some(value.clone());
    if options.require_protection && value["extensions"].get(protection::NAMESPACE).is_none() {
        report.record(Failure::invalid(
            "protection.missing",
            "Application policy requires the protection extension",
        ));
    }
    report.checks.push("manifest.json");
    let id = value
        .pointer("/darkbox/id")
        .and_then(|value| value.as_str());
    let version = value
        .pointer("/darkbox/version")
        .and_then(|value| value.as_str());
    if id.is_none() || version.is_none() {
        return Err(Failure::invalid(
            "manifest.identity",
            "The manifest must declare string darkbox.id and darkbox.version fields",
        ));
    }
    let spec = if id == Some("darkbox") {
        version.and_then(|version| versions::find_in(versions::VERSIONS, version))
    } else {
        None
    };
    if spec.is_none() {
        let message = format!(
            "Unsupported specification: {} {}",
            id.unwrap_or("missing identifier"),
            version.unwrap_or("missing version")
        );
        if mode == Mode::Verify {
            report.record(Failure::new(
                Status::Unsupported,
                "version.unsupported",
                message,
            ));
        } else {
            report.note("version.unsupported", message);
        }
    }
    let mut common = mode == Mode::Verify && spec.is_some();
    if common {
        let spec = spec.unwrap();
        match spec.rules {
            RuleSet::V1 => {}
        }
        let schema: serde_json::Value = serde_json::from_str(spec.schema).map_err(|error| {
            Failure::new(
                Status::OperationalError,
                "reference.schema",
                error.to_string(),
            )
        })?;
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|error| {
                Failure::new(
                    Status::OperationalError,
                    "reference.schema",
                    error.to_string(),
                )
            })?;
        let mut errors = validator.iter_errors(&value).peekable();
        if errors.peek().is_some() {
            for error in errors.take(50) {
                report.record(Failure::invalid(
                    "manifest.schema",
                    format!(
                        "{}: {}",
                        error.instance_path(),
                        error.to_string().chars().take(500).collect::<String>()
                    ),
                ));
            }
            common = false;
        } else {
            report.checks.push("manifest.schema");
        }
    }
    let manifest: Option<Manifest> = serde_json::from_value(value).ok();
    if common && manifest.is_none() {
        return Err(Failure::invalid(
            "manifest.structure",
            "Manifest inventory is unreadable",
        ));
    }
    if common {
        if let Err(error) = inventory(manifest.as_ref().unwrap(), &directory.nodes, spec.unwrap()) {
            report.record(error);
            common = false;
        } else {
            report.checks.push("inventory");
        }
    }
    let temporary = tempfile::Builder::new()
        .prefix("darkbox-")
        .tempdir()
        .map_err(io_failure)?;
    let databases: BTreeMap<_, _> = manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .databases
                .iter()
                .enumerate()
                .map(|(index, db)| (db.path.as_str(), (index, db)))
                .collect()
        })
        .unwrap_or_default();
    let mut staged = BTreeMap::new();
    let mut signatures = BTreeMap::new();
    let mut digests = BTreeMap::new();
    let mut total_actual = 0u64;
    let mut canonical_ok = common;
    let mut profile_ok = common;
    for (index, name) in directory.names.iter().enumerate() {
        container::check_deadline(deadline)?;
        let mut file = archive.by_index(index).map_err(zip_failure)?;
        let expected =
            spec.and_then(|spec| spec.files.iter().find(|expected| expected.path == name));
        let catalog = name == CATALOG_PATH;
        let profile = manifest
            .as_ref()
            .is_some_and(|manifest| manifest.application.profile_path == *name);
        let capture =
            name == "manifest.json" || profile || (common && (expected.is_some() || catalog));
        let destination = if !name.ends_with('/')
            && (capture_all || common || databases.contains_key(name.as_str()))
        {
            let destination = temporary.path().join(format!("entry-{index}"));
            let handle = File::create(&destination).map_err(io_failure)?;
            staged.insert(name.clone(), destination);
            Some(handle)
        } else {
            None
        };
        let expected_crc = file.crc32();
        let expected_size = file.size();
        let scan = stream(
            &mut file,
            destination,
            capture,
            &limits,
            &mut total_actual,
            deadline,
        )
        .map_err(|error| error.at(name))?;
        if scan.size != expected_size || scan.crc != expected_crc {
            return Err(Failure::invalid(
                "zip.crc",
                "ZIP entry size or CRC does not match its data",
            )
            .at(name));
        }
        report.entries[index].crc_verified = true;
        if name == "manifest.json" && scan.bytes != manifest_bytes {
            return Err(Failure::new(
                Status::OperationalError,
                "io.changed",
                "The manifest changed during analysis",
            ));
        }
        if !name.ends_with('/') {
            signatures.insert(name.clone(), scan.prefix);
            digests.insert(
                name.clone(),
                extensions::EntryDigest {
                    path: name.clone(),
                    size: scan.size,
                    sha256: scan.sha256.clone(),
                },
            );
        }
        if common {
            if let Some(expected) = expected
                && (scan.size != expected.bytes.len() as u64
                    || scan.sha256 != expected.sha256
                    || scan.bytes != expected.bytes)
            {
                canonical_ok = false;
                report.record(
                    Failure::invalid(
                        "bundle.file",
                        "Canonical file differs from the official version-specific reference",
                    )
                    .at(name),
                );
            }
            if catalog && scan.bytes != spec.unwrap().catalog {
                canonical_ok = false;
                report.record(
                    Failure::invalid(
                        "bundle.catalog",
                        "Bundle catalog differs from the trusted embedded catalog",
                    )
                    .at(name),
                );
            }
            if profile
                && (scan.bytes.starts_with(&[0xef, 0xbb, 0xbf])
                    || std::str::from_utf8(&scan.bytes).map_or(true, |text| text.trim().is_empty()))
            {
                profile_ok = false;
                report.record(
                    Failure::invalid(
                        "profile.encoding",
                        "Profile documentation must be readable UTF-8 without a BOM",
                    )
                    .at(name),
                );
            }
        }
    }
    report.checks.push("zip.crc");
    if canonical_ok {
        report.checks.push("bundle.canonical");
    }
    if common {
        for (name, prefix) in &signatures {
            if prefix.starts_with(b"SQLite format 3\0") && !databases.contains_key(name.as_str()) {
                report.record(
                    Failure::invalid(
                        "sqlite.undeclared",
                        "Standalone SQLite database is absent from the manifest inventory",
                    )
                    .at(name),
                );
            }
            let associated = databases.keys().any(|base| {
                name == &format!("{base}-wal")
                    || name == &format!("{base}-shm")
                    || name == &format!("{base}-journal")
                    || name.starts_with(&format!("{base}-mj"))
            });
            let journal_magic = name.ends_with("-journal")
                && prefix.starts_with(&[0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]);
            let wal_magic = name.ends_with("-wal")
                && (prefix.starts_with(&[0x37, 0x7f, 0x06, 0x82])
                    || prefix.starts_with(&[0x37, 0x7f, 0x06, 0x83]));
            if associated || journal_magic || wal_magic {
                report.record(
                    Failure::invalid(
                        "sqlite.sidecar",
                        "SQLite journal, WAL and shared-memory sidecars are forbidden",
                    )
                    .at(name),
                );
            }
        }
        if profile_ok {
            report.checks.push("profile.presence_and_encoding");
        }
        let extension_manifest = report.manifest.as_ref().unwrap().clone();
        let context = extensions::ExtensionContext {
            manifest: &extension_manifest,
            manifest_bytes: &manifest_bytes,
            inventory: &digests,
            options,
            limits: &limits,
            deadline,
            staged: &staged,
        };
        for (namespace, extension) in &manifest.as_ref().unwrap().extensions {
            if namespace == protection::NAMESPACE && !extension.required {
                report.record(Failure::invalid(
                    "protection.required",
                    "Protection must be a required extension",
                ));
                continue;
            }
            if let Some(verifier) = options.extensions.get(namespace, &extension.version) {
                if let Err(error) = verifier.verify(&context, report) {
                    report.record(error);
                }
            } else if extension.required {
                report.record(Failure::new(
                    Status::Unsupported,
                    if namespace == protection::NAMESPACE
                        && extension.version != protection::VERSION
                    {
                        "protection.version"
                    } else {
                        "extension.required"
                    },
                    format!("Required extension is not implemented: {namespace}"),
                ));
            } else {
                report.note(
                    "extension.optional",
                    format!("Optional extension semantics were not checked: {namespace}"),
                );
            }
        }
    }
    let mut sqlite_ok = common;
    for (name, (_, db)) in &databases {
        if let Some(path) = staged.get(*name) {
            match sqlite::examine(
                path,
                db,
                if common { Mode::Verify } else { Mode::Inspect },
                &limits,
                deadline,
            ) {
                Ok(info) => report.databases.push(info),
                Err(error) => {
                    sqlite_ok = false;
                    report.record(error.at(*name));
                }
            }
        }
    }
    if sqlite_ok {
        report.checks.push("sqlite.integrity_and_inventory");
    }
    if mode == Mode::Inspect {
        report.checks.push("sqlite.metadata");
    }
    if let Some(manifest) = manifest {
        report.note(
            "profile.identity",
            format!(
                "Declared profile: {} data format {}",
                manifest.application.id, manifest.application.format_version
            ),
        );
    }
    if common && report.status == Status::Passed {
        let metadata = report.manifest.as_ref().unwrap().clone();
        let context = profiles::ProfileContext {
            manifest: &metadata,
            inventory: &digests,
            limits: &limits,
            deadline,
            options,
            staged: &staged,
        };
        if let Some(profile) = options.profiles.get(
            metadata["application"]["id"].as_str().unwrap(),
            metadata["application"]["formatVersion"].as_str().unwrap(),
        ) {
            match profile.validate(&context) {
                Ok(()) => {
                    report.application_validation = "passed";
                    report.checks.push("profile.application");
                }
                Err(mut error) => {
                    report.application_validation = "failed";
                    if matches!(error.status, Status::Passed | Status::Inspected) {
                        error.status = Status::Invalid;
                    }
                    report.record(error);
                }
            }
        } else if options.require_profile {
            report.application_validation = "unsupported";
            report.record(Failure::new(
                Status::Unsupported,
                "profile.unsupported",
                "Application policy requires a registered verifier for this exact profile version",
            ));
        }
    }
    container::check_deadline(deadline)?;
    if capture_all {
        *captured = Some(Staging {
            _directory: temporary,
            files: staged,
            digests,
        });
    }
    Ok(())
}

fn read_metadata(reader: &mut impl Read, limits: &Limits, deadline: Instant) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 65_536];
    loop {
        container::check_deadline(deadline)?;
        let count = reader.read(&mut buffer).map_err(read_failure)?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > limits.max_metadata_bytes {
            return Err(Failure::limit("Metadata exceeds the configured byte limit"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

struct Scan {
    size: u64,
    crc: u32,
    sha256: String,
    prefix: Vec<u8>,
    bytes: Vec<u8>,
}

fn stream(
    reader: &mut impl Read,
    mut destination: Option<File>,
    capture: bool,
    limits: &Limits,
    total: &mut u64,
    deadline: Instant,
) -> Result<Scan> {
    let mut size = 0u64;
    let mut crc = crc32fast::Hasher::new();
    let mut sha = Sha256::new();
    let mut bytes = Vec::new();
    let mut prefix = Vec::new();
    let mut buffer = [0; 65_536];
    loop {
        container::check_deadline(deadline)?;
        let count = reader.read(&mut buffer).map_err(read_failure)?;
        if count == 0 {
            break;
        }
        let data = &buffer[..count];
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= limits.max_entry_bytes)
            .ok_or_else(|| Failure::limit("Actual entry data exceeds the configured byte limit"))?;
        *total = total
            .checked_add(count as u64)
            .filter(|total| *total <= limits.max_total_bytes)
            .ok_or_else(|| Failure::limit("Actual total data exceeds the configured byte limit"))?;
        crc.update(data);
        sha.update(data);
        prefix.extend_from_slice(&data[..data.len().min(16 - prefix.len())]);
        if capture {
            if size > limits.max_metadata_bytes {
                return Err(Failure::limit(
                    "Documentation exceeds the configured metadata limit",
                ));
            }
            bytes.extend_from_slice(data);
        }
        if let Some(destination) = &mut destination {
            destination.write_all(data).map_err(io_failure)?;
        }
    }
    Ok(Scan {
        size,
        crc: crc.finalize(),
        sha256: format!("{:x}", sha.finalize()),
        prefix,
        bytes,
    })
}

fn inventory(manifest: &Manifest, nodes: &paths::Nodes, spec: &VersionSpec) -> Result<()> {
    let mut declared = paths::Nodes::new();
    let mut folders = BTreeSet::new();
    for folder in &manifest.folders {
        paths::insert(&mut declared, &folder.path, true)?;
        folders.insert(folder.path.as_str());
        let node = nodes.get(&folder.path.to_ascii_lowercase());
        if !node.is_some_and(|node| node.directory && node.path == folder.path) {
            return Err(Failure::invalid(
                "folder.missing",
                "Declared folder is missing or is not a directory",
            )
            .at(&folder.path));
        }
    }
    let canonical: BTreeSet<_> = spec
        .files
        .iter()
        .map(|file| file.path)
        .chain([CATALOG_PATH])
        .collect();
    for path in &canonical {
        if !nodes
            .get(&path.to_ascii_lowercase())
            .is_some_and(|node| !node.directory && node.path == *path)
        {
            return Err(Failure::invalid(
                "bundle.missing",
                "Canonical file is missing or is not a regular file",
            )
            .at(*path));
        }
    }
    let catalog: Catalog = serde_json::from_slice(spec.catalog).map_err(|error| {
        Failure::new(
            Status::OperationalError,
            "reference.catalog",
            error.to_string(),
        )
    })?;
    let canonical_folders: BTreeSet<_> = catalog.folders.iter().map(String::as_str).collect();
    let mut database_paths = BTreeSet::new();
    for database in &manifest.databases {
        paths::insert(&mut declared, &database.path, false)?;
        if canonical.contains(database.path.as_str())
            || !database_paths.insert(database.path.as_str())
        {
            return Err(Failure::invalid(
                "database.path",
                "Database path collides with metadata or another database",
            )
            .at(&database.path));
        }
        if !nodes
            .get(&database.path.to_ascii_lowercase())
            .is_some_and(|node| !node.directory && node.path == database.path)
        {
            return Err(Failure::invalid(
                "database.missing",
                "Declared database is missing or is not a regular file",
            )
            .at(&database.path));
        }
        let mut tables = BTreeSet::new();
        if database
            .tables
            .iter()
            .any(|table| !tables.insert(table.name.to_ascii_lowercase()))
        {
            return Err(Failure::invalid(
                "database.tables_duplicate",
                "Duplicate SQLite table names",
            )
            .at(&database.path));
        }
    }
    let profile = &manifest.application.profile_path;
    paths::validate(profile)?;
    if canonical.contains(profile.as_str())
        || database_paths.contains(profile.as_str())
        || !nodes
            .get(&profile.to_ascii_lowercase())
            .is_some_and(|node| !node.directory && node.path == *profile)
    {
        return Err(Failure::invalid(
            "profile.missing",
            "Profile document is missing, is not a file or collides with metadata or a database",
        )
        .at(profile));
    }
    for node in nodes.values() {
        if node.directory && !folders.contains(node.path.as_str()) {
            return Err(Failure::invalid(
                "folder.undeclared",
                "Archive directory is absent from the folder inventory",
            )
            .at(&node.path));
        }
        if !node.directory
            && !node.path.contains('/')
            && node.path != "manifest.json"
            && node.path != "README.md"
            && !database_paths.contains(node.path.as_str())
        {
            return Err(Failure::invalid(
                "file.root",
                "Unexpected regular file at the archive root",
            )
            .at(&node.path));
        }
        if (node.path.starts_with("docs/sqlite/") || node.path.starts_with("docs/darkbox/"))
            && !(canonical.contains(node.path.as_str())
                || canonical_folders.contains(node.path.as_str()))
        {
            return Err(Failure::invalid(
                "bundle.extra",
                "Noncanonical resource in a reserved documentation subtree",
            )
            .at(&node.path));
        }
        if let Some(suffix) = node.path.strip_prefix("extensions/") {
            let namespace = suffix.split('/').next().unwrap_or_default();
            if !manifest.extensions.contains_key(namespace)
                || (!node.directory && !suffix.contains('/'))
            {
                return Err(Failure::invalid(
                    "extension.namespace",
                    "Extension resource has no matching namespace descriptor",
                )
                .at(&node.path));
            }
        }
    }
    Ok(())
}
