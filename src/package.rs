//! Immutable verified snapshots and isolated editing sessions.
use crate::{
    Error, Limits, Mode, Report, Status, VerificationOptions,
    extensions::EntryDigest,
    manifest::DatabaseDeclaration,
    protection::{
        self, BlockContext, BlockLocation, DecryptionKeys, ManifestSigner, NonceSequence,
    },
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub(crate) struct Snapshot {
    pub archive: NamedTempFile,
    pub digest: [u8; 32],
    pub staging: crate::Staging,
}

fn deadline(limits: &Limits) -> Result<Instant, Error> {
    if limits.max_archive_bytes == 0
        || limits.max_entry_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_entries == 0
        || limits.max_metadata_bytes == 0
        || limits.timeout_seconds == 0
    {
        return Err(Error::limit("Resource limits must be positive"));
    }
    Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_seconds))
        .ok_or_else(|| Error::limit("Timeout is too large"))
}

pub(crate) fn freeze(
    path: &Path,
    limits: &Limits,
    deadline: Instant,
) -> Result<(NamedTempFile, [u8; 32]), Error> {
    if !std::fs::symlink_metadata(path)
        .map_err(crate::io_failure)?
        .is_file()
    {
        return Err(Error::new(
            Status::OperationalError,
            "package.file_type",
            "Package source must be a regular file, without a symbolic link",
        ));
    }
    let input = File::open(path).map_err(crate::io_failure)?;
    freeze_reader(input, limits, deadline)
}

fn freeze_reader(
    mut input: impl Read,
    limits: &Limits,
    deadline: Instant,
) -> Result<(NamedTempFile, [u8; 32]), Error> {
    let mut output = tempfile::Builder::new()
        .prefix("darkbox-snapshot-")
        .tempfile()
        .map_err(crate::io_failure)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0; 65_536];
    loop {
        crate::container::check_deadline(deadline)?;
        let count = match input.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(crate::io_failure)?,
        };
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= limits.max_archive_bytes)
            .ok_or_else(|| Error::limit("Snapshot exceeds the compressed archive limit"))?;
        output
            .write_all(&buffer[..count])
            .map_err(crate::io_failure)?;
        hash.update(&buffer[..count]);
    }
    output.flush().map_err(crate::io_failure)?;
    Ok((output, hash.finalize().into()))
}

pub(crate) fn destination(path: &Path) -> Result<PathBuf, Error> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::invalid("package.destination", "Destination must name a file"))?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(std::fs::canonicalize(parent)
        .map_err(crate::io_failure)?
        .join(name))
}

#[derive(Clone)]
enum ResourceSource {
    Snapshot {
        _owner: Arc<Snapshot>,
        path: PathBuf,
    },
    Temporary(Arc<NamedTempFile>),
}
impl ResourceSource {
    fn path(&self) -> &Path {
        match self {
            Self::Snapshot { path, .. } => path,
            Self::Temporary(file) => file.path(),
        }
    }
    fn open(&self) -> Result<ResourceReader, Error> {
        Ok(ResourceReader {
            file: File::open(self.path()).map_err(crate::io_failure)?,
            _source: self.clone(),
        })
    }
}

/// Bounded, uncompressed, CRC-checked resource bytes from an immutable snapshot.
/// Owns its storage, so it can outlive the package or editing session.
pub struct ResourceReader {
    file: File,
    _source: ResourceSource,
}
impl Read for ResourceReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}
impl Seek for ResourceReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

/// A read-only SQLite connection kept alive with its isolated backing snapshot.
pub struct DatabaseReader {
    connection: rusqlite::Connection,
    _source: ResourceSource,
    limits: Limits,
}

/// Exact, stable application address of a protected SQLite value.
#[derive(Clone, Copy, Debug)]
pub struct ValueAddress<'a> {
    pub database: &'a str,
    pub table: &'a str,
    pub column: &'a str,
    pub record_id: &'a str,
}

impl<'a> ValueAddress<'a> {
    pub const fn new(
        database: &'a str,
        table: &'a str,
        column: &'a str,
        record_id: &'a str,
    ) -> Self {
        Self {
            database,
            table,
            column,
            record_id,
        }
    }
}
impl DatabaseReader {
    /// Low-level access uses the deadline installed when this guard was opened.
    /// Use with_connection for fresh per-operation deadlines in a long-lived UI.
    pub fn connection(&self) -> &rusqlite::Connection {
        &self.connection
    }
    pub fn with_connection<T>(
        &self,
        read: impl FnOnce(&rusqlite::Connection) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let end = deadline(&self.limits)?;
        self.connection
            .progress_handler(1000, Some(move || Instant::now() >= end))
            .map_err(crate::sqlite::classify)?;
        let result = read(&self.connection)?;
        crate::container::check_deadline(end)?;
        Ok(result)
    }
}

#[derive(Clone)]
struct Resource {
    source: ResourceSource,
    digest: EntryDigest,
}

/// A complete, verified, immutable Darkbox edition. Missing decryption keys are allowed.
#[derive(Clone)]
pub struct Package {
    report: Report,
    snapshot: Arc<Snapshot>,
    origin: Option<PathBuf>,
}

/// Diagnostic access never authorizes editing, saving or trusted interpretation.
pub struct DiagnosticPackage {
    report: Report,
    snapshot: Option<Arc<Snapshot>>,
}

impl DiagnosticPackage {
    pub fn from_reader(
        reader: impl Read,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Self, Error> {
        let end = deadline(&limits)?;
        let (archive, digest) = freeze_reader(reader, &limits, end)?;
        let (mut report, staging) =
            crate::analyze_captured(archive.path(), Mode::Verify, limits, options, true);
        report.file = "<reader>".into();
        let snapshot = staging.map(|staging| {
            Arc::new(Snapshot {
                archive,
                digest,
                staging,
            })
        });
        Ok(Self { report, snapshot })
    }
    pub fn open(
        path: impl AsRef<Path>,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Self, Error> {
        let end = deadline(&limits)?;
        let (archive, digest) = freeze(path.as_ref(), &limits, end)?;
        let (mut report, staging) =
            crate::analyze_captured(archive.path(), Mode::Verify, limits, options, true);
        report.file = path.as_ref().display().to_string();
        let snapshot = staging.map(|staging| {
            Arc::new(Snapshot {
                archive,
                digest,
                staging,
            })
        });
        Ok(Self { report, snapshot })
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    pub fn resource(&self, path: &str) -> Result<ResourceReader, Error> {
        let snapshot = self.snapshot.as_ref().ok_or_else(|| {
            Error::invalid(
                "package.diagnostic_unavailable",
                "No complete safely readable ZIP snapshot is available",
            )
        })?;
        snapshot_resource(snapshot, path)?.source.open()
    }
}

fn snapshot_resource(snapshot: &Arc<Snapshot>, path: &str) -> Result<Resource, Error> {
    let file =
        snapshot.staging.files.get(path).ok_or_else(|| {
            Error::invalid("package.resource_missing", "Resource is absent").at(path)
        })?;
    Ok(Resource {
        source: ResourceSource::Snapshot {
            _owner: snapshot.clone(),
            path: file.clone(),
        },
        digest: snapshot.staging.digests[path].clone(),
    })
}

impl Package {
    /// Freeze and validate ZIP bytes from the current position of any reader.
    /// Saving such a package requires save_as to select its filesystem destination.
    pub fn from_reader(
        reader: impl Read,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Self, Error> {
        let diagnostic = DiagnosticPackage::from_reader(reader, limits, options)?;
        if diagnostic.report.status != Status::Passed {
            return Err(Error::new(
                diagnostic.report.status,
                "package.open",
                "Ordinary opening refused; use DiagnosticPackage to inspect the report",
            )
            .with_report(diagnostic.report));
        }
        Ok(Self {
            report: diagnostic.report,
            snapshot: diagnostic.snapshot.unwrap(),
            origin: None,
        })
    }
    pub fn open(
        path: impl AsRef<Path>,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Self, Error> {
        let origin = destination(path.as_ref())?;
        let end = deadline(&limits)?;
        let diagnostic = DiagnosticPackage::open(&origin, limits.clone(), options)?;
        if diagnostic.report.status != Status::Passed {
            let first = diagnostic
                .report
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.severity == "error");
            return Err(Error::new(
                diagnostic.report.status,
                "package.open",
                format!(
                    "Ordinary opening refused{}",
                    first.map(|d| format!(": {}", d.code)).unwrap_or_default()
                ),
            )
            .with_report(diagnostic.report));
        }
        let snapshot = diagnostic.snapshot.unwrap();
        if crate::writer::file_digest(&origin, limits.max_archive_bytes, end)? != snapshot.digest {
            return Err(Error::new(
                Status::OperationalError,
                "package.source_changed",
                "Source changed while opening; retry with a coherent file",
            ));
        }
        Ok(Self {
            report: diagnostic.report,
            snapshot,
            origin: Some(origin),
        })
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    pub fn manifest(&self) -> &Value {
        self.report.manifest.as_ref().unwrap()
    }
    pub fn path(&self) -> Option<&Path> {
        self.origin.as_deref()
    }
    /// Copy the exact verified archive bytes to an application-owned output stream.
    /// Atomic publication of a stream is the application's responsibility.
    pub fn copy_to(&self, mut output: impl Write) -> Result<u64, Error> {
        let end = deadline(&self.report.limits)?;
        let mut input = File::open(self.snapshot.archive.path()).map_err(crate::io_failure)?;
        let mut buffer = [0; 65_536];
        let mut total = 0;
        loop {
            crate::container::check_deadline(end)?;
            let count = input.read(&mut buffer).map_err(crate::io_failure)?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count])
                .map_err(crate::io_failure)?;
            total += count as u64;
        }
        Ok(total)
    }
    pub fn resources(&self) -> impl Iterator<Item = &EntryDigest> {
        self.snapshot.staging.digests.values()
    }
    pub fn resource(&self, path: &str) -> Result<ResourceReader, Error> {
        snapshot_resource(&self.snapshot, path)?.source.open()
    }
    pub fn database(&self, path: &str) -> Result<DatabaseReader, Error> {
        declared_database(self.manifest(), path)?;
        let source = snapshot_resource(&self.snapshot, path)?.source;
        let connection = crate::sqlite::open(
            source.path(),
            &self.report.limits,
            deadline(&self.report.limits)?,
        )?;
        Ok(DatabaseReader {
            connection,
            _source: source,
            limits: self.report.limits.clone(),
        })
    }
    /// Export raw bytes atomically to a new file. Never implicitly decrypts resources.
    pub fn export_resource(&self, path: &str, output: impl AsRef<Path>) -> Result<(), Error> {
        let output = destination(output.as_ref())?;
        let parent = output.parent().unwrap();
        let mut candidate = tempfile::Builder::new()
            .prefix(".darkbox-export-")
            .tempfile_in(parent)
            .map_err(crate::io_failure)?;
        let mut input = self.resource(path)?;
        let mut buffer = [0; 65_536];
        let end = deadline(&self.report.limits)?;
        loop {
            crate::container::check_deadline(end)?;
            let count = input.read(&mut buffer).map_err(crate::io_failure)?;
            if count == 0 {
                break;
            }
            candidate
                .write_all(&buffer[..count])
                .map_err(crate::io_failure)?;
        }
        candidate.as_file().sync_all().map_err(crate::io_failure)?;
        candidate
            .persist_noclobber(output)
            .map_err(|error| crate::io_failure(error.error))?;
        Ok(())
    }
    pub fn decrypt_resource(
        &self,
        path: &str,
        keys: &dyn DecryptionKeys,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let context = file_context(self.manifest(), path)?;
        let key = key(keys, &context.key_id)?;
        let mut block = Vec::new();
        self.resource(path)?
            .read_to_end(&mut block)
            .map_err(crate::io_failure)?;
        protection::decrypt_block(&block, &key, &context)
    }
    pub fn decrypt_value(
        &self,
        database: &str,
        table: &str,
        column: &str,
        record_id: &str,
        keys: &dyn DecryptionKeys,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let (context, id_column) =
            value_context(self.manifest(), database, table, column, record_id)?;
        let reader = self.database(database)?;
        decrypt_value(reader.connection(), &context, &id_column, keys)
    }
    pub fn edit(&self) -> PackageEditor {
        PackageEditor {
            manifest: self.manifest().clone(),
            initial_manifest: self.manifest().clone(),
            resources: self
                .snapshot
                .staging
                .files
                .keys()
                .map(|path| {
                    (
                        path.clone(),
                        snapshot_resource(&self.snapshot, path).unwrap(),
                    )
                })
                .collect(),
            base: Some(self.clone()),
            limits: self.report.limits.clone(),
            dirty: false,
        }
    }
}

fn managed(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    matches!(path.as_str(), "manifest.json" | "readme.md")
        || path == protection::SIGNATURE_PATH
        || path.starts_with("docs/darkbox/")
        || path.starts_with("docs/sqlite/")
}
fn declared_database(manifest: &Value, path: &str) -> Result<crate::model::Database, Error> {
    manifest["databases"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|db| db["path"] == path)
        .and_then(|db| serde_json::from_value(db.clone()).ok())
        .ok_or_else(|| Error::invalid("package.database", "Database is not declared").at(path))
}
pub(crate) fn key(keys: &dyn DecryptionKeys, id: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    keys.key(id).ok_or_else(|| {
        Error::new(
            Status::Unsupported,
            "protection.key_absent",
            "Required decryption key is absent",
        )
    })
}
pub(crate) fn file_context(manifest: &Value, path: &str) -> Result<BlockContext, Error> {
    let data = protection::data(manifest)?;
    let file = data
        .files
        .iter()
        .find(|file| file.path == path)
        .ok_or_else(|| {
            Error::invalid(
                "protection.file",
                "Resource has no encrypted-file declaration",
            )
            .at(path)
        })?;
    Ok(BlockContext {
        package_id: data.package_id,
        key_id: file.key_id.clone(),
        location: BlockLocation::File { path: path.into() },
    })
}
pub(crate) fn value_context(
    manifest: &Value,
    database: &str,
    table: &str,
    column: &str,
    record_id: &str,
) -> Result<(BlockContext, String), Error> {
    let data = protection::data(manifest)?;
    let declaration = data
        .sqlite
        .iter()
        .find(|d| d.database == database && d.table == table && d.column == column)
        .ok_or_else(|| {
            Error::invalid(
                "protection.sqlite_column",
                "Column has no encrypted-value declaration",
            )
        })?;
    let context = BlockContext {
        package_id: data.package_id,
        key_id: declaration.key_id.clone(),
        location: BlockLocation::Sqlite {
            database: database.into(),
            table: table.into(),
            column: column.into(),
            record_id: record_id.into(),
        },
    };
    // Also validate record IDs before executing trusted, bound-parameter queries.
    context.aad(&[0; 28])?;
    Ok((context, declaration.record_id_column.clone()))
}
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
pub(crate) fn decrypt_value(
    db: &rusqlite::Connection,
    context: &BlockContext,
    id_column: &str,
    keys: &dyn DecryptionKeys,
) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
    let BlockLocation::Sqlite {
        table,
        column,
        record_id,
        ..
    } = &context.location
    else {
        unreachable!()
    };
    let sql = format!(
        "SELECT {} FROM {} WHERE CAST({} AS BLOB)=CAST(?1 AS BLOB)",
        quote(column),
        quote(table),
        quote(id_column)
    );
    let mut statement = db.prepare(&sql).map_err(crate::sqlite::classify)?;
    let mut rows = statement
        .query([record_id])
        .map_err(crate::sqlite::classify)?;
    let row = rows
        .next()
        .map_err(crate::sqlite::classify)?
        .ok_or_else(|| Error::invalid("package.record_missing", "Record is absent"))?;
    let block: Option<Vec<u8>> = row.get(0).map_err(crate::sqlite::classify)?;
    if rows.next().map_err(crate::sqlite::classify)?.is_some() {
        return Err(Error::invalid(
            "protection.record_id",
            "Record identifier is not unique",
        ));
    }
    block
        .map(|block| protection::decrypt_block(&block, &*key(keys, &context.key_id)?, context))
        .transpose()
}

/// Staged changes never mutate the source package. Failed operations retain the
/// previous staged resource; failed saves retain all staged changes for retry.
#[derive(Clone)]
pub struct PackageEditor {
    manifest: Value,
    initial_manifest: Value,
    resources: BTreeMap<String, Resource>,
    base: Option<Package>,
    limits: Limits,
    dirty: bool,
}

impl PackageEditor {
    pub fn new(manifest: Value, limits: Limits) -> Result<Self, Error> {
        deadline(&limits)?;
        crate::creation::serialized_manifest(&manifest, limits.max_metadata_bytes)?;
        crate::creation::specification(&manifest)?;
        Ok(Self {
            initial_manifest: manifest.clone(),
            manifest,
            resources: BTreeMap::new(),
            base: None,
            limits,
            dirty: false,
        })
    }
    pub fn manifest(&self) -> &Value {
        &self.manifest
    }
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }
    pub fn resources(&self) -> impl Iterator<Item = &EntryDigest> {
        self.resources.values().map(|r| &r.digest)
    }
    pub fn resource(&self, path: &str) -> Result<ResourceReader, Error> {
        self.resources
            .get(path)
            .ok_or_else(|| {
                Error::invalid("package.resource_missing", "Resource is absent").at(path)
            })?
            .source
            .open()
    }
    pub fn database(&self, path: &str) -> Result<DatabaseReader, Error> {
        declared_database(&self.manifest, path)?;
        let source = self
            .resources
            .get(path)
            .ok_or_else(|| {
                Error::invalid("package.resource_missing", "Database is absent").at(path)
            })?
            .source
            .clone();
        let connection = crate::sqlite::open(source.path(), &self.limits, deadline(&self.limits)?)?;
        Ok(DatabaseReader {
            connection,
            _source: source,
            limits: self.limits.clone(),
        })
    }
    /// Work on a copy, validating its metadata before committing the change.
    pub fn update_manifest(
        &mut self,
        change: impl FnOnce(&mut Value) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut candidate = self.manifest.clone();
        change(&mut candidate)?;
        crate::creation::serialized_manifest(&candidate, self.limits.max_metadata_bytes)?;
        crate::creation::specification(&candidate)?;
        self.manifest = candidate;
        self.dirty = true;
        Ok(())
    }
    pub fn add_folder(&mut self, path: &str, description: &str) -> Result<(), Error> {
        crate::paths::validate(path)?;
        self.update_manifest(|manifest| {
            let folders = manifest["folders"].as_array_mut().unwrap();
            if folders.iter().any(|folder| {
                folder["path"]
                    .as_str()
                    .is_some_and(|p| p.eq_ignore_ascii_case(path))
            }) {
                return Err(Error::invalid("path.collision", "Folder already exists").at(path));
            }
            folders.push(json!({"path":path,"description":description}));
            Ok(())
        })
    }
    pub fn remove_folder(&mut self, path: &str) -> Result<(), Error> {
        let prefix = format!("{path}/");
        if self.resources.keys().any(|p| p.starts_with(&prefix))
            || self.manifest["folders"]
                .as_array()
                .unwrap()
                .iter()
                .any(|folder| {
                    folder["path"]
                        .as_str()
                        .is_some_and(|p| p.starts_with(&prefix))
                })
        {
            return Err(
                Error::invalid("package.folder_nonempty", "Remove folder contents first").at(path),
            );
        }
        self.update_manifest(|manifest| {
            let folders = manifest["folders"].as_array_mut().unwrap();
            let count = folders.len();
            folders.retain(|folder| folder["path"] != path);
            if count == folders.len() {
                return Err(Error::invalid("package.folder_missing", "Folder is absent").at(path));
            }
            Ok(())
        })
    }
    fn check_resource_path(&self, path: &str) -> Result<(), Error> {
        if managed(path) {
            return Err(Error::invalid(
                "package.reserved",
                "Canonical documentation, manifest and signature are managed by Darkbox",
            )
            .at(path));
        }
        let mut nodes = crate::paths::Nodes::new();
        let folders = self.manifest["folders"].as_array().unwrap();
        for folder in folders {
            crate::paths::insert(&mut nodes, folder["path"].as_str().unwrap(), true)?;
        }
        for name in self.resources.keys().filter(|name| *name != path) {
            crate::paths::insert(&mut nodes, name, false)?;
        }
        crate::paths::insert(&mut nodes, path, false)?;
        let mut current = path;
        while let Some((parent, _)) = current.rsplit_once('/') {
            if !folders.iter().any(|folder| folder["path"] == parent) {
                return Err(Error::invalid(
                    "folder.missing",
                    "Declare every resource parent directory first",
                )
                .at(parent));
            }
            current = parent;
        }
        Ok(())
    }
    fn stage(&self, path: &str, mut reader: impl Read) -> Result<Resource, Error> {
        self.check_resource_path(path)?;
        let end = deadline(&self.limits)?;
        let mut file = tempfile::Builder::new()
            .prefix("darkbox-edit-")
            .tempfile()
            .map_err(crate::io_failure)?;
        let mut size = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0; 65_536];
        let remaining: u64 = self
            .resources
            .iter()
            .filter(|(name, _)| *name != path)
            .map(|(_, r)| r.digest.size)
            .try_fold(0u64, |total, size| total.checked_add(size))
            .ok_or_else(|| Error::limit("Staged resources exceed the total byte limit"))?;
        if !self.resources.contains_key(path) && self.resources.len() >= self.limits.max_entries {
            return Err(Error::limit("Staged resource count exceeds limits"));
        }
        loop {
            crate::container::check_deadline(end)?;
            let count = match reader.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result.map_err(crate::io_failure)?,
            };
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .filter(|size| {
                    *size <= self.limits.max_entry_bytes
                        && remaining
                            .checked_add(*size)
                            .is_some_and(|total| total <= self.limits.max_total_bytes)
                })
                .ok_or_else(|| Error::limit("Staged resource size exceeds limits"))?;
            file.write_all(&buffer[..count])
                .map_err(crate::io_failure)?;
            hash.update(&buffer[..count]);
        }
        file.flush().map_err(crate::io_failure)?;
        Ok(Resource {
            source: ResourceSource::Temporary(Arc::new(file)),
            digest: EntryDigest {
                path: path.into(),
                size,
                sha256: format!("{:x}", hash.finalize()),
            },
        })
    }
    /// Insert or replace a resource with already public or already encrypted bytes.
    pub fn put_reader(&mut self, path: &str, reader: impl Read) -> Result<EntryDigest, Error> {
        let resource = self.stage(path, reader)?;
        let digest = resource.digest.clone();
        self.resources.insert(path.into(), resource);
        self.dirty = true;
        Ok(digest)
    }
    pub fn put_path(&mut self, path: &str, source: impl AsRef<Path>) -> Result<EntryDigest, Error> {
        let file = File::open(source).map_err(crate::io_failure)?;
        if !file.metadata().map_err(crate::io_failure)?.is_file() {
            return Err(Error::invalid(
                "package.resource_type",
                "Input must be a regular file",
            ));
        }
        self.put_reader(path, file)
    }
    /// Remove resource bytes and their database/protection declarations together.
    pub fn remove_resource(&mut self, path: &str) -> Result<(), Error> {
        if managed(path) || self.manifest["application"]["profilePath"] == path {
            return Err(Error::invalid(
                "package.reserved",
                "Required documentation cannot be removed",
            )
            .at(path));
        }
        if !self.resources.contains_key(path) {
            return Err(Error::invalid("package.resource_missing", "Resource is absent").at(path));
        }
        let mut metadata = self.manifest.clone();
        metadata["databases"]
            .as_array_mut()
            .unwrap()
            .retain(|db| db["path"] != path);
        if let Some(descriptor) = metadata
            .get_mut("extensions")
            .and_then(|extensions| extensions.get_mut(protection::NAMESPACE))
        {
            descriptor["data"]["files"]
                .as_array_mut()
                .unwrap()
                .retain(|file| file["path"] != path);
            descriptor["data"]["sqlite"]
                .as_array_mut()
                .unwrap()
                .retain(|column| column["database"] != path);
        }
        crate::creation::specification(&metadata)?;
        self.manifest = metadata;
        self.resources.remove(path);
        self.dirty = true;
        Ok(())
    }
    /// Rename a public resource. Encrypted paths require decrypting and re-encrypting.
    pub fn rename_resource(&mut self, old: &str, new: &str) -> Result<(), Error> {
        self.check_resource_path(new)?;
        if self.resources.contains_key(new) {
            return Err(
                Error::invalid("path.collision", "Destination resource already exists").at(new),
            );
        }
        if managed(old) {
            return Err(Error::invalid(
                "package.reserved",
                "Managed resources cannot be renamed",
            ));
        }
        if self.manifest["extensions"]
            .get(protection::NAMESPACE)
            .is_some()
        {
            let data = protection::data(&self.manifest)?;
            if data.files.iter().any(|f| f.path == old)
                || data.sqlite.iter().any(|d| d.database == old)
            {
                return Err(Error::new(
                    Status::Unsupported,
                    "protection.context_changed",
                    "Encrypted contexts require new authenticated blocks before renaming",
                ));
            }
        }
        let mut resource = self
            .resources
            .get(old)
            .ok_or_else(|| {
                Error::invalid("package.resource_missing", "Resource is absent").at(old)
            })?
            .clone();
        let mut metadata = self.manifest.clone();
        if metadata["application"]["profilePath"] == old {
            metadata["application"]["profilePath"] = json!(new);
        }
        for db in metadata["databases"].as_array_mut().unwrap() {
            if db["path"] == old {
                db["path"] = json!(new);
            }
        }
        crate::creation::specification(&metadata)?;
        resource.digest.path = new.into();
        self.resources.remove(old);
        self.resources.insert(new.into(), resource);
        self.manifest = metadata;
        self.dirty = true;
        Ok(())
    }
    /// Encrypt before staging. Plaintext is never written to the package staging area.
    pub fn put_encrypted(
        &mut self,
        path: &str,
        plaintext: &[u8],
        key_id: &str,
        keys: &dyn DecryptionKeys,
        nonces: &mut dyn NonceSequence,
    ) -> Result<EntryDigest, Error> {
        self.check_resource_path(path)?;
        if plaintext.len() as u64 > self.limits.max_entry_bytes.saturating_sub(44) {
            return Err(Error::limit("Encrypted resource exceeds entry limits"));
        }
        let mut data = protection::data(&self.manifest)?;
        let context = BlockContext {
            package_id: data.package_id.clone(),
            key_id: key_id.into(),
            location: BlockLocation::File { path: path.into() },
        };
        let block = protection::encrypt_block(plaintext, &*key(keys, key_id)?, &context, nonces)?;
        let resource = self.stage(path, io::Cursor::new(block))?;
        if let Some(file) = data.files.iter_mut().find(|file| file.path == path) {
            file.key_id = key_id.into();
        } else {
            data.files.push(protection::FileProtection {
                path: path.into(),
                key_id: key_id.into(),
            });
        }
        let digest = resource.digest.clone();
        self.resources.insert(path.into(), resource);
        self.manifest["extensions"][protection::NAMESPACE]["data"] =
            serde_json::to_value(data).unwrap();
        self.dirty = true;
        Ok(digest)
    }
    pub fn decrypt_resource(
        &self,
        path: &str,
        keys: &dyn DecryptionKeys,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let context = file_context(&self.manifest, path)?;
        let key = key(keys, &context.key_id)?;
        let mut block = Vec::new();
        self.resource(path)?
            .read_to_end(&mut block)
            .map_err(crate::io_failure)?;
        protection::decrypt_block(&block, &key, &context)
    }
    pub fn decrypt_value(
        &self,
        database: &str,
        table: &str,
        column: &str,
        record_id: &str,
        keys: &dyn DecryptionKeys,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let (context, id_column) =
            value_context(&self.manifest, database, table, column, record_id)?;
        let reader = self.database(database)?;
        decrypt_value(reader.connection(), &context, &id_column, keys)
    }
    /// Encrypt a value for a declared record before binding it to application SQL.
    pub fn encrypt_value(
        &self,
        address: ValueAddress<'_>,
        plaintext: &[u8],
        keys: &dyn DecryptionKeys,
        nonces: &mut dyn NonceSequence,
    ) -> Result<Vec<u8>, Error> {
        if plaintext.len() as u64 > self.limits.max_entry_bytes.saturating_sub(44) {
            return Err(Error::limit("Encrypted value exceeds entry limits"));
        }
        let (context, _) = value_context(
            &self.manifest,
            address.database,
            address.table,
            address.column,
            address.record_id,
        )?;
        protection::encrypt_block(plaintext, &*key(keys, &context.key_id)?, &context, nonces)
    }
    /// Replace one existing protected value. Only the ciphertext enters SQLite or journals.
    pub fn put_encrypted_value(
        &mut self,
        address: ValueAddress<'_>,
        plaintext: &[u8],
        keys: &dyn DecryptionKeys,
        nonces: &mut dyn NonceSequence,
    ) -> Result<(), Error> {
        let block = self.encrypt_value(address, plaintext, keys, nonces)?;
        let ValueAddress {
            database,
            table,
            column,
            record_id,
        } = address;
        let (_, id_column) = value_context(&self.manifest, database, table, column, record_id)?;
        self.edit_database(database, |transaction| {
            let count = transaction
                .execute(
                    &format!(
                        "UPDATE {} SET {}=?1 WHERE CAST({} AS BLOB)=CAST(?2 AS BLOB)",
                        quote(table),
                        quote(column),
                        quote(&id_column)
                    ),
                    rusqlite::params![block, record_id],
                )
                .map_err(crate::sqlite::classify)?;
            if count != 1 {
                return Err(Error::invalid(
                    "package.record_missing",
                    "Expected exactly one record with this stable identifier",
                ));
            }
            Ok(())
        })
    }
    /// Snapshot an application-owned connection using SQLite's backup API, including
    /// committed WAL data. No raw copy of a live database or its sidecars is used.
    pub fn put_database(
        &mut self,
        declaration: DatabaseDeclaration,
        connection: &rusqlite::Connection,
    ) -> Result<(), Error> {
        self.check_resource_path(&declaration.path)?;
        let end = deadline(&self.limits)?;
        let snapshot = database_snapshot(connection, &self.limits, end)?;
        let mut metadata = self.manifest.clone();
        let databases = metadata["databases"].as_array_mut().unwrap();
        let value = serde_json::to_value(&declaration).unwrap();
        if let Some(db) = databases
            .iter_mut()
            .find(|db| db["path"] == declaration.path)
        {
            *db = value;
        } else {
            databases.push(value);
        }
        crate::creation::specification(&metadata)?;
        crate::sqlite::examine(
            snapshot.path(),
            &declared_database(&metadata, &declaration.path)?,
            Mode::Verify,
            &self.limits,
            end,
        )?;
        let resource = self.stage(
            &declaration.path,
            File::open(snapshot.path()).map_err(crate::io_failure)?,
        )?;
        self.resources.insert(declaration.path, resource);
        self.manifest = metadata;
        self.dirty = true;
        Ok(())
    }
    /// Run application SQL in one transaction on a private database copy. A failed
    /// callback, commit, integrity check or snapshot leaves staged state unchanged.
    /// Schema/user_version changes must agree with the manifest set by the caller.
    pub fn edit_database<T>(
        &mut self,
        path: &str,
        edit: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let declaration = declared_database(&self.manifest, path)?;
        let end = deadline(&self.limits)?;
        // TempDir owns any journal/WAL created even by unsuccessful application SQL.
        let directory = tempfile::Builder::new()
            .prefix("darkbox-db-edit-")
            .tempdir()
            .map_err(crate::io_failure)?;
        let candidate = directory.path().join("database.sqlite");
        let mut input = self.resource(path)?;
        let mut output = File::create(&candidate).map_err(crate::io_failure)?;
        let mut buffer = [0; 65_536];
        loop {
            crate::container::check_deadline(end)?;
            let count = input.read(&mut buffer).map_err(crate::io_failure)?;
            if count == 0 {
                break;
            }
            output
                .write_all(&buffer[..count])
                .map_err(crate::io_failure)?;
        }
        drop(output);
        let mut db = rusqlite::Connection::open(&candidate).map_err(crate::sqlite::classify)?;
        configure_edit(&db, &self.limits, end)?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=DELETE;")
            .map_err(crate::sqlite::classify)?;
        let transaction = db.transaction().map_err(crate::sqlite::classify)?;
        let result = edit(&transaction)?;
        crate::container::check_deadline(end)?;
        transaction.commit().map_err(crate::sqlite::classify)?;
        // Produce a closed, coherent snapshot, even if application SQL changed pragmas.
        let snapshot = database_snapshot(&db, &self.limits, end)?;
        drop(db);
        crate::sqlite::examine(
            snapshot.path(),
            &declaration,
            Mode::Verify,
            &self.limits,
            end,
        )?;
        let resource = self.stage(
            path,
            File::open(snapshot.path()).map_err(crate::io_failure)?,
        )?;
        self.resources.insert(path.into(), resource);
        self.dirty = true;
        Ok(result)
    }
    /// Rename an encrypted attachment by authenticating and allocating a fresh nonce.
    pub fn rename_encrypted(
        &mut self,
        old: &str,
        new: &str,
        keys: &dyn DecryptionKeys,
        nonces: &mut dyn NonceSequence,
    ) -> Result<(), Error> {
        self.check_resource_path(new)?;
        if self.resources.contains_key(new) {
            return Err(Error::invalid("path.collision", "Destination exists").at(new));
        }
        let context = file_context(&self.manifest, old)?;
        let plaintext = self.decrypt_resource(old, keys)?;
        let mut candidate = self.clone();
        candidate.put_encrypted(new, &plaintext, &context.key_id, keys, nonces)?;
        // Both paths are attachments, so this removal cannot violate database minimums.
        candidate.remove_resource(old)?;
        *self = candidate;
        Ok(())
    }
    /// Re-encrypt every protected file/value for a new package identity and/or
    /// key mapping. Requires old and new keys and fresh durably reserved nonces.
    /// The entire staged edition survives unchanged if any block fails.
    pub fn rekey(
        &mut self,
        package_id: &str,
        key_mapping: &BTreeMap<String, String>,
        keys: &dyn DecryptionKeys,
        nonces: &mut dyn NonceSequence,
    ) -> Result<(), Error> {
        let old = protection::data(&self.manifest)?;
        let mut new = old.clone();
        new.package_id = package_id.into();
        for file in &mut new.files {
            if let Some(id) = key_mapping.get(&file.key_id) {
                file.key_id = id.clone();
            }
        }
        for column in &mut new.sqlite {
            if let Some(id) = key_mapping.get(&column.key_id) {
                column.key_id = id.clone();
            }
        }
        let mut candidate = self.clone();
        candidate.manifest["extensions"][protection::NAMESPACE]["data"] =
            serde_json::to_value(&new).unwrap();
        protection::data(&candidate.manifest)?;
        for file in &new.files {
            let plaintext = self.decrypt_resource(&file.path, keys)?;
            candidate.put_encrypted(&file.path, &plaintext, &file.key_id, keys, nonces)?;
        }
        let databases: std::collections::BTreeSet<_> = old
            .sqlite
            .iter()
            .map(|column| column.database.clone())
            .collect();
        for database in databases {
            let source = self
                .resources
                .get(&database)
                .ok_or_else(|| Error::invalid("package.database", "Database is absent"))?
                .source
                .clone();
            let end = deadline(&self.limits)?;
            candidate.edit_database(&database,|transaction| {
                for declaration in old.sqlite.iter().filter(|column|column.database == database) {
                    let target = new.sqlite.iter().find(|column|column.database == database && column.table == declaration.table && column.column == declaration.column).unwrap();
                    crate::sqlite::encrypted_values(source.path(),declaration,&self.limits,end,|id,block| {
                        let old_context = BlockContext {package_id:old.package_id.clone(),key_id:declaration.key_id.clone(),location:BlockLocation::Sqlite {database:database.clone(),table:declaration.table.clone(),column:declaration.column.clone(),record_id:id.into()}};
                        let plaintext = protection::decrypt_block(block,&*key(keys,&old_context.key_id)?,&old_context)?;
                        let mut new_context = old_context;
                        new_context.package_id = new.package_id.clone(); new_context.key_id = target.key_id.clone();
                        let block = protection::encrypt_block(&plaintext,&*key(keys,&new_context.key_id)?,&new_context,nonces)?;
                        let count = transaction.execute(&format!("UPDATE {} SET {}=?1 WHERE CAST({} AS BLOB)=CAST(?2 AS BLOB)",quote(&declaration.table),quote(&declaration.column),quote(&declaration.record_id_column)),rusqlite::params![block,id]).map_err(crate::sqlite::classify)?;
                        if count != 1 { return Err(Error::invalid("protection.record_id","Expected exactly one stable record identifier")); }
                        Ok(())
                    })?;
                }
                Ok(())
            })?;
        }
        candidate.dirty = true;
        *self = candidate;
        Ok(())
    }
    pub fn discard_changes(&mut self) {
        if let Some(base) = &self.base {
            *self = base.edit();
        } else {
            self.manifest = self.initial_manifest.clone();
            self.resources.clear();
            self.dirty = false;
        }
    }
    pub fn save(
        &mut self,
        options: &VerificationOptions<'_>,
        signer: Option<&dyn ManifestSigner>,
    ) -> Result<Package, Error> {
        let path = self
            .base
            .as_ref()
            .ok_or_else(|| {
                Error::invalid("package.destination", "New projects need save_as first")
            })?
            .origin
            .clone()
            .ok_or_else(|| {
                Error::invalid(
                    "package.destination",
                    "Reader-backed packages need save_as first",
                )
            })?;
        self.publish(&path, true, options, signer)
    }
    /// Save a copy/new project to an absent destination. Existing unrelated files
    /// are never overwritten. After success the editor follows the new edition.
    pub fn save_as(
        &mut self,
        path: impl AsRef<Path>,
        options: &VerificationOptions<'_>,
        signer: Option<&dyn ManifestSigner>,
    ) -> Result<Package, Error> {
        self.publish(path.as_ref(), false, options, signer)
    }
    fn publish(
        &mut self,
        path: &Path,
        replace: bool,
        options: &VerificationOptions<'_>,
        signer: Option<&dyn ManifestSigner>,
    ) -> Result<Package, Error> {
        let path = destination(path)?;
        let lock = lock_destination(&path)?;
        let end = deadline(&self.limits)?;
        if replace {
            let base = self.base.as_ref().unwrap();
            if !std::fs::symlink_metadata(&path)
                .map_err(crate::io_failure)?
                .is_file()
                || crate::writer::file_digest(&path, self.limits.max_archive_bytes, end)?
                    != base.snapshot.digest
            {
                return Err(Error::new(
                    Status::OperationalError,
                    "package.conflict",
                    "Original file changed since opening; staged changes were retained",
                ));
            }
        } else if std::fs::symlink_metadata(&path).is_ok() {
            return Err(Error::new(
                Status::OperationalError,
                "package.destination_exists",
                "Save-as requires an absent destination",
            ));
        }
        let mut writer = crate::PackageWriter::new_locked(
            &path,
            self.manifest.clone(),
            self.limits.clone(),
            options,
            signer,
            lock,
        )?;
        if let Some(base) = &self.base {
            writer.previous_snapshot(&base.report, base.snapshot.archive.path());
        }
        for (name, resource) in &self.resources {
            if !managed(name) {
                writer.add_reader(name, resource.source.open()?)?;
            }
        }
        let (report, snapshot) = writer.finish_captured()?;
        let package = Package {
            report,
            snapshot: Arc::new(snapshot),
            origin: Some(path),
        };
        *self = package.edit();
        Ok(package)
    }
}

fn configure_edit(db: &rusqlite::Connection, limits: &Limits, end: Instant) -> Result<(), Error> {
    use rusqlite::{config::DbConfig, limits::Limit};
    db.busy_timeout(Duration::ZERO)
        .map_err(crate::sqlite::classify)?;
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(crate::sqlite::classify)?;
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(crate::sqlite::classify)?;
    db.load_extension_disable()
        .map_err(crate::sqlite::classify)?;
    db.set_limit(
        Limit::SQLITE_LIMIT_LENGTH,
        limits.max_entry_bytes.min(i32::MAX as u64) as i32,
    )
    .map_err(crate::sqlite::classify)?;
    db.set_limit(
        Limit::SQLITE_LIMIT_SQL_LENGTH,
        limits.max_metadata_bytes.min(i32::MAX as u64) as i32,
    )
    .map_err(crate::sqlite::classify)?;
    db.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 100)
        .map_err(crate::sqlite::classify)?;
    let page_size: u64 = db
        .query_row("PRAGMA page_size", [], |row| {
            row.get::<_, u32>(0).map(u64::from)
        })
        .map_err(crate::sqlite::classify)?;
    let maximum = limits.max_entry_bytes / page_size;
    if maximum == 0 {
        return Err(Error::limit("Database page exceeds entry limits"));
    }
    let actual: u64 = db
        .query_row(&format!("PRAGMA max_page_count={maximum}"), [], |row| {
            row.get::<_, u32>(0).map(u64::from)
        })
        .map_err(crate::sqlite::classify)?;
    if actual > maximum {
        return Err(Error::limit("Database exceeds entry limits"));
    }
    db.progress_handler(1000, Some(move || Instant::now() >= end))
        .map_err(crate::sqlite::classify)?;
    db.execute_batch("PRAGMA cache_size=-2048;")
        .map_err(crate::sqlite::classify)?;
    Ok(())
}

struct DatabaseSnapshot {
    _directory: tempfile::TempDir,
    path: PathBuf,
}
impl DatabaseSnapshot {
    fn path(&self) -> &Path {
        &self.path
    }
}

fn database_snapshot(
    source: &rusqlite::Connection,
    limits: &Limits,
    end: Instant,
) -> Result<DatabaseSnapshot, Error> {
    use rusqlite::backup::{Backup, StepResult};
    crate::container::check_deadline(end)?;
    let page_size: u64 = source
        .query_row("PRAGMA page_size", [], |row| {
            row.get::<_, u32>(0).map(u64::from)
        })
        .map_err(crate::sqlite::classify)?;
    let page_count: u64 = source
        .query_row("PRAGMA page_count", [], |row| {
            row.get::<_, u32>(0).map(u64::from)
        })
        .map_err(crate::sqlite::classify)?;
    if page_size
        .checked_mul(page_count)
        .is_none_or(|bytes| bytes > limits.max_entry_bytes)
    {
        return Err(Error::limit("Database snapshot exceeds entry limits"));
    }
    let directory = tempfile::Builder::new()
        .prefix("darkbox-db-snapshot-")
        .tempdir()
        .map_err(crate::io_failure)?;
    let path = directory.path().join("database.sqlite");
    let mut destination = rusqlite::Connection::open(&path).map_err(crate::sqlite::classify)?;
    configure_edit(&destination, limits, end)?;
    {
        let backup = Backup::new(source, &mut destination).map_err(crate::sqlite::classify)?;
        loop {
            crate::container::check_deadline(end)?;
            let step = backup.step(128).map_err(crate::sqlite::classify)?;
            let pages = u64::try_from(backup.progress().pagecount).unwrap_or(u64::MAX);
            if pages
                .checked_mul(page_size)
                .is_none_or(|bytes| bytes > limits.max_entry_bytes)
            {
                return Err(Error::limit("Growing database snapshot exceeds limits"));
            }
            match step {
                StepResult::Done => break,
                StepResult::More => {}
                _ => {
                    return Err(Error::new(
                        Status::OperationalError,
                        "package.database_busy",
                        "Source database is locked; retry after committing its transaction",
                    ));
                }
            }
        }
    }
    destination
        .execute_batch("PRAGMA journal_mode=DELETE;")
        .map_err(crate::sqlite::classify)?;
    destination
        .close()
        .map_err(|(_, error)| crate::sqlite::classify(error))?;
    if std::fs::metadata(&path).map_err(crate::io_failure)?.len() > limits.max_entry_bytes {
        return Err(Error::limit("Database snapshot exceeds entry limits"));
    }
    Ok(DatabaseSnapshot {
        _directory: directory,
        path,
    })
}

pub(crate) fn lock_destination(path: &Path) -> Result<File, Error> {
    // Stable sidecar locks survive atomic replacement. Never unlink an active
    // lock inode: concurrent processes must continue locking the same object.
    // Case-fold lock names on every platform so spelling aliases cannot bypass
    // coordination on case-insensitive filesystems. Extra contention is safe.
    let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
    let hash = format!("{:x}", Sha256::digest(name.as_bytes()));
    let lock_path = path.parent().unwrap().join(format!(".darkbox-{hash}.lock"));
    if let Ok(metadata) = std::fs::symlink_metadata(&lock_path)
        && !metadata.is_file()
    {
        return Err(Error::new(
            Status::OperationalError,
            "package.lock_type",
            "Lock path must be a regular file",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
        .map_err(crate::io_failure)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| {
        Error::new(
            Status::OperationalError,
            "package.busy",
            "Another SDK writer holds the destination lock",
        )
    })?;
    Ok(file)
}
