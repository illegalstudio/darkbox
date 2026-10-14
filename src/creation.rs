//! Incremental package creation and publication of complete replacement editions.
use crate::extensions::EntryDigest;
use crate::protection::{self, ManifestSigner};
use crate::versions::{self, Catalog, VersionSpec};
use crate::{Error, Limits, Mode, Report, Status, VerificationOptions};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use zip::{ZipWriter, write::SimpleFileOptions};

struct BoundedFile {
    file: File,
    position: u64,
    end: u64,
    limit: u64,
    deadline: Instant,
    discarded: Arc<AtomicBool>,
}

impl Write for BoundedFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.discarded.load(Ordering::Relaxed) {
            // ZipWriter finalizes again on drop. Discard cleanup output instead
            // of exceeding limits or emitting its retry error to application stderr.
            self.position = self.position.saturating_add(bytes.len() as u64);
            self.end = self.end.max(self.position);
            return Ok(bytes.len());
        }
        if Instant::now() >= self.deadline {
            self.discarded.store(true, Ordering::Relaxed);
            return Err(io::ErrorKind::TimedOut.into());
        }
        if self
            .position
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.limit)
        {
            self.discarded.store(true, Ordering::Relaxed);
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let count = self
            .file
            .write(bytes)
            .inspect_err(|_| self.discarded.store(true, Ordering::Relaxed))?;
        self.position += count as u64;
        self.end = self.end.max(self.position);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.discarded.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.file
            .flush()
            .inspect_err(|_| self.discarded.store(true, Ordering::Relaxed))
    }
}

impl Seek for BoundedFile {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        if self.discarded.load(Ordering::Relaxed) {
            let target = match position {
                SeekFrom::Start(target) => target as i128,
                SeekFrom::Current(delta) => self.position as i128 + delta as i128,
                SeekFrom::End(delta) => self.end as i128 + delta as i128,
            };
            self.position =
                u64::try_from(target).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            return Ok(self.position);
        }
        self.position = self
            .file
            .seek(position)
            .inspect_err(|_| self.discarded.store(true, Ordering::Relaxed))?;
        if self.position > self.limit {
            self.discarded.store(true, Ordering::Relaxed);
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        Ok(self.position)
    }
}

fn output_error(error: io::Error) -> Error {
    if matches!(
        error.kind(),
        io::ErrorKind::FileTooLarge | io::ErrorKind::TimedOut
    ) {
        Error::limit("Streamed package exceeds the configured archive size or deadline")
    } else {
        crate::io_failure(error)
    }
}

fn zip_error(error: zip::result::ZipError) -> Error {
    match error {
        zip::result::ZipError::Io(error) => output_error(error),
        error => crate::zip_failure(error),
    }
}

fn refused(code: &'static str, message: &str) -> Error {
    Error::new(Status::Unsupported, code, message)
}

pub(crate) fn serialized_manifest(manifest: &Value, maximum: u64) -> Result<Vec<u8>, Error> {
    struct Metadata {
        bytes: Vec<u8>,
        maximum: u64,
    }
    impl Write for Metadata {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if (self.bytes.len() as u64)
                .checked_add(bytes.len() as u64)
                .is_none_or(|end| end > self.maximum)
            {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Metadata {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer_pretty(&mut output, manifest).map_err(|error| {
        if error.io_error_kind() == Some(io::ErrorKind::FileTooLarge) {
            Error::limit("Final manifest exceeds the metadata limit")
        } else {
            Error::invalid("create.manifest", "Candidate manifest cannot be serialized")
        }
    })?;
    Ok(output.bytes)
}

pub(crate) fn specification(manifest: &Value) -> Result<&'static VersionSpec, Error> {
    let spec = (manifest["darkbox"]["id"] == "darkbox")
        .then(|| {
            manifest["darkbox"]["version"]
                .as_str()
                .and_then(|version| versions::find_in(versions::VERSIONS, version))
        })
        .flatten()
        .ok_or_else(|| {
            refused(
                "version.unsupported",
                "Streaming creation requires an explicitly supported common version",
            )
        })?;
    let schema: Value = serde_json::from_str(spec.schema).unwrap();
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap();
    if !validator.is_valid(manifest) {
        return Err(Error::invalid(
            "manifest.schema",
            "Candidate metadata does not match its common-version schema",
        ));
    }
    Ok(spec)
}

/// Streams complete resources into a private candidate ZIP. The matching canonical
/// bundle is included automatically. No payload collection is retained in memory.
/// Callers coordinate exclusive destination access and coherent input snapshots.
pub struct PackageWriter<'a> {
    _destination_lock: File,
    // Close ZIP output before removing its owning temporary path on drop.
    zip: Option<ZipWriter<BoundedFile>>,
    candidate: Option<NamedTempFile>,
    discarded: Arc<AtomicBool>,
    destination: PathBuf,
    manifest: Value,
    inventory: BTreeMap<String, EntryDigest>,
    nodes: crate::paths::Nodes,
    entries: usize,
    total: u64,
    reserved_entries: usize,
    limits: Limits,
    options: &'a VerificationOptions<'a>,
    signer: Option<&'a dyn ManifestSigner>,
    previous: Option<Report>,
    previous_archive: Option<PathBuf>,
    previous_digest: Option<[u8; 32]>,
    deadline: Instant,
    failed: bool,
}

impl Drop for PackageWriter<'_> {
    fn drop(&mut self) {
        self.discarded.store(true, Ordering::Relaxed);
    }
}

impl<'a> PackageWriter<'a> {
    /// Start a new package or replacement edition. Existing destinations must be
    /// valid supported packages; their required protection cannot be downgraded.
    pub fn new(
        destination: impl AsRef<Path>,
        manifest: Value,
        limits: Limits,
        options: &'a VerificationOptions<'a>,
        signer: Option<&'a dyn ManifestSigner>,
    ) -> Result<Self, Error> {
        let destination = crate::package::destination(destination.as_ref())?;
        let lock = crate::package::lock_destination(&destination)?;
        Self::new_locked(destination, manifest, limits, options, signer, lock)
    }

    pub(crate) fn new_locked(
        destination: impl AsRef<Path>,
        manifest: Value,
        limits: Limits,
        options: &'a VerificationOptions<'a>,
        signer: Option<&'a dyn ManifestSigner>,
        lock: File,
    ) -> Result<Self, Error> {
        if limits.max_entries == 0
            || limits.max_entry_bytes == 0
            || limits.max_archive_bytes == 0
            || limits.max_total_bytes == 0
            || limits.max_metadata_bytes == 0
            || limits.timeout_seconds == 0
        {
            return Err(Error::limit("Resource limits must be positive"));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(limits.timeout_seconds))
            .ok_or_else(|| Error::limit("Creation timeout is too large"))?;
        serialized_manifest(&manifest, limits.max_metadata_bytes)?;
        let spec = specification(&manifest)?;
        let protected = manifest["extensions"].get(protection::NAMESPACE).is_some();
        if options.require_protection && !protected {
            return Err(Error::invalid(
                "protection.missing",
                "Application policy requires the protection extension",
            ));
        }
        if protected {
            let data = protection::data(&manifest)?;
            if spec.version == "1.0.0" {
                return Err(Error::invalid(
                    "protection.common_version",
                    "Protection requires Darkbox 1.1.0",
                ));
            }
            let signer = signer.ok_or_else(|| {
                refused(
                    "create.signer_required",
                    "Creating a protected package requires signing capability",
                )
            })?;
            if signer.signer_id() != data.signature.signer_id
                || options.trusted_signers.get(signer.signer_id()) != Some(&signer.public_key())
            {
                return Err(refused(
                    "create.signer_trust",
                    "Signing capability must match the declared application-trusted signer",
                ));
            }
        }
        let destination = destination.as_ref().to_owned();
        let (previous, previous_digest) = match std::fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.is_file() => {
                let digest =
                    crate::writer::file_digest(&destination, limits.max_archive_bytes, deadline)?;
                let report = crate::open(&destination, limits.clone(), options)?;
                (Some(report), Some(digest))
            }
            Ok(_) => {
                return Err(refused(
                    "create.destination_type",
                    "Destination must be a regular package file or absent",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (None, None),
            Err(error) => return Err(crate::io_failure(error)),
        };
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let candidate = tempfile::Builder::new()
            .prefix(".darkbox-create-")
            .tempfile_in(parent)
            .map_err(crate::io_failure)?;
        let discarded = Arc::new(AtomicBool::new(false));
        let file = BoundedFile {
            file: candidate.as_file().try_clone().map_err(crate::io_failure)?,
            position: 0,
            end: 0,
            limit: limits.max_archive_bytes,
            deadline,
            discarded: discarded.clone(),
        };
        let mut writer = Self {
            _destination_lock: lock,
            zip: Some(ZipWriter::new(file)),
            candidate: Some(candidate),
            discarded,
            destination: destination.clone(),
            manifest,
            inventory: BTreeMap::new(),
            nodes: crate::paths::Nodes::new(),
            entries: 0,
            total: 0,
            reserved_entries: 1 + usize::from(protected),
            limits,
            options,
            signer,
            previous,
            previous_archive: previous_digest.map(|_| destination.clone()),
            previous_digest,
            deadline,
            failed: false,
        };
        let folders: Vec<String> = writer.manifest["folders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|folder| folder["path"].as_str().unwrap().to_owned())
            .collect();
        for path in folders {
            writer.check_entry_count()?;
            crate::paths::insert(&mut writer.nodes, &path, true)?;
            writer
                .zip
                .as_mut()
                .unwrap()
                .add_directory(format!("{path}/"), SimpleFileOptions::default())
                .map_err(zip_error)?;
            writer.entries += 1;
        }
        let catalog: Catalog = serde_json::from_slice(spec.catalog).unwrap();
        if catalog.folders.iter().any(|folder| {
            !writer
                .nodes
                .get(&folder.to_ascii_lowercase())
                .is_some_and(|node| node.directory && node.path == *folder)
        }) {
            return Err(Error::invalid(
                "folder.missing",
                "Manifest must declare every matching canonical bundle directory",
            ));
        }
        for file in spec.files {
            writer.write_resource(file.path, Cursor::new(file.bytes))?;
        }
        writer.write_resource(versions::CATALOG_PATH, Cursor::new(spec.catalog))?;
        Ok(writer)
    }

    /// Copy a regular filesystem resource without retaining its bytes.
    pub fn add_path(
        &mut self,
        archive_path: &str,
        source: impl AsRef<Path>,
    ) -> Result<EntryDigest, Error> {
        let result = (|| {
            let source = source.as_ref();
            if !std::fs::metadata(source)
                .map_err(crate::io_failure)?
                .is_file()
            {
                return Err(Error::invalid(
                    "create.resource_type",
                    "Resource source must be a regular file",
                )
                .at(archive_path));
            }
            let file = File::open(source).map_err(crate::io_failure)?;
            if !file.metadata().map_err(crate::io_failure)?.is_file() {
                return Err(Error::invalid(
                    "create.resource_type",
                    "Opened resource is not a regular file",
                )
                .at(archive_path));
            }
            self.add_reader(archive_path, file)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Consume a resource from its current reader position through EOF, using a
    /// 64 KiB buffer. A failed addition poisons this candidate, even if ignored.
    pub fn add_reader(
        &mut self,
        archive_path: &str,
        reader: impl Read,
    ) -> Result<EntryDigest, Error> {
        let result = (|| {
            if self.failed {
                return Err(refused(
                    "create.failed",
                    "A previous resource operation failed; discard this writer",
                ));
            }
            let lower = archive_path.to_ascii_lowercase();
            if matches!(lower.as_str(), "manifest.json" | "readme.md")
                || lower == protection::SIGNATURE_PATH
                || lower.starts_with("docs/darkbox/")
                || lower.starts_with("docs/sqlite/")
            {
                return Err(Error::invalid(
                    "create.reserved",
                    "Writer owns manifest, signature and canonical resource paths",
                )
                .at(archive_path));
            }
            self.write_resource(archive_path, reader)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn check_entry_count(&self) -> Result<(), Error> {
        crate::container::check_deadline(self.deadline)?;
        if self
            .entries
            .checked_add(1 + self.reserved_entries)
            .is_none_or(|count| count > self.limits.max_entries)
        {
            return Err(Error::limit(
                "Streamed entry count exceeds the configured limit",
            ));
        }
        Ok(())
    }

    fn write_resource(&mut self, path: &str, mut reader: impl Read) -> Result<EntryDigest, Error> {
        self.check_entry_count()?;
        crate::paths::insert(&mut self.nodes, path, false)?;
        self.zip
            .as_mut()
            .unwrap()
            .start_file(
                path,
                SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated)
                    .large_file(true),
            )
            .map_err(zip_error)?;
        self.entries += 1;
        let mut size = 0u64;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65_536];
        loop {
            crate::container::check_deadline(self.deadline)?;
            let count = match reader.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result.map_err(|error| {
                    Error::new(Status::OperationalError, "create.read", error.to_string()).at(path)
                })?,
            };
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .filter(|size| *size <= self.limits.max_entry_bytes)
                .ok_or_else(|| {
                    Error::limit("Streamed resource exceeds the configured entry limit").at(path)
                })?;
            self.total = self
                .total
                .checked_add(count as u64)
                .filter(|total| *total <= self.limits.max_total_bytes)
                .ok_or_else(|| {
                    Error::limit("Streamed uncompressed package exceeds the configured total limit")
                })?;
            let bytes = &buffer[..count];
            self.zip
                .as_mut()
                .unwrap()
                .write_all(bytes)
                .map_err(output_error)?;
            hash.update(bytes);
        }
        let digest = EntryDigest {
            path: path.to_owned(),
            size,
            sha256: format!("{:x}", hash.finalize()),
        };
        self.inventory.insert(path.to_owned(), digest.clone());
        Ok(digest)
    }

    /// Finalize the inventory/signature, validate the full candidate and publish
    /// atomically. Every returned Err leaves the prior destination untouched.
    pub fn finish(mut self) -> Result<Report, Error> {
        self.finish_inner(false).map(|(report, _)| report)
    }

    pub(crate) fn previous_snapshot(&mut self, report: &Report, archive: &Path) {
        self.previous = Some(report.clone());
        self.previous_archive = Some(archive.to_owned());
    }

    pub(crate) fn finish_captured(mut self) -> Result<(Report, crate::package::Snapshot), Error> {
        let (report, snapshot) = self.finish_inner(true)?;
        Ok((report, snapshot.unwrap()))
    }

    fn finish_inner(
        &mut self,
        capture: bool,
    ) -> Result<(Report, Option<crate::package::Snapshot>), Error> {
        if self.failed {
            return Err(refused(
                "create.failed",
                "A resource operation failed; candidate cannot be published",
            ));
        }
        let declarations = self.manifest["extensions"].clone();
        for (namespace, descriptor) in declarations.as_object().into_iter().flatten() {
            if let Some(verifier) = self
                .options
                .extensions
                .get(namespace, descriptor["version"].as_str().unwrap_or(""))
            {
                verifier.prepare_streamed_package(
                    self.previous
                        .as_ref()
                        .and_then(|report| report.manifest.as_ref()),
                    &mut self.manifest,
                    &self.inventory,
                )?;
            } else if descriptor["required"] == true {
                return Err(refused(
                    "extension.required",
                    "A required extension has no recognized streaming verifier/writer",
                ));
            }
        }
        for descriptors in [
            self.previous
                .as_ref()
                .and_then(|report| report.manifest.as_ref())
                .map(|manifest| &manifest["extensions"]),
            Some(&declarations),
        ]
        .into_iter()
        .flatten()
        {
            for (namespace, descriptor) in descriptors.as_object().into_iter().flatten() {
                let next = &self.manifest["extensions"][namespace];
                if descriptor["required"] == true
                    && (next["required"] != true || next["version"] != descriptor["version"])
                {
                    return Err(refused(
                        "create.protection_downgrade",
                        "Required extension presence and versions must survive publication",
                    ));
                }
            }
        }
        self.check_optional_preservation()?;
        let protected = self.manifest["extensions"]
            .get(protection::NAMESPACE)
            .is_some();
        if protected != declarations.get(protection::NAMESPACE).is_some() {
            return Err(refused(
                "create.extension_mutation",
                "A streaming callback cannot add or remove the protection descriptor",
            ));
        }
        if self.manifest["extensions"]
            .as_object()
            .into_iter()
            .flatten()
            .any(|(namespace, descriptor)| {
                descriptor["required"] == true && declarations.get(namespace).is_none()
            })
        {
            return Err(refused(
                "create.extension_mutation",
                "A streaming callback cannot introduce an unprepared required extension",
            ));
        }
        let signature = if protected {
            let mut data = protection::data(&self.manifest)?;
            let signer = self.signer.ok_or_else(|| {
                refused(
                    "create.signer_required",
                    "Protected creation requires a manifest signer",
                )
            })?;
            if signer.signer_id() != data.signature.signer_id
                || self.options.trusted_signers.get(signer.signer_id())
                    != Some(&signer.public_key())
            {
                return Err(refused(
                    "create.signer_trust",
                    "Final signer must match an application-trusted public key",
                ));
            }
            data.inventory = self.inventory.values().cloned().collect();
            self.manifest["extensions"][protection::NAMESPACE]["data"] =
                serde_json::to_value(data).unwrap();
            let bytes = serialized_manifest(&self.manifest, self.limits.max_metadata_bytes)?;
            Some((signer.sign(&bytes)?, bytes))
        } else {
            None
        };
        let manifest_bytes = if let Some((signature, bytes)) = signature {
            self.reserved_entries -= 1;
            self.write_resource(protection::SIGNATURE_PATH, Cursor::new(signature))?;
            bytes
        } else {
            serialized_manifest(&self.manifest, self.limits.max_metadata_bytes)?
        };
        self.reserved_entries -= 1;
        self.write_resource("manifest.json", Cursor::new(manifest_bytes))?;
        self.zip.take().unwrap().finish().map_err(zip_error)?;
        self.candidate
            .as_ref()
            .unwrap()
            .as_file()
            .sync_all()
            .map_err(crate::io_failure)?;
        crate::container::check_deadline(self.deadline)?;
        let mut remaining = self.limits.clone();
        remaining.timeout_seconds = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(1);
        let (mut report, staging) = crate::analyze_captured(
            self.candidate.as_ref().unwrap().path(),
            Mode::Verify,
            remaining,
            self.options,
            capture,
        );
        if report.status != Status::Passed {
            let diagnostic = report
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.severity == "error");
            report.file = self.destination.display().to_string();
            return Err(Error::new(
                report.status,
                "create.validation",
                format!(
                    "Candidate failed verification{}; destination was preserved",
                    diagnostic
                        .map(|diagnostic| format!(": {}", diagnostic.code))
                        .unwrap_or_default()
                ),
            )
            .with_report(report));
        }
        crate::writer::check_protected_blocks(
            self.previous.as_ref(),
            &report,
            self.options,
            self.deadline,
        )
        .map_err(|mut error| {
            if error.code == "save.refused" {
                error.code = "create.protection_capability";
            }
            error
        })?;
        self.check_protection_removals(&report)?;
        // Prepare all fallible session state before publication. No reopen is
        // required after replacement, so an Err still means the target survived.
        let snapshot = if capture {
            let (archive, digest) = crate::package::freeze(
                self.candidate.as_ref().unwrap().path(),
                &self.limits,
                self.deadline,
            )?;
            Some(crate::package::Snapshot {
                archive,
                digest,
                staging: staging.unwrap(),
            })
        } else {
            None
        };
        self.check_destination()?;
        report.file = self.destination.display().to_string();
        report.limits = self.limits.clone();
        let parent = self
            .destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        #[cfg(unix)]
        let parent_handle = File::open(parent).map_err(crate::io_failure)?;
        #[cfg(unix)]
        parent_handle.sync_all().map_err(crate::io_failure)?;
        crate::container::check_deadline(self.deadline)?;
        if self.previous_digest.is_some() {
            self.candidate
                .take()
                .unwrap()
                .persist(&self.destination)
                .map_err(|error| crate::io_failure(error.error))?;
        } else {
            self.candidate
                .take()
                .unwrap()
                .persist_noclobber(&self.destination)
                .map_err(|error| crate::io_failure(error.error))?;
        }
        #[cfg(unix)]
        if parent_handle.sync_all().is_err() {
            report.diagnostics.push(crate::Diagnostic { severity: "warning", code: "create.durability".into(), path: None, message: "Package was atomically published but final directory synchronization failed; crash durability is uncertain".into() });
        }
        Ok((report, snapshot))
    }

    fn check_destination(&self) -> Result<(), Error> {
        crate::container::check_deadline(self.deadline)?;
        let unchanged = match (
            self.previous_digest,
            std::fs::symlink_metadata(&self.destination),
        ) {
            (Some(expected), Ok(metadata)) if metadata.is_file() => {
                crate::writer::file_digest(
                    &self.destination,
                    self.limits.max_archive_bytes,
                    self.deadline,
                )? == expected
            }
            (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => true,
            _ => false,
        };
        if !unchanged {
            return Err(Error::new(
                Status::OperationalError,
                "create.destination_changed",
                "Destination changed during preparation; candidate was discarded",
            ));
        }
        Ok(())
    }

    fn check_optional_preservation(&self) -> Result<(), Error> {
        let Some(previous) = &self.previous else {
            return Ok(());
        };
        let manifest = previous.manifest.as_ref().unwrap();
        let unknown: Vec<_> = manifest["extensions"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(namespace, descriptor)| {
                self.options
                    .extensions
                    .get(namespace, descriptor["version"].as_str().unwrap_or(""))
                    .is_none()
            })
            .collect();
        if unknown.is_empty() {
            return Ok(());
        }
        self.check_destination()?;
        let mut archive = zip::ZipArchive::new(
            File::open(self.previous_archive.as_ref().unwrap()).map_err(crate::io_failure)?,
        )
        .map_err(crate::zip_failure)?;
        for (namespace, descriptor) in unknown {
            if descriptor != &self.manifest["extensions"][namespace] {
                return Err(refused(
                    "create.optional_preservation",
                    "Unknown optional descriptors must be preserved",
                ));
            }
            let prefix = format!("extensions/{namespace}/");
            let root = format!("extensions/{namespace}");
            let folders = |metadata: &Value| {
                metadata["folders"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|folder| folder["path"].as_str())
                    .filter(|path| *path == root || path.starts_with(&prefix))
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            };
            if folders(manifest) != folders(&self.manifest) {
                return Err(refused(
                    "create.optional_preservation",
                    "Unknown optional namespace directories must be preserved",
                ));
            }
            let mut expected = BTreeMap::new();
            for index in 0..archive.len() {
                crate::container::check_deadline(self.deadline)?;
                let mut entry = archive.by_index(index).map_err(crate::zip_failure)?;
                if entry.is_dir() || !entry.name().starts_with(&prefix) {
                    continue;
                }
                let path = entry.name().to_owned();
                let mut hash = Sha256::new();
                let mut bytes = 0u64;
                let mut buffer = [0u8; 65_536];
                loop {
                    crate::container::check_deadline(self.deadline)?;
                    let count = entry.read(&mut buffer).map_err(crate::read_failure)?;
                    if count == 0 {
                        break;
                    }
                    bytes = bytes
                        .checked_add(count as u64)
                        .filter(|bytes| *bytes <= self.limits.max_entry_bytes)
                        .ok_or_else(|| {
                            Error::limit("Preserved extension resource exceeds limits")
                        })?;
                    hash.update(&buffer[..count]);
                }
                expected.insert(
                    path.clone(),
                    EntryDigest {
                        path,
                        size: bytes,
                        sha256: format!("{:x}", hash.finalize()),
                    },
                );
            }
            let actual: BTreeMap<_, _> = self
                .inventory
                .iter()
                .filter(|(path, _)| path.starts_with(&prefix))
                .map(|(path, entry)| (path.clone(), entry.clone()))
                .collect();
            if expected != actual {
                return Err(refused(
                    "create.optional_preservation",
                    "Unknown optional resources must be preserved byte-for-byte",
                ));
            }
        }
        Ok(())
    }

    fn check_protection_removals(&self, candidate: &Report) -> Result<(), Error> {
        let Some(previous) = &self.previous else {
            return Ok(());
        };
        let old = previous.manifest.as_ref().unwrap();
        if old["extensions"].get(protection::NAMESPACE).is_none() {
            return Ok(());
        }
        let old = protection::data(old)?;
        let new = protection::data(candidate.manifest.as_ref().unwrap())?;
        for file in old.files {
            if self.inventory.contains_key(&file.path)
                && !new.files.iter().any(|next| next.path == file.path)
            {
                return Err(refused(
                    "create.protection_downgrade",
                    "A retained encrypted resource cannot be declared public; remove it or preserve protection",
                ));
            }
        }
        // Retained protected SQLite columns cannot be silently reclassified as public.
        for column in old.sqlite {
            if self.inventory.contains_key(&column.database)
                && !new.sqlite.iter().any(|next| {
                    next.database == column.database
                        && next.table == column.table
                        && next.column == column.column
                })
            {
                return Err(refused(
                    "create.protection_downgrade",
                    "Removing protected column declarations requires removing the containing database resource",
                ));
            }
        }
        Ok(())
    }
}
