//! Lossless package conversion and content-bound incremental editions.
use crate::{
    Error, Limits, Mode, Report, Status, VerificationOptions, extensions::EntryDigest,
    source::Source,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::NamedTempFile;
use zip::{ZipWriter, write::SimpleFileOptions};

pub(crate) struct Verified {
    source: Source,
    indices: BTreeMap<String, usize>,
    pub(crate) report: Report,
    // Retain verifier scratch files until all application callbacks have finished.
    staging: crate::Staging,
}
impl Verified {
    fn open(
        path: &Path,
        limits: &Limits,
        options: &VerificationOptions<'_>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        let pair = Source::open(path, limits, deadline)?;
        Self::from_source(path, pair, limits, options, deadline)
    }
    pub(crate) fn from_source(
        path: &Path,
        (source, directory): (Source, crate::container::Directory),
        limits: &Limits,
        options: &VerificationOptions<'_>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        Self::from_input(path, (source, directory), limits, options, deadline, false)
    }
    fn open_full(
        path: &Path,
        limits: &Limits,
        options: &VerificationOptions<'_>,
        deadline: Instant,
    ) -> Result<Self, Error> {
        Self::from_input(
            path,
            Source::open(path, limits, deadline)?,
            limits,
            options,
            deadline,
            true,
        )
    }
    fn from_input(
        path: &Path,
        (source, directory): (Source, crate::container::Directory),
        limits: &Limits,
        options: &VerificationOptions<'_>,
        deadline: Instant,
        full: bool,
    ) -> Result<Self, Error> {
        let input = source.fork(limits, deadline)?;
        let (report, staging) = crate::analyze_source(
            path,
            Mode::Verify,
            limits.clone(),
            options,
            false,
            Some(if full {
                crate::AnalysisInput::Full(input)
            } else {
                crate::AnalysisInput::Opened(input)
            }),
        );
        if report.status != Status::Passed {
            return Err(Error::new(
                report.status,
                "transfer.validation",
                "Source package verification failed",
            )
            .with_report(report));
        }
        crate::container::check_deadline(deadline)?;
        Ok(Self {
            source,
            indices: directory
                .names
                .into_iter()
                .enumerate()
                .map(|(i, n)| (n, i))
                .collect(),
            report,
            staging: staging.unwrap(),
        })
    }
    pub(crate) fn files(&self) -> &BTreeMap<String, EntryDigest> {
        &self.staging.digests
    }
    fn copy(
        &mut self,
        name: &str,
        output: &mut impl Write,
        limits: &Limits,
        deadline: Instant,
    ) -> Result<(), Error> {
        let expected = self
            .files()
            .get(name)
            .ok_or_else(|| invalid("Resource is absent from the verified inventory"))?
            .clone();
        let mut entry = self.source.entry(self.indices[name], name)?;
        copy_checked(&mut entry.reader, output, &expected, limits, deadline)
    }
    pub(crate) fn manifest(&self) -> &serde_json::Value {
        self.report.manifest.as_ref().unwrap()
    }
    fn folders(&self) -> Vec<String> {
        let mut folders: Vec<_> = self.manifest()["folders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap().to_owned())
            .collect();
        folders.sort();
        folders
    }
}
fn invalid(message: &str) -> Error {
    Error::invalid("delta.invalid", message)
}
pub(crate) fn deadline(limits: &Limits) -> Result<Instant, Error> {
    if limits.timeout_seconds == 0
        || limits.max_archive_bytes == 0
        || limits.max_entry_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_entries == 0
        || limits.max_metadata_bytes == 0
    {
        return Err(Error::limit("Resource limits must be positive"));
    }
    Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_seconds))
        .ok_or_else(|| Error::limit("Timeout is too large"))
}
fn copy_checked(
    reader: &mut impl Read,
    output: &mut impl Write,
    expected: &EntryDigest,
    limits: &Limits,
    end: Instant,
) -> Result<(), Error> {
    let mut size = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65_536];
    loop {
        crate::container::check_deadline(end)?;
        let count = match reader.read(&mut buffer) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => r.map_err(crate::read_failure)?,
        };
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= limits.max_entry_bytes && *size <= expected.size)
            .ok_or_else(|| {
                Error::limit("Resource grew beyond its verified size or --max-entry-bytes")
            })?;
        output
            .write_all(&buffer[..count])
            .map_err(crate::creation::output_error)?;
        hash.update(&buffer[..count]);
    }
    if size != expected.size || format!("{:x}", hash.finalize()) != expected.sha256 {
        return Err(
            Error::invalid("transfer.changed", "Resource changed since verification")
                .at(&expected.path),
        );
    }
    Ok(())
}
pub(crate) fn output_path(path: &Path, sources: &[&Path]) -> Result<PathBuf, Error> {
    let destination = crate::package::destination(path)?;
    match fs::symlink_metadata(&destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(Error::invalid(
                "transfer.destination_exists",
                "Destination must be absent",
            ));
        }
        Err(error) => return Err(crate::io_failure(error)),
    }
    for source in sources {
        if source.is_dir()
            && destination.starts_with(fs::canonicalize(source).map_err(crate::io_failure)?)
        {
            return Err(Error::invalid(
                "transfer.nested_destination",
                "Destination must be outside every input directory package",
            ));
        }
    }
    Ok(destination)
}

fn write_zip(
    destination: &Path,
    folders: &[String],
    names: &[(String, SimpleFileOptions)],
    limits: &Limits,
    end: Instant,
    mut copy: impl FnMut(usize, &mut ZipWriter<crate::creation::BoundedFile>) -> Result<(), Error>,
) -> Result<NamedTempFile, Error> {
    if folders
        .len()
        .checked_add(names.len())
        .is_none_or(|n| n > limits.max_entries)
    {
        return Err(Error::limit("Output exceeds --max-entries"));
    }
    let candidate = tempfile::Builder::new()
        .prefix(".darkbox-transfer-")
        .tempfile_in(destination.parent().unwrap())
        .map_err(crate::io_failure)?;
    let discarded = Arc::new(AtomicBool::new(false));
    let file = crate::creation::BoundedFile {
        file: candidate.as_file().try_clone().map_err(crate::io_failure)?,
        position: 0,
        end: 0,
        limit: limits.max_archive_bytes,
        deadline: end,
        discarded: discarded.clone(),
    };
    let mut zip = ZipWriter::new(file);
    let result = (|| {
        for folder in folders {
            crate::paths::validate(folder)?;
            zip.add_directory(format!("{folder}/"), SimpleFileOptions::default())
                .map_err(crate::creation::zip_error)?;
        }
        for (index, (name, options)) in names.iter().enumerate() {
            crate::container::check_deadline(end)?;
            crate::paths::validate(name)?;
            zip.start_file(name, *options)
                .map_err(crate::creation::zip_error)?;
            copy(index, &mut zip)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        discarded.store(true, Ordering::Relaxed);
        return Err(error);
    }
    zip.finish().map_err(crate::creation::zip_error)?;
    candidate.as_file().sync_all().map_err(crate::io_failure)?;
    Ok(candidate)
}
fn checked(
    path: &Path,
    limits: &Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let report = crate::analyze_with(path, Mode::Verify, limits.clone(), options);
    if report.status != Status::Passed {
        return Err(Error::new(
            report.status,
            "transfer.validation",
            "Candidate verification failed",
        )
        .with_report(report));
    }
    Ok(report)
}
fn publish(
    candidate: NamedTempFile,
    destination: &Path,
    mut report: Report,
) -> Result<Report, Error> {
    candidate
        .persist_noclobber(destination)
        .map_err(|e| crate::io_failure(e.error))?;
    report.file = destination.display().to_string();
    sync_parent(destination, &mut report);
    Ok(report)
}
fn sync_parent(destination: &Path, report: &mut Report) {
    #[cfg(unix)]
    if File::open(destination.parent().unwrap())
        .and_then(|p| p.sync_all())
        .is_err()
    {
        report.diagnostics.push(crate::Diagnostic {
            severity: "warning",
            code: "transfer.durability".into(),
            path: None,
            message:
                "Published output but parent synchronization failed; crash durability is uncertain"
                    .into(),
        });
    }
    #[cfg(not(unix))]
    let _ = (destination, report);
}

/// Pack a quiescent 1.2.0 directory to a new ZIP, preserving every file byte.
pub fn pack(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let source = source.as_ref();
    let destination = output_path(destination.as_ref(), &[source])?;
    let end = deadline(&limits)?;
    let input = Verified::open(source, &limits, options, end)?;
    if !input.source.is_directory() {
        return Err(Error::invalid(
            "pack.source",
            "Packing requires a directory package",
        ));
    }
    pack_verified(input, &destination, &limits, options, end)
}

pub(crate) fn pack_verified(
    mut input: Verified,
    destination: &Path,
    limits: &Limits,
    options: &VerificationOptions<'_>,
    end: Instant,
) -> Result<Report, Error> {
    let names: Vec<_> = input.files().keys().cloned().collect();
    let candidate = write_zip(
        destination,
        &input.folders(),
        &names
            .iter()
            .map(|name| (name.clone(), crate::media::file_options(name)))
            .collect::<Vec<_>>(),
        limits,
        end,
        |i, output| input.copy(&names[i], output, limits, end),
    )?;
    let report = checked(candidate.path(), limits, options)?;
    input.source.check_retained(end)?;
    crate::container::check_deadline(end)?;
    publish(candidate, destination, report)
}

/// Unpack a supported 1.2.0 ZIP to an absent directory using private staging.
/// No archive paths are used until all common checks have passed.
pub fn unpack(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let source = source.as_ref();
    let destination = output_path(destination.as_ref(), &[source])?;
    let destination_lock = crate::live::destination_lock(&destination)?;
    let end = deadline(&limits)?;
    let mut input = Verified::open(source, &limits, options, end)?;
    if input.source.is_directory()
        || !matches!(
            input.manifest()["darkbox"]["version"].as_str(),
            Some("1.2.0" | "1.3.0" | "1.4.0")
        )
    {
        return Err(Error::new(
            Status::Unsupported,
            "unpack.version",
            "Unpacking requires a Darkbox 1.2.0 or 1.3.0 ZIP",
        ));
    }
    let candidate = tempfile::Builder::new()
        .prefix(".darkbox-unpack-")
        .tempdir_in(destination.parent().unwrap())
        .map_err(crate::io_failure)?;
    let folders = input.folders();
    for folder in &folders {
        fs::create_dir(candidate.path().join(folder)).map_err(crate::io_failure)?;
    }
    let names: Vec<_> = input.files().keys().cloned().collect();
    for name in names {
        let mut file = File::create(candidate.path().join(&name)).map_err(crate::io_failure)?;
        input.copy(&name, &mut file, &limits, end)?;
        file.sync_all().map_err(crate::io_failure)?;
    }
    let pair = Source::directory_locked(
        candidate.path(),
        destination_lock,
        BTreeMap::new(),
        &BTreeSet::new(),
        &limits,
        end,
    )?;
    let verified = Verified::from_source(candidate.path(), pair, &limits, options, end)?;
    let mut report = verified.report;
    #[cfg(unix)]
    for folder in folders
        .iter()
        .rev()
        .map(|f| candidate.path().join(f))
        .chain([candidate.path().to_owned()])
    {
        File::open(folder)
            .and_then(|f| f.sync_all())
            .map_err(crate::io_failure)?;
    }
    crate::container::check_deadline(end)?;
    // Reserve the absent name. On Unix rename replaces only our empty directory.
    // Parent directories are caller-controlled, as for all SDK publication APIs.
    fs::create_dir(&destination).map_err(crate::io_failure)?;
    if let Err(error) = fs::rename(candidate.path(), &destination) {
        let _ = fs::remove_dir(&destination);
        return Err(crate::io_failure(error));
    }
    report.file = destination.display().to_string();
    sync_parent(&destination, &mut report);
    Ok(report)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identity {
    package_id: String,
    manifest_sha256: String,
    inventory_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Delta {
    darkbox_delta: String,
    base: Identity,
    target: Identity,
    target_files: Vec<EntryDigest>,
    folders: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
}
fn identity(input: &Verified) -> Result<Identity, Error> {
    if !matches!(
        input.manifest()["darkbox"]["version"].as_str(),
        Some("1.2.0" | "1.3.0" | "1.4.0")
    ) {
        return Err(Error::new(
            Status::Unsupported,
            "delta.version",
            "Delta editions require Darkbox 1.2.0 or 1.3.0",
        ));
    }
    let id = input.manifest()["packageId"]
        .as_str()
        .ok_or_else(|| invalid("Delta editions require manifest packageId"))?;
    let inventory: Vec<_> = input.files().values().collect();
    Ok(Identity {
        package_id: id.into(),
        manifest_sha256: input.files()["manifest.json"].sha256.clone(),
        inventory_sha256: format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&inventory).unwrap())
        ),
    })
}
fn compatible(base: &Verified, target: &Verified) -> Result<(), Error> {
    if identity(base)?.package_id != identity(target)?.package_id {
        return Err(invalid("Base and target must have the same packageId"));
    }
    for (ns, descriptor) in base.manifest()["extensions"]
        .as_object()
        .into_iter()
        .flatten()
    {
        if descriptor["required"] == true
            && (target.manifest()["extensions"][ns]["required"] != true
                || target.manifest()["extensions"][ns]["version"] != descriptor["version"])
        {
            return Err(invalid(
                "A delta cannot remove or change a required extension",
            ));
        }
    }
    Ok(())
}
/// Create a delta between two verified complete editions. Only changed files are
/// copied. SQLite databases are whole-file resources, not page-level patches.
pub fn create_delta(
    base: impl AsRef<Path>,
    target: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let destination = output_path(destination.as_ref(), &[base.as_ref(), target.as_ref()])?;
    let end = deadline(&limits)?;
    let base = Verified::open_full(base.as_ref(), &limits, options, end)?;
    let target = Verified::open(target.as_ref(), &limits, options, end)?;
    delta_verified(base, target, &destination, &limits, end)
}

pub(crate) fn delta_from_verified(
    base: &Path,
    target: Verified,
    destination: &Path,
    limits: &Limits,
    options: &VerificationOptions<'_>,
    end: Instant,
) -> Result<Report, Error> {
    let base = Verified::open_full(base, limits, options, end)?;
    delta_verified(base, target, destination, limits, end)
}
fn delta_verified(
    base: Verified,
    mut target: Verified,
    destination: &Path,
    limits: &Limits,
    end: Instant,
) -> Result<Report, Error> {
    compatible(&base, &target)?;
    let descriptor = Delta {
        darkbox_delta: "1.0.0".into(),
        base: identity(&base)?,
        target: identity(&target)?,
        target_files: target.files().values().cloned().collect(),
        folders: target.folders(),
        changed: target
            .files()
            .iter()
            .filter(|(path, digest)| base.files().get(*path) != Some(*digest))
            .map(|(path, _)| path.clone())
            .collect(),
        removed: base
            .files()
            .keys()
            .filter(|path| !target.files().contains_key(*path))
            .cloned()
            .collect(),
    };
    let metadata = serde_json::to_value(&descriptor).unwrap();
    let bytes = crate::creation::serialized_manifest(&metadata, limits.max_metadata_bytes)?;
    if bytes.len() as u64 > limits.max_entry_bytes {
        return Err(Error::limit("Delta descriptor exceeds --max-entry-bytes"));
    }
    let changed_size = descriptor
        .changed
        .iter()
        .try_fold(bytes.len() as u64, |total, path| {
            total.checked_add(target.files()[path].size)
        })
        .ok_or_else(|| Error::limit("Delta size overflows"))?;
    if changed_size > limits.max_total_bytes {
        return Err(Error::limit("Delta exceeds --max-total-bytes"));
    }
    let names: Vec<_> = std::iter::once("delta.json".into())
        .chain((0..descriptor.changed.len()).map(|i| format!("files/{i}")))
        .collect();
    let folders = if descriptor.changed.is_empty() {
        vec![]
    } else {
        vec!["files".into()]
    };
    let candidate = write_zip(
        destination,
        &folders,
        &names
            .iter()
            .enumerate()
            .map(|(index, name)| {
                let logical = if index == 0 {
                    name.as_str()
                } else {
                    descriptor.changed[index - 1].as_str()
                };
                (name.clone(), crate::media::file_options(logical))
            })
            .collect::<Vec<_>>(),
        limits,
        end,
        |index, zip| {
            if index == 0 {
                zip.write_all(&bytes).map_err(crate::creation::output_error)
            } else {
                target.copy(&descriptor.changed[index - 1], zip, limits, end)
            }
        },
    )?;
    target.source.check_retained(end)?;
    let mut report = target.report;
    report.scope = "delta_creation";
    report.checks.push("delta.base_and_target");
    report.note("delta.base_required", "This incremental transfer requires its exact verified base; it is not a standalone Darkbox package");
    crate::container::check_deadline(end)?;
    publish(candidate, destination, report)
}

fn reconstruct(
    base_path: &Path,
    delta_path: &Path,
    destination: &Path,
    limits: &Limits,
    options: &VerificationOptions<'_>,
    end: Instant,
) -> Result<(NamedTempFile, Report), Error> {
    let mut base = Verified::open_full(base_path, limits, options, end)?;
    let (mut source, directory) = Source::open(delta_path, limits, end)?;
    if source.is_directory() {
        return Err(invalid("A delta must be a ZIP transfer"));
    }
    let index = directory
        .names
        .iter()
        .position(|n| n == "delta.json")
        .ok_or_else(|| invalid("Missing delta.json"))?;
    let bytes = {
        let mut entry = source.entry(index, "delta.json")?;
        crate::read_metadata(&mut entry.reader, limits, end)?
    };
    let descriptor: Delta = serde_json::from_value(crate::json::parse(&bytes)?)
        .map_err(|_| invalid("Malformed delta descriptor"))?;
    if descriptor.darkbox_delta != "1.0.0" {
        return Err(Error::new(
            Status::Unsupported,
            "delta.version",
            "Unsupported delta transfer version",
        ));
    }
    if identity(&base)? != descriptor.base
        || descriptor.base.package_id != descriptor.target.package_id
    {
        return Err(invalid(
            "The supplied base does not match the complete delta base identity",
        ));
    }
    if descriptor
        .target_files
        .windows(2)
        .any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(invalid(
            "Target file inventory must be sorted by unique ASCII path",
        ));
    }
    let mut nodes = crate::paths::Nodes::new();
    let mut expected = BTreeMap::new();
    let mut total = 0u64;
    for folder in &descriptor.folders {
        crate::paths::insert(&mut nodes, folder, true)?;
    }
    for file in &descriptor.target_files {
        crate::container::check_deadline(end)?;
        crate::paths::insert(&mut nodes, &file.path, false)?;
        total = total
            .checked_add(file.size)
            .filter(|sum| *sum <= limits.max_total_bytes)
            .ok_or_else(|| Error::limit("Delta target exceeds --max-total-bytes"))?;
        if file.size > limits.max_entry_bytes {
            return Err(Error::limit("Delta target exceeds --max-entry-bytes"));
        }
        expected.insert(file.path.clone(), file.clone());
    }
    if expected.len() + descriptor.folders.len() > limits.max_entries {
        return Err(Error::limit("Delta target exceeds --max-entries"));
    }
    let changed: Vec<_> = expected
        .iter()
        .filter(|(path, digest)| base.files().get(*path) != Some(*digest))
        .map(|(path, _)| path.clone())
        .collect();
    let removed: Vec<_> = base
        .files()
        .keys()
        .filter(|path| !expected.contains_key(*path))
        .cloned()
        .collect();
    if changed != descriptor.changed || removed != descriptor.removed {
        return Err(invalid(
            "Changed and removed paths must exactly describe the target inventory",
        ));
    }
    let expected_names: BTreeSet<String> = std::iter::once("delta.json".into())
        .chain((0..changed.len()).map(|i| format!("files/{i}")))
        .collect();
    let actual_names: BTreeSet<_> = directory
        .names
        .iter()
        .filter(|n| !n.ends_with('/'))
        .cloned()
        .collect();
    if actual_names != expected_names
        || directory
            .names
            .iter()
            .any(|n| n.ends_with('/') && (n != "files/" || changed.is_empty()))
    {
        return Err(invalid(
            "Delta transfer contains missing or unexpected entries",
        ));
    }
    // Validate type, CRC, sizes and total bytes for every transfer entry, even metadata.
    let mut actual_total = 0;
    for (index, name) in directory.names.iter().enumerate() {
        let mut entry = source.entry(index, name)?;
        let scan = crate::stream(
            &mut entry.reader,
            None,
            false,
            limits,
            &mut actual_total,
            end,
        )?;
        if scan.size != entry.size || Some(scan.crc) != entry.crc {
            return Err(invalid("Delta entry CRC or size mismatch"));
        }
        if name == "delta.json"
            && (scan.size != bytes.len() as u64
                || scan.sha256 != format!("{:x}", Sha256::digest(&bytes)))
        {
            return Err(invalid("Delta descriptor changed during verification"));
        }
    }
    let indices: BTreeMap<_, _> = directory
        .names
        .iter()
        .enumerate()
        .map(|(i, n)| (n.clone(), i))
        .collect();
    let changed_indices: BTreeMap<_, _> = changed
        .iter()
        .enumerate()
        .map(|(i, n)| (n.as_str(), i))
        .collect();
    let names: Vec<_> = expected.keys().cloned().collect();
    let candidate = write_zip(
        destination,
        &descriptor.folders,
        &names
            .iter()
            .map(|name| (name.clone(), crate::media::file_options(name)))
            .collect::<Vec<_>>(),
        limits,
        end,
        |i, zip| {
            let name = &names[i];
            if let Some(index) = changed_indices.get(name.as_str()) {
                let transfer_name = format!("files/{index}");
                let mut entry = source.entry(indices[&transfer_name], &transfer_name)?;
                copy_checked(&mut entry.reader, zip, &expected[name], limits, end)
            } else {
                base.copy(name, zip, limits, end)
            }
        },
    )?;
    let target = Verified::open(candidate.path(), limits, options, end)?;
    if target.files() != &expected
        || target.folders() != descriptor.folders
        || identity(&target)? != descriptor.target
    {
        return Err(invalid(
            "Reconstructed target does not match its declared identity",
        ));
    }
    compatible(&base, &target)?;
    let mut report = target.report;
    report.checks.extend(["delta.base", "delta.target"]);
    crate::container::check_deadline(end)?;
    Ok((candidate, report))
}
/// Reconstruct and fully verify one delta link, publishing a complete new ZIP.
/// Apply each subsequent link to the preceding verified result to check a chain.
pub fn merge(
    base: impl AsRef<Path>,
    delta: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let destination = output_path(destination.as_ref(), &[base.as_ref(), delta.as_ref()])?;
    let end = deadline(&limits)?;
    let (candidate, report) = reconstruct(
        base.as_ref(),
        delta.as_ref(),
        &destination,
        &limits,
        options,
        end,
    )?;
    publish(candidate, &destination, report)
}
/// Verify the exact base, delta transport and reconstructed complete edition,
/// without publishing a file. Scratch output follows Limits::staging_directory.
pub fn verify_delta(
    base: impl AsRef<Path>,
    delta: impl AsRef<Path>,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let end = deadline(&limits)?;
    let scratch = limits.tempdir("darkbox-delta-")?;
    let (_, mut report) = reconstruct(
        base.as_ref(),
        delta.as_ref(),
        &scratch.path().join("result"),
        &limits,
        options,
        end,
    )?;
    report.file = delta.as_ref().display().to_string();
    report.scope = "delta_against_base";
    Ok(report)
}
