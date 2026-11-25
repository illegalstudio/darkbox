//! Common-rule analysis of one ZIP or directory package, as ordered phases:
//! entry listing, manifest and version identification, schema and inventory,
//! one bounded pass over every byte, then SQLite, extension and profile checks.
use crate::model::{ApplicationValidation, EntryInfo, EntryKind, Failure, Manifest, Result, Scope};
use crate::versions::{self, CATALOG_PATH, CanonicalFile, RuleSet, VersionSpec};
use crate::{
    Limits, Mode, Report, Status, VerificationOptions, container, extensions, io_failure, json,
    live, paths, profiles, protection, read_failure, resource_inventory, source, sqlite,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Files extracted to private storage during one analysis.
pub(crate) struct Staging {
    pub _directory: tempfile::TempDir,
    pub files: BTreeMap<String, PathBuf>,
    pub digests: BTreeMap<String, extensions::EntryDigest>,
}

/// An already opened input, when the caller holds it.
pub(crate) enum AnalysisInput {
    File(File),
    Opened((source::Source, container::Directory)),
    /// Opened input that must be read completely, ignoring trusted digests.
    Full((source::Source, container::Directory)),
}

pub(crate) fn analyze_source(
    path: &Path,
    mode: Mode,
    limits: Limits,
    options: &VerificationOptions<'_>,
    capture: bool,
    input: Option<AnalysisInput>,
) -> (Report, Option<Staging>) {
    let mut report = Report::new(mode, path.display().to_string(), limits);
    let mut staging = None;
    if let Err(error) = run(
        path,
        mode,
        &mut report,
        options,
        capture,
        &mut staging,
        input,
    ) {
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
    if report.application_validation == ApplicationValidation::NotPerformed {
        report.note("profile.not_validated", "Application data semantics and the accuracy or completeness of profile documentation have not been validated");
    }
    (report, staging)
}

fn run(
    path: &Path,
    mode: Mode,
    report: &mut Report,
    options: &VerificationOptions<'_>,
    capture_all: bool,
    captured: &mut Option<Staging>,
    input: Option<AnalysisInput>,
) -> Result<()> {
    let limits = report.limits.clone();
    limits.check()?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_seconds))
        .ok_or_else(|| Failure::limit("Processing timeout is too large"))?;
    let allow_cached = !matches!(&input, Some(AnalysisInput::Full(_)));
    let (mut archive, directory) = match input {
        Some(AnalysisInput::File(file)) => source::Source::zip(file, &limits, deadline)?,
        Some(AnalysisInput::Opened(pair) | AnalysisInput::Full(pair)) => pair,
        None => source::Source::open(path, &limits, deadline)?,
    };
    let directory_form = archive.is_directory();
    list_entries(&mut archive, &directory, &limits, deadline, report)?;
    report.checks.push(if directory_form {
        "directory.structure"
    } else {
        "zip.structure"
    });

    let manifest_bytes = read_manifest(&mut archive, &directory, &limits, deadline)?;
    let value = json::parse(&manifest_bytes)?;
    report.manifest = Some(value.clone());
    if options.require_protection && value["extensions"].get(protection::NAMESPACE).is_none() {
        report.record(Failure::invalid(
            "protection.missing",
            "Application policy requires the protection extension",
        ));
    }
    report.checks.push("manifest.json");
    let spec = identify(&value, mode, report)?;
    let canonical_files = spec
        .map(|spec| versions::canonical_files(spec, &value))
        .unwrap_or_default();

    // `common` stays true while the package can still be judged by the common
    // rules of its declared version. A failed layer stops the deeper ones.
    let mut common = mode != Mode::Inspect && spec.is_some();
    if common {
        common = check_schema(spec.unwrap(), &value, report)?;
    }
    let manifest: Option<Manifest> = serde_json::from_value(value.clone()).ok();
    if common && manifest.is_none() {
        return Err(Failure::invalid(
            "manifest.structure",
            "Manifest inventory is unreadable",
        ));
    }
    if directory_form {
        live::check_quiescence(&mut archive, &directory.names, &value)?;
    }
    if common {
        if let Err(error) = inventory(
            manifest.as_ref().unwrap(),
            &value,
            &directory.nodes,
            spec.unwrap(),
        ) {
            report.record(error);
            common = false;
        } else {
            report.checks.push("inventory");
        }
    }
    if directory_form && !spec.is_some_and(|spec| spec.capabilities.directory) {
        return Err(Failure::new(
            Status::Unsupported,
            "directory.version",
            "Directory form requires an explicitly supported common version with directory storage",
        ));
    }
    if mode == Mode::Inventory {
        if common && report.status == Status::Inspected {
            resource_inventory::claims(report)?;
        }
        return Ok(());
    }
    if common
        && value.get("packageId").is_some()
        && value["extensions"].get(protection::NAMESPACE).is_some()
        && value["packageId"] != value["extensions"][protection::NAMESPACE]["data"]["packageId"]
    {
        report.record(Failure::invalid(
            "manifest.package_id",
            "Root packageId must match protection data.packageId",
        ));
    }

    let temporary = limits.tempdir("darkbox-")?;
    let databases: BTreeMap<&str, &crate::model::Database> = manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .databases
                .iter()
                .map(|database| (database.path.as_str(), database))
                .collect()
        })
        .unwrap_or_default();
    let plan = StagingPlan::new(common, capture_all, manifest.as_ref(), &value, options);
    let scan = scan_entries(
        ScanInput {
            archive: &mut archive,
            names: &directory.names,
            manifest: manifest.as_ref(),
            manifest_bytes: &manifest_bytes,
            spec,
            canonical_files: &canonical_files,
            databases: &databases,
            plan: &plan,
            options,
            limits: &limits,
            deadline,
            staging: temporary.path(),
            common,
            directory_form,
            // Trusted digests apply only to live-capable directory versions.
            allow_trusted: allow_cached
                && directory_form
                && spec.is_some_and(|spec| spec.capabilities.live_directory),
        },
        report,
    )?;
    report.checks.push(if !report.trusted_resources.is_empty() {
        "directory.incremental"
    } else if directory_form {
        "directory.bytes"
    } else {
        "zip.crc"
    });
    if scan.canonical_ok {
        report.checks.push("bundle.canonical");
    }

    if common {
        check_database_files(&scan.signatures, &databases, report);
        if scan.profile_ok {
            report.checks.push("profile.presence_and_encoding");
        }
        check_extensions(
            ExtensionInput {
                manifest: manifest.as_ref().unwrap(),
                value: &value,
                manifest_bytes: &manifest_bytes,
                spec: spec.unwrap(),
                scan: &scan,
                options,
                limits: &limits,
                deadline,
            },
            report,
        );
        if let Err(error) = resource_inventory::check(&value, &scan.digests, report) {
            report.record(error);
        }
    }

    let mut sqlite_ok = common;
    for (name, database) in &databases {
        if let Some(path) = scan.staged.get(*name) {
            match sqlite::examine(
                path,
                database,
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
    if let Some(manifest) = &manifest {
        report.note(
            "profile.identity",
            format!(
                "Declared profile: {} data format {}",
                manifest.application.id, manifest.application.format_version
            ),
        );
    }
    if common && report.status == Status::Passed {
        validate_profile(&value, &scan, options, &limits, deadline, report);
    }
    if !report.trusted_resources.is_empty() {
        report.scope = Scope::CommonChecksWithTrustedResources;
        report.note("directory.trusted_resources", "Application-trusted digests replaced full byte reads for the listed resources. This is conditional validation, not a full byte verification.");
    }
    container::check_deadline(deadline)?;
    *captured = Some(Staging {
        _directory: temporary,
        files: scan.staged,
        digests: scan.digests,
    });
    Ok(())
}

/// Record every container entry and bound the declared sizes.
fn list_entries(
    archive: &mut source::Source,
    directory: &container::Directory,
    limits: &Limits,
    deadline: Instant,
    report: &mut Report,
) -> Result<()> {
    let mut total_declared = 0u64;
    for (index, name) in directory.names.iter().enumerate() {
        container::check_deadline(deadline)?;
        let file = archive.entry(index, name)?;
        if file.size > limits.max_entry_bytes {
            return Err(
                Failure::limit("Uncompressed entry exceeds the configured byte limit").at(name),
            );
        }
        total_declared = total_declared
            .checked_add(file.size)
            .filter(|sum| *sum <= limits.max_total_bytes)
            .ok_or_else(|| {
                Failure::limit("Total uncompressed size exceeds the configured limit")
            })?;
        report.entries.push(EntryInfo {
            path: name.clone(),
            kind: if name.ends_with('/') {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            compressed_bytes: file.compressed,
            bytes: file.size,
            compression: file.compression,
            crc_verified: false,
        });
    }
    Ok(())
}

fn read_manifest(
    archive: &mut source::Source,
    directory: &container::Directory,
    limits: &Limits,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let index = directory
        .names
        .iter()
        .position(|name| name == "manifest.json")
        .ok_or_else(|| {
            Failure::invalid("manifest.missing", "Required root manifest.json is missing")
        })?;
    let mut file = archive.entry(index, "manifest.json")?;
    if file.size > limits.max_metadata_bytes {
        return Err(Failure::limit(
            "Manifest exceeds the configured metadata limit",
        ));
    }
    read_metadata(&mut file.reader, limits, deadline)
}

/// Select the exact supported common version the manifest declares.
fn identify(
    value: &serde_json::Value,
    mode: Mode,
    report: &mut Report,
) -> Result<Option<&'static VersionSpec>> {
    let id = value
        .pointer("/darkbox/id")
        .and_then(|value| value.as_str());
    let version = value
        .pointer("/darkbox/version")
        .and_then(|value| value.as_str());
    let (Some(id), Some(version)) = (id, version) else {
        return Err(Failure::invalid(
            "manifest.identity",
            "The manifest must declare string darkbox.id and darkbox.version fields",
        ));
    };
    let spec = (id == "darkbox").then(|| versions::find(version)).flatten();
    if spec.is_none() {
        let message = format!("Unsupported specification: {id} {version}");
        if mode != Mode::Inspect {
            report.record(Failure::new(
                Status::Unsupported,
                "version.unsupported",
                message,
            ));
        } else {
            report.note("version.unsupported", message);
        }
    }
    Ok(spec)
}

/// Validate the manifest against its version-specific schema. Returns whether
/// the deeper common checks can still run.
fn check_schema(
    spec: &VersionSpec,
    value: &serde_json::Value,
    report: &mut Report,
) -> Result<bool> {
    match spec.rules {
        RuleSet::V1 => {}
    }
    let reference =
        |error: String| Failure::new(Status::OperationalError, "reference.schema", error);
    let schema: serde_json::Value =
        serde_json::from_str(spec.schema).map_err(|error| reference(error.to_string()))?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| reference(error.to_string()))?;
    let mut errors = validator.iter_errors(value).peekable();
    if errors.peek().is_none() {
        report.checks.push("manifest.schema");
        return Ok(true);
    }
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
    Ok(false)
}

/// Which entries are extracted to private staging during the byte pass.
struct StagingPlan {
    all: bool,
    paths: BTreeSet<String>,
}

impl StagingPlan {
    fn new(
        common: bool,
        capture_all: bool,
        manifest: Option<&Manifest>,
        value: &serde_json::Value,
        options: &VerificationOptions<'_>,
    ) -> Self {
        let mut plan = Self {
            // A registered application profile may read any resource.
            all: capture_all
                || (common
                    && manifest.is_some_and(|manifest| {
                        options
                            .profiles
                            .get(
                                &manifest.application.id,
                                &manifest.application.format_version,
                            )
                            .is_some()
                    })),
            paths: BTreeSet::new(),
        };
        if let (true, Some(manifest)) = (common, manifest) {
            for (namespace, extension) in &manifest.extensions {
                if let Some(verifier) = options.extensions.get(namespace, &extension.version) {
                    match verifier.resources_to_stage(value) {
                        Some(paths) => plan.paths.extend(paths),
                        None => plan.all = true,
                    }
                }
            }
        }
        plan
    }

    fn includes(&self, name: &str) -> bool {
        self.all || self.paths.contains(name)
    }
}

struct ScanInput<'a, 'o> {
    archive: &'a mut source::Source,
    names: &'a [String],
    manifest: Option<&'a Manifest>,
    manifest_bytes: &'a [u8],
    spec: Option<&'static VersionSpec>,
    canonical_files: &'a [&'static CanonicalFile],
    databases: &'a BTreeMap<&'a str, &'a crate::model::Database>,
    plan: &'a StagingPlan,
    options: &'a VerificationOptions<'o>,
    limits: &'a Limits,
    deadline: Instant,
    staging: &'a Path,
    common: bool,
    directory_form: bool,
    allow_trusted: bool,
}

/// What the single pass over every entry learned.
struct ScanOutcome {
    staged: BTreeMap<String, PathBuf>,
    /// First bytes of each file, to recognize SQLite databases and sidecars.
    signatures: BTreeMap<String, Vec<u8>>,
    digests: BTreeMap<String, extensions::EntryDigest>,
    canonical_ok: bool,
    profile_ok: bool,
}

/// Read every entry once: check size and CRC, hash it, compare canonical
/// files with their trusted references and stage what later checks need.
fn scan_entries(input: ScanInput<'_, '_>, report: &mut Report) -> Result<ScanOutcome> {
    let ScanInput {
        archive,
        names,
        manifest,
        manifest_bytes,
        spec,
        canonical_files,
        databases,
        plan,
        options,
        limits,
        deadline,
        staging,
        common,
        directory_form,
        allow_trusted,
    } = input;
    let mut outcome = ScanOutcome {
        staged: BTreeMap::new(),
        signatures: BTreeMap::new(),
        digests: BTreeMap::new(),
        canonical_ok: common,
        profile_ok: common,
    };
    let mut total_actual = 0u64;
    for (index, name) in names.iter().enumerate() {
        container::check_deadline(deadline)?;
        let mut file = archive.entry(index, name)?;
        let is_file = !name.ends_with('/');
        let expected = canonical_files
            .iter()
            .copied()
            .find(|expected| expected.path == name);
        let catalog = name == CATALOG_PATH;
        let profile = manifest.is_some_and(|manifest| manifest.application.profile_path == *name);
        // Metadata and canonical documentation are also held in memory.
        let capture =
            name == "manifest.json" || profile || (common && (expected.is_some() || catalog));
        let destination =
            if is_file && (databases.contains_key(name.as_str()) || plan.includes(name)) {
                let destination = staging.join(format!("entry-{index}"));
                let handle = File::create(&destination).map_err(io_failure)?;
                outcome.staged.insert(name.clone(), destination);
                Some(handle)
            } else {
                None
            };
        let expected_crc = file.crc;
        let expected_size = file.size;
        let trusted = if allow_trusted
            && common
            && !capture
            && destination.is_none()
            && is_file
            && !name.starts_with("extensions/")
        {
            options
                .trusted_digests
                .and_then(|cache| cache.sha256(name, expected_size))
        } else {
            None
        };
        let scan = if let Some(hash) = trusted {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(Failure::invalid(
                    "directory.trusted_digest",
                    "Trusted SHA-256 must be 64 lowercase hex characters",
                )
                .at(name));
            }
            total_actual = total_actual
                .checked_add(expected_size)
                .filter(|n| *n <= limits.max_total_bytes)
                .ok_or_else(|| Failure::limit("Trusted resources exceed total limits"))?;
            let mut prefix = vec![0; expected_size.min(16) as usize];
            file.reader.read_exact(&mut prefix).map_err(read_failure)?;
            report.trusted_resources.push(extensions::EntryDigest {
                path: name.clone(),
                size: expected_size,
                sha256: hash.clone(),
            });
            Scan {
                size: expected_size,
                crc: 0,
                sha256: hash,
                prefix,
                bytes: vec![],
            }
        } else {
            stream(
                &mut file.reader,
                destination,
                capture,
                limits,
                &mut total_actual,
                deadline,
            )
            .map_err(|error| error.at(name))?
        };
        if scan.size != expected_size || expected_crc.is_some_and(|crc| scan.crc != crc) {
            return Err(Failure::invalid(
                "zip.crc",
                "ZIP entry size or CRC does not match its data",
            )
            .at(name));
        }
        report.entries[index].crc_verified = !directory_form;
        if name == "manifest.json" && scan.bytes != manifest_bytes {
            return Err(Failure::new(
                Status::OperationalError,
                "io.changed",
                "The manifest changed during analysis",
            ));
        }
        if is_file {
            outcome.signatures.insert(name.clone(), scan.prefix);
            outcome.digests.insert(
                name.clone(),
                extensions::EntryDigest {
                    path: name.clone(),
                    size: scan.size,
                    sha256: scan.sha256.clone(),
                },
            );
        }
        if !common {
            continue;
        }
        if let Some(expected) = expected
            && (scan.size != expected.bytes.len() as u64
                || scan.sha256 != expected.sha256
                || scan.bytes != expected.bytes)
        {
            outcome.canonical_ok = false;
            report.record(
                Failure::invalid(
                    "bundle.file",
                    "Canonical file differs from the official version-specific reference",
                )
                .at(name),
            );
        }
        if catalog && scan.bytes != spec.unwrap().catalog {
            outcome.canonical_ok = false;
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
            outcome.profile_ok = false;
            report.record(
                Failure::invalid(
                    "profile.encoding",
                    "Profile documentation must be readable UTF-8 without a BOM",
                )
                .at(name),
            );
        }
    }
    Ok(outcome)
}

/// Every standalone SQLite database must be declared, and snapshots carry no
/// journal, WAL or shared-memory sidecars.
fn check_database_files(
    signatures: &BTreeMap<String, Vec<u8>>,
    databases: &BTreeMap<&str, &crate::model::Database>,
    report: &mut Report,
) {
    for (name, prefix) in signatures {
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
}

struct ExtensionInput<'a, 'o> {
    manifest: &'a Manifest,
    value: &'a serde_json::Value,
    manifest_bytes: &'a [u8],
    spec: &'static VersionSpec,
    scan: &'a ScanOutcome,
    options: &'a VerificationOptions<'o>,
    limits: &'a Limits,
    deadline: Instant,
}

/// Run registered extension verifiers; classify the extensions without one.
fn check_extensions(input: ExtensionInput<'_, '_>, report: &mut Report) {
    let context = extensions::ExtensionContext {
        manifest: input.value,
        manifest_bytes: input.manifest_bytes,
        inventory: &input.scan.digests,
        options: input.options,
        limits: input.limits,
        deadline: input.deadline,
        staged: &input.scan.staged,
    };
    for (namespace, extension) in &input.manifest.extensions {
        if input.spec.capabilities.extension_bundles
            && versions::official_directory(namespace).is_some()
            && versions::extension_bundle(input.spec, namespace, &extension.version).is_none()
        {
            report.note(
                "extension.bundle_unverified",
                format!(
                    "No trusted reference is available for the canonical bundle of {namespace} {}; its documentation was not verified",
                    extension.version
                ),
            );
        }
        if namespace == protection::NAMESPACE && !extension.required {
            report.record(Failure::invalid(
                "protection.required",
                "Protection must be a required extension",
            ));
            continue;
        }
        if let Some(verifier) = input.options.extensions.get(namespace, &extension.version) {
            if let Err(error) = verifier.verify(&context, report) {
                report.record(error);
            }
        } else if extension.required {
            report.record(Failure::new(
                Status::Unsupported,
                if namespace == protection::NAMESPACE && extension.version != protection::VERSION {
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

/// Application semantics, validated only by code the application registered.
fn validate_profile(
    value: &serde_json::Value,
    scan: &ScanOutcome,
    options: &VerificationOptions<'_>,
    limits: &Limits,
    deadline: Instant,
    report: &mut Report,
) {
    let context = profiles::ProfileContext {
        manifest: value,
        inventory: &scan.digests,
        limits,
        deadline,
        options,
        staged: &scan.staged,
    };
    let registered = options.profiles.get(
        value["application"]["id"].as_str().unwrap(),
        value["application"]["formatVersion"].as_str().unwrap(),
    );
    if let Some(profile) = registered {
        match profile.validate(&context) {
            Ok(()) => {
                report.application_validation = ApplicationValidation::Passed;
                report.checks.push("profile.application");
            }
            Err(mut error) => {
                report.application_validation = ApplicationValidation::Failed;
                if matches!(error.status, Status::Passed | Status::Inspected) {
                    error.status = Status::Invalid;
                }
                report.record(error);
            }
        }
    } else if options.require_profile {
        report.application_validation = ApplicationValidation::Unsupported;
        report.record(Failure::new(
            Status::Unsupported,
            "profile.unsupported",
            "Application policy requires a registered verifier for this exact profile version",
        ));
    }
}

pub(crate) fn read_metadata(
    reader: &mut impl Read,
    limits: &Limits,
    deadline: Instant,
) -> Result<Vec<u8>> {
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

/// Size, checksums and leading bytes of one streamed entry.
pub(crate) struct Scan {
    pub size: u64,
    pub crc: u32,
    pub sha256: String,
    pub prefix: Vec<u8>,
    pub bytes: Vec<u8>,
}

pub(crate) fn stream(
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
        sha256: crate::digest::hex(sha.finalize()),
        prefix,
        bytes,
    })
}

/// Compare the manifest inventory with the container's actual tree.
fn inventory(
    manifest: &Manifest,
    value: &serde_json::Value,
    nodes: &paths::Nodes,
    spec: &'static VersionSpec,
) -> Result<()> {
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
    // The common bundle plus the bundle of every declared official extension.
    let canonical: BTreeSet<_> = versions::canonical_files(spec, value)
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
    let canonical_folders = versions::canonical_folders(spec, value).map_err(|error| {
        Failure::new(
            Status::OperationalError,
            "reference.catalog",
            error.to_string(),
        )
    })?;
    let canonical_folders: BTreeSet<_> = canonical_folders.iter().map(String::as_str).collect();
    // A declared official extension without a trusted reference keeps its
    // directory: its documentation is reported as unverified, not as corrupt.
    let unverifiable: Vec<String> = if spec.capabilities.extension_bundles {
        manifest
            .extensions
            .iter()
            .filter(|(namespace, extension)| {
                versions::extension_bundle(spec, namespace, &extension.version).is_none()
            })
            .filter_map(|(namespace, _)| versions::official_directory(namespace))
            .collect()
    } else {
        Vec::new()
    };
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
                || canonical_folders.contains(node.path.as_str())
                || unverifiable.iter().any(|directory| {
                    node.path == *directory || node.path.starts_with(&format!("{directory}/"))
                }))
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
