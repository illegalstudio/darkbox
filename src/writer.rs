//! Validated, atomic replacement with mandatory extension preservation.
use crate::protection::{self, ManifestSigner};
use crate::{Error, Limits, Mode, Report, Status, VerificationOptions};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

#[derive(Default)]
pub struct PackageUpdate {
    pub manifest: Option<Value>,
    /// Some bytes replaces/adds a file; None removes it. Directory declarations
    /// come from the candidate manifest. Payload must already contain encryption.
    pub files: BTreeMap<String, Option<Vec<u8>>>,
}

/// Ordinary opening requires supported common and required extension checks.
/// A trusted signed package may be opened as a public/locked view without keys.
pub fn open(
    path: impl AsRef<Path>,
    limits: Limits,
    options: &VerificationOptions<'_>,
) -> Result<Report, Error> {
    let report = crate::analyze_with(path, Mode::Verify, limits, options);
    if report.status != Status::Passed {
        return Err(Error::new(
            report.status,
            "open.refused",
            "Ordinary opening requires successful verification; use diagnostic inspection for unsupported or invalid packages",
        ).with_report(report));
    }
    Ok(report)
}

fn refused(message: &str) -> Error {
    Error::new(Status::Unsupported, "save.refused", message)
}

pub(crate) fn file_digest(path: &Path, limit: u64, deadline: Instant) -> Result<[u8; 32], Error> {
    let mut source = File::open(path).map_err(crate::io_failure)?;
    if source.metadata().map_err(crate::io_failure)?.len() > limit {
        return Err(Error::limit("Save source exceeds configured archive limit"));
    }
    let mut sha = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        crate::container::check_deadline(deadline)?;
        let count = source.read(&mut buffer).map_err(crate::io_failure)?;
        if count == 0 {
            break;
        }
        size = size
            .checked_add(count as u64)
            .filter(|size| *size <= limit)
            .ok_or_else(|| Error::limit("Save source grew beyond configured archive limit"))?;
        sha.update(&buffer[..count]);
    }
    Ok(sha.finalize().into())
}

/// Save an already encrypted candidate. SDK writers coordinate destination access
/// through a stable advisory lock. No signing keys are stored.
/// Existing output is replaced only after complete validation and fsync.
pub fn save(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    update: PackageUpdate,
    limits: Limits,
    options: &VerificationOptions<'_>,
    signer: Option<&dyn ManifestSigner>,
) -> Result<Report, Error> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    let resolved_destination = crate::package::destination(destination)?;
    let _destination_lock = crate::package::lock_destination(&resolved_destination)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(limits.timeout_seconds))
        .ok_or_else(|| Error::limit("Save timeout is too large"))?;
    if !std::fs::symlink_metadata(source)
        .map_err(crate::io_failure)?
        .file_type()
        .is_file()
    {
        return Err(refused(
            "Save source must be a regular file, without symbolic links",
        ));
    }
    let replace_source = if destination.exists() {
        if std::fs::symlink_metadata(destination)
            .map_err(crate::io_failure)?
            .file_type()
            .is_symlink()
            || std::fs::canonicalize(destination).map_err(crate::io_failure)?
                != std::fs::canonicalize(source).map_err(crate::io_failure)?
        {
            return Err(refused(
                "A separate save destination must not already exist",
            ));
        }
        true
    } else {
        false
    };
    let source_digest = file_digest(source, limits.max_archive_bytes, deadline)?;
    let previous_report = open(source, limits.clone(), options)?;
    let previous = previous_report.manifest.as_ref().unwrap();
    let mut manifest = update.manifest.unwrap_or_else(|| previous.clone());
    if manifest["darkbox"] != previous["darkbox"] {
        return Err(refused(
            "This writer preserves the original common version; migration requires a separate explicit operation",
        ));
    }
    let mut archive = ZipArchive::new(File::open(source).map_err(crate::io_failure)?)
        .map_err(crate::zip_failure)?;
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        crate::container::check_deadline(deadline)?;
        let mut entry = archive.by_index(index).map_err(crate::zip_failure)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_owned();
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(limits.max_entry_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(crate::read_failure)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| Error::limit("Save input is too large"))?;
        if bytes.len() as u64 > limits.max_entry_bytes || total > limits.max_total_bytes {
            return Err(Error::limit("Save input exceeds configured byte limits"));
        }
        files.insert(name, bytes);
    }
    for (path, bytes) in update.files {
        crate::paths::validate(&path)?;
        if path == "manifest.json" || path == protection::SIGNATURE_PATH {
            return Err(refused("Writer owns manifest and detached signature bytes"));
        }
        if let Some(bytes) = bytes {
            files.insert(path, bytes);
        } else {
            files.remove(&path);
        }
    }
    for (namespace, descriptor) in previous["extensions"].as_object().into_iter().flatten() {
        let next = &manifest["extensions"][namespace];
        if descriptor["required"] == true
            && (next.is_null()
                || next["required"] != true
                || next["version"] != descriptor["version"])
        {
            return Err(refused(
                "A required extension cannot be removed, downgraded or replaced while saving",
            ));
        }
        if let Some(verifier) = options
            .extensions
            .get(namespace, descriptor["version"].as_str().unwrap_or(""))
        {
            verifier.prepare_save(previous, &mut manifest, &mut files)?;
        }
    }
    let candidate_extensions = manifest["extensions"].clone();
    for (namespace, descriptor) in candidate_extensions.as_object().into_iter().flatten() {
        if previous["extensions"].get(namespace).is_none() {
            if let Some(verifier) = options
                .extensions
                .get(namespace, descriptor["version"].as_str().unwrap_or(""))
            {
                verifier.prepare_save(previous, &mut manifest, &mut files)?;
            } else if descriptor["required"] == true {
                return Err(refused(
                    "New required extensions need a registered verifier and writer capability",
                ));
            }
        }
    }
    for extensions in [&previous["extensions"], &candidate_extensions] {
        for (namespace, descriptor) in extensions.as_object().into_iter().flatten() {
            let next = &manifest["extensions"][namespace];
            if descriptor["required"] == true
                && (next["required"] != true || next["version"] != descriptor["version"])
            {
                return Err(refused(
                    "Extension writer callbacks must retain required extension versions",
                ));
            }
        }
    }
    // Check opaque preservation after every registered writer callback.
    for (namespace, descriptor) in previous["extensions"].as_object().into_iter().flatten() {
        if options
            .extensions
            .get(namespace, descriptor["version"].as_str().unwrap_or(""))
            .is_some()
        {
            continue;
        }
        if descriptor != &manifest["extensions"][namespace] {
            return Err(refused(
                "Unknown optional extension descriptors must be preserved",
            ));
        }
        let prefix = format!("extensions/{namespace}/");
        for index in 0..archive.len() {
            crate::container::check_deadline(deadline)?;
            let mut entry = archive.by_index(index).map_err(crate::zip_failure)?;
            if entry.is_dir() || !entry.name().starts_with(&prefix) {
                continue;
            }
            let mut bytes = Vec::new();
            entry
                .by_ref()
                .take(limits.max_entry_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(crate::read_failure)?;
            if files.get(entry.name()) != Some(&bytes) {
                return Err(refused(
                    "Unknown optional extension resources must be preserved",
                ));
            }
        }
        if files
            .keys()
            .any(|path| path.starts_with(&prefix) && archive.index_for_name(path).is_none())
        {
            return Err(refused(
                "Unknown optional extension resources cannot be added",
            ));
        }
    }
    if let Some(previous_data) = previous["extensions"].get(protection::NAMESPACE) {
        let next_data = &manifest["extensions"][protection::NAMESPACE];
        for field in ["packageId", "files", "sqlite"] {
            if previous_data["data"][field] != next_data["data"][field] {
                return Err(refused(
                    "This writer preserves package identity and protection declarations; context migration requires re-encryption in a separate package",
                ));
            }
        }
    }
    let protected = manifest["extensions"].get(protection::NAMESPACE).is_some();
    if protected {
        let signer = signer.ok_or_else(|| {
            refused("Saving a protected package requires a manifest signing capability")
        })?;
        let mut data = protection::data(&manifest)?;
        if signer.signer_id() != data.signature.signer_id {
            return Err(refused(
                "Signing capability does not match the declared signer identifier",
            ));
        }
        if options.trusted_signers.get(signer.signer_id()) != Some(&signer.public_key()) {
            return Err(refused(
                "Signing capability must match an application-trusted public key",
            ));
        }
        data.inventory = files
            .iter()
            .filter(|(path, _)| {
                path.as_str() != "manifest.json" && path.as_str() != data.signature.path
            })
            .map(|(path, bytes)| crate::extensions::EntryDigest {
                path: path.clone(),
                size: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            })
            .collect();
        manifest["extensions"][protection::NAMESPACE]["data"] =
            serde_json::to_value(&data).unwrap();
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| refused("Cannot serialize candidate manifest"))?;
        let signature = signer.sign(&manifest_bytes)?;
        files.insert(data.signature.path, signature.to_vec());
        files.insert("manifest.json".into(), manifest_bytes);
    } else {
        files.insert(
            "manifest.json".into(),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|_| refused("Cannot serialize candidate manifest"))?,
        );
    }
    total = 0;
    if files.len() > limits.max_entries {
        return Err(Error::limit("Save file count exceeds configured limit"));
    }
    for bytes in files.values() {
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| Error::limit("Candidate is too large"))?;
        if bytes.len() as u64 > limits.max_entry_bytes || total > limits.max_total_bytes {
            return Err(Error::limit("Candidate exceeds configured byte limits"));
        }
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut candidate = tempfile::Builder::new()
        .prefix(".darkbox-save-")
        .tempfile_in(parent)
        .map_err(crate::io_failure)?;
    {
        let mut zip = ZipWriter::new(candidate.as_file_mut());
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        let folders = manifest["folders"]
            .as_array()
            .ok_or_else(|| refused("Candidate folder inventory is missing"))?;
        if folders.len() + files.len() > limits.max_entries {
            return Err(Error::limit(
                "Candidate entry count exceeds configured limit",
            ));
        }
        for folder in folders {
            let path = folder["path"]
                .as_str()
                .ok_or_else(|| refused("Candidate folder is malformed"))?;
            crate::paths::validate(path)?;
            zip.add_directory(format!("{path}/"), options)
                .map_err(crate::zip_failure)?;
        }
        for (path, bytes) in &files {
            zip.start_file(path, options).map_err(crate::zip_failure)?;
            zip.write_all(bytes).map_err(crate::io_failure)?;
        }
        zip.finish().map_err(crate::zip_failure)?;
    }
    candidate.as_file().sync_all().map_err(crate::io_failure)?;
    // Preserve custom verifier registrations by using the original registry.
    let mut candidate_report =
        crate::analyze_with(candidate.path(), Mode::Verify, limits.clone(), options);
    if candidate_report.status != Status::Passed {
        candidate_report.file = destination.display().to_string();
        return Err(Error::new(
            candidate_report.status,
            "save.validation",
            "Candidate verification failed; original and destination remain unchanged",
        )
        .with_report(candidate_report));
    }
    check_protected_blocks(Some(&previous_report), &candidate_report, options, deadline)?;
    if file_digest(source, limits.max_archive_bytes, deadline)? != source_digest {
        return Err(Error::new(
            Status::OperationalError,
            "save.source_changed",
            "Source changed during save; candidate was discarded",
        ));
    }
    #[cfg(unix)]
    let parent_handle = File::open(parent).map_err(crate::io_failure)?;
    #[cfg(unix)]
    parent_handle.sync_all().map_err(crate::io_failure)?;
    if replace_source {
        candidate
            .persist(destination)
            .map_err(|error| crate::io_failure(error.error))?;
    } else {
        candidate
            .persist_noclobber(destination)
            .map_err(|error| crate::io_failure(error.error))?;
    }
    let mut report = candidate_report;
    report.file = destination.display().to_string();
    #[cfg(unix)]
    if parent_handle.sync_all().is_err() {
        report.diagnostics.push(crate::Diagnostic {
            severity: "warning", code: "save.durability".into(), path: None,
            message: "Candidate was published but directory synchronization failed; crash durability is uncertain".into(),
        });
    }
    Ok(report)
}

pub(crate) fn check_protected_blocks(
    previous: Option<&Report>,
    candidate: &Report,
    options: &VerificationOptions<'_>,
    deadline: Instant,
) -> Result<(), Error> {
    if let Some(protection) = &candidate.protection {
        let old_blocks = previous
            .and_then(|report| report.protection.as_ref())
            .map(|report| report.encrypted.as_slice())
            .unwrap_or(&[]);
        let mut old_by_digest: BTreeMap<&str, Vec<&protection::EncryptedContent>> = BTreeMap::new();
        let mut old_nonces: BTreeMap<(String, String), BTreeSet<&str>> = BTreeMap::new();
        let mut key_identities = BTreeMap::new();
        let mut identity = |id: &str| {
            key_identities
                .entry(id.to_owned())
                .or_insert_with(|| {
                    options
                        .decryption_keys
                        .and_then(|keys| keys.key(id))
                        .map(|key| format!("key:{:x}", Sha256::digest(key.as_slice())))
                        .unwrap_or_else(|| format!("id:{id}"))
                })
                .clone()
        };
        for old in old_blocks {
            crate::container::check_deadline(deadline)?;
            old_by_digest
                .entry(&old.block_sha256)
                .or_default()
                .push(old);
            if let Some(nonce) = &old.nonce_hex {
                old_nonces
                    .entry((identity(&old.context.key_id), nonce.clone()))
                    .or_default()
                    .insert(&old.block_sha256);
            }
        }
        for block in &protection.encrypted {
            crate::container::check_deadline(deadline)?;
            let matching = old_by_digest.get(block.block_sha256.as_str());
            let retained = matching
                .is_some_and(|blocks| blocks.iter().any(|old| old.context == block.context));
            if !retained && block.authentication != "verified" {
                return Err(refused(
                    "New or moved encrypted blocks require successful authentication with a decryption key",
                ));
            }
            if !retained && let Some(nonce) = &block.nonce_hex {
                let key_identity = identity(&block.context.key_id);
                if old_nonces
                    .get(&(key_identity, nonce.clone()))
                    .is_some_and(|digests| !digests.contains(block.block_sha256.as_str()))
                {
                    return Err(Error::invalid(
                        "protection.nonce_reuse",
                        "A changed block reuses a nonce observed in the source package",
                    ));
                }
            }
            if matching.is_some_and(|blocks| blocks.iter().any(|old| old.context != block.context))
            {
                return Err(refused(
                    "An unchanged encrypted block cannot be moved to a different authenticated context",
                ));
            }
        }
    }
    Ok(())
}
