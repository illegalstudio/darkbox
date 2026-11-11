//! Coordinated live directory storage. Applications own recovery and write barriers.
use crate::{
    Error, Limits, Report, Status, VerificationOptions, extensions::EntryDigest, source::Source,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub(crate) fn not_quiescent() -> Error {
    Error::new(
        Status::NotQuiescent,
        "directory.not_quiescent",
        "Active or interrupted working directory; reopen the owning application to recover and seal it. Readers never delete sidecars or checkpoint databases",
    )
}

/// Stable lock name shared with SDK destination writers. Resolve parent aliases
/// before hashing the Unicode lowercase UTF-8 final component with SHA-256.
pub fn lock_path(path: impl AsRef<Path>) -> Result<PathBuf, Error> {
    let path = crate::package::destination(path.as_ref())?;
    let name = path
        .file_name()
        .unwrap()
        .to_str()
        .ok_or_else(|| Error::invalid("directory.name", "Library name must be UTF-8"))?
        .to_lowercase();
    Ok(path.parent().unwrap().join(format!(
        ".darkbox-{:x}.lock",
        Sha256::digest(name.as_bytes())
    )))
}

pub(crate) struct DirectoryLock(File);
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        // Explicitly unlock when this process releases its last guard. A child
        // between fork and exec can briefly inherit even CLOEXEC descriptors;
        // closing only the parent's descriptor would extend the lock lifetime.
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
fn lock(path: &Path, exclusive: bool) -> Result<Arc<DirectoryLock>, Error> {
    let path = lock_path(path)?;
    match fs::symlink_metadata(&path) {
        Ok(meta) if !meta.is_file() => {
            return Err(Error::new(
                Status::OperationalError,
                "directory.lock_type",
                "Lock must be a regular file, never a symlink",
            ));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(crate::io_failure(e)),
        _ => {}
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => file,
        Err(_) if !exclusive => File::open(&path).map_err(crate::io_failure)?,
        Err(error) => return Err(crate::io_failure(error)),
    };
    let result = if exclusive {
        fs2::FileExt::try_lock_exclusive(&file)
    } else {
        fs2::FileExt::try_lock_shared(&file)
    };
    result.map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            not_quiescent()
        } else {
            crate::io_failure(error)
        }
    })?;
    Ok(Arc::new(DirectoryLock(file)))
}
pub(crate) fn shared_lock(path: &Path) -> Result<Arc<DirectoryLock>, Error> {
    lock(path, false)
}
pub(crate) fn destination_lock(path: &Path) -> Result<Arc<DirectoryLock>, Error> {
    lock(path, true)
}

fn sidecar(name: &str, db: &str) -> bool {
    name == format!("{db}-wal")
        || name == format!("{db}-shm")
        || name == format!("{db}-journal")
        || name.starts_with(&format!("{db}-mj"))
}
pub(crate) fn check_quiescence(
    source: &mut Source,
    names: &[String],
    manifest: &Value,
) -> Result<(), Error> {
    for db in manifest["databases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|db| db["path"].as_str())
    {
        if let Some(name) = names.iter().find(|name| sidecar(name, db)) {
            return Err(not_quiescent().at(name));
        }
        if let Some(index) = names.iter().position(|name| name == db) {
            let mut header = Vec::new();
            source
                .entry(index, db)?
                .reader
                .take(20)
                .read_to_end(&mut header)
                .map_err(crate::read_failure)?;
            if header.starts_with(b"SQLite format 3\0")
                && header.len() == 20
                && (header[18] == 2 || header[19] == 2)
            {
                return Err(not_quiescent().at(db));
            }
        }
    }
    Ok(())
}

/// Own the exclusive cross-process lock throughout the application's working
/// session, including all background database/resource writers. Dropping releases
/// the advisory lock, never deletes its inode and never performs SQLite recovery.
pub struct DirectoryLibrary {
    root: PathBuf,
    lock: Arc<DirectoryLock>,
}
impl DirectoryLibrary {
    pub(crate) fn adopt_prepared(candidate: &Path, destination: &Path) -> Result<Self, Error> {
        let root = crate::transfer::output_path(destination, &[])?;
        let guard = lock(&root, true)?;
        fs::create_dir(&root).map_err(crate::io_failure)?;
        if let Err(error) = fs::rename(candidate, &root) {
            let _ = fs::remove_dir(&root);
            return Err(crate::io_failure(error));
        }
        sync_directory(root.parent().unwrap())?;
        Ok(Self { root, lock: guard })
    }

    /// Open working storage, including interrupted state, without modifying data.
    /// This grants coordination, not a conformance certificate.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        if !fs::symlink_metadata(path)
            .map_err(crate::io_failure)?
            .is_dir()
        {
            return Err(Error::invalid(
                "directory.type",
                "Library must be a directory without a root symlink",
            ));
        }
        let root = fs::canonicalize(path).map_err(crate::io_failure)?;
        let lock = lock(&root, true)?;
        Ok(Self { root, lock })
    }
    /// Initialize absent working storage directly, without an intermediate ZIP.
    /// Create declared databases/resources while holding the returned handle,
    /// then seal. Until then this is working storage, not a conforming snapshot.
    pub fn initialize(
        path: impl AsRef<Path>,
        manifest: Value,
        profile: &str,
        limits: Limits,
    ) -> Result<Self, Error> {
        let root = crate::transfer::output_path(path.as_ref(), &[])?;
        let guard = lock(&root, true)?;
        require_live(&manifest)?;
        let spec = crate::creation::specification(&manifest)?;
        let end = crate::transfer::deadline(&limits)?;
        let candidate = tempfile::Builder::new()
            .prefix(".darkbox-library-")
            .tempdir_in(root.parent().unwrap())
            .map_err(crate::io_failure)?;
        let mut folders: Vec<_> = manifest["folders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        folders.sort();
        for folder in &folders {
            crate::paths::validate(folder)?;
            fs::create_dir(candidate.path().join(folder)).map_err(crate::io_failure)?;
        }
        for file in spec.files {
            write_file(&candidate.path().join(file.path), file.bytes)?;
        }
        write_file(
            &candidate.path().join(crate::versions::CATALOG_PATH),
            spec.catalog,
        )?;
        let profile_path = manifest["application"]["profilePath"].as_str().unwrap();
        crate::paths::validate(profile_path)?;
        if profile_path.starts_with("docs/darkbox/")
            || profile_path.starts_with("docs/sqlite/")
            || profile_path.starts_with("extensions/")
            || profile.is_empty()
            || profile.starts_with('\u{feff}')
        {
            return Err(Error::invalid(
                "directory.profile",
                "Profile must be nonempty UTF-8 outside reserved subtrees",
            ));
        }
        if profile.len() as u64 > limits.max_metadata_bytes {
            return Err(Error::limit("Profile exceeds metadata limit"));
        }
        write_file(&candidate.path().join(profile_path), profile.as_bytes())?;
        let bytes = crate::creation::serialized_manifest(&manifest, limits.max_metadata_bytes)?;
        write_file(&candidate.path().join("manifest.json"), &bytes)?;
        crate::container::check_deadline(end)?;
        for folder in folders.iter().rev() {
            sync_directory(&candidate.path().join(folder))?;
        }
        sync_directory(candidate.path())?;
        let _ = Source::directory_locked(
            candidate.path(),
            guard.clone(),
            BTreeMap::new(),
            &BTreeSet::new(),
            &limits,
            end,
        )?;
        fs::create_dir(&root).map_err(crate::io_failure)?;
        if let Err(error) = fs::rename(candidate.path(), &root) {
            let _ = fs::remove_dir(&root);
            return Err(crate::io_failure(error));
        }
        sync_directory(root.parent().unwrap())?;
        Ok(Self { root, lock: guard })
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    pub fn lock_path(&self) -> Result<PathBuf, Error> {
        lock_path(&self.root)
    }

    /// Seal closed DELETE-mode databases, refreshing inventory and metadata.
    /// This consumes the handle and releases the lock on return. Stop all
    /// application writers first; on failure reopen the handle to recover.
    /// Protected live metadata changes require a transactional application writer
    /// and are rejected here; exact protected pack/unpack remain supported.
    pub fn seal(
        self,
        manifest: Value,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Report, Error> {
        let end = crate::transfer::deadline(&limits)?;
        let prepared = self.prepare(manifest, &BTreeMap::new(), &limits, options, false)?;
        let mut candidate = tempfile::Builder::new()
            .prefix(".darkbox-seal-")
            .tempfile_in(self.root.parent().unwrap())
            .map_err(crate::io_failure)?;
        candidate
            .write_all(&prepared.manifest)
            .map_err(crate::io_failure)?;
        candidate.as_file().sync_all().map_err(crate::io_failure)?;
        crate::container::check_deadline(end)?;
        candidate
            .persist(self.root.join("manifest.json"))
            .map_err(|e| crate::io_failure(e.error))?;
        sync_directory(&self.root)?;
        Ok(prepared.verified.report)
    }

    /// Capture a coherent application revision while its write barrier is held.
    /// Supply every declared database connection, including WAL-backed ones.
    /// Pause mutations/deletions and metadata changes until this call returns;
    /// immutable media are streamed directly, never staged as a full edition.
    pub fn hot_backup(
        &mut self,
        destination: impl AsRef<Path>,
        manifest: Value,
        databases: &BTreeMap<String, &crate::rusqlite::Connection>,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Report, Error> {
        let destination = crate::transfer::output_path(destination.as_ref(), &[&self.root])?;
        let end = crate::transfer::deadline(&limits)?;
        let prepared = self.prepare(manifest, databases, &limits, options, true)?;
        crate::transfer::pack_verified(prepared.verified, &destination, &limits, options, end)
    }
    /// Create a delta directly from live working storage and database snapshots.
    /// An empty connection map selects a closed quiescent directory. Hold the
    /// same write barrier as hot_backup; no complete target ZIP is materialized.
    pub fn create_delta(
        &mut self,
        base: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        manifest: Value,
        databases: &BTreeMap<String, &crate::rusqlite::Connection>,
        limits: Limits,
        options: &VerificationOptions<'_>,
    ) -> Result<Report, Error> {
        let destination =
            crate::transfer::output_path(destination.as_ref(), &[&self.root, base.as_ref()])?;
        let end = crate::transfer::deadline(&limits)?;
        let prepared =
            self.prepare(manifest, databases, &limits, options, !databases.is_empty())?;
        crate::transfer::delta_from_verified(
            base.as_ref(),
            prepared.verified,
            &destination,
            &limits,
            options,
            end,
        )
    }

    /// Capture only listing, profile and SQLite snapshots under the application's
    /// short write barrier. Then release that barrier and retain captured resources
    /// unchanged until write_backup/write_delta completes or the handle drops.
    pub fn prepare_hot_capture(
        &self,
        manifest: Value,
        databases: &BTreeMap<String, &crate::rusqlite::Connection>,
        limits: Limits,
    ) -> Result<HotCapture, Error> {
        if !matches!(
            manifest["darkbox"]["version"].as_str(),
            Some("1.4.0" | "1.5.0")
        ) {
            return Err(Error::new(
                Status::Unsupported,
                "directory.capture_version",
                "Split-barrier capture requires common 1.4.0 or 1.5.0",
            ));
        }
        self.capture(manifest, databases, &limits, true)
    }
    fn prepare(
        &self,
        manifest: Value,
        databases: &BTreeMap<String, &crate::rusqlite::Connection>,
        limits: &Limits,
        options: &VerificationOptions<'_>,
        hot: bool,
    ) -> Result<Prepared, Error> {
        self.capture(manifest, databases, limits, hot)?
            .prepare(options)
    }
    fn capture(
        &self,
        manifest: Value,
        databases: &BTreeMap<String, &crate::rusqlite::Connection>,
        limits: &Limits,
        hot: bool,
    ) -> Result<HotCapture, Error> {
        require_live(&manifest)?;
        crate::creation::specification(&manifest)?;
        let end = crate::transfer::deadline(limits)?;
        let previous = crate::json::parse(&crate::read_metadata(
            &mut File::open(self.root.join("manifest.json")).map_err(crate::io_failure)?,
            limits,
            end,
        )?)?;
        if previous["darkbox"] != manifest["darkbox"]
            || previous["packageId"] != manifest["packageId"]
            || previous["extensions"] != manifest["extensions"]
        {
            return Err(Error::new(
                Status::Unsupported,
                "directory.metadata",
                "Live operations preserve common version, packageId and extension descriptors",
            ));
        }
        // No implicit re-signing or semantic changes to extension-owned data.
        if manifest["extensions"]
            .get(crate::protection::NAMESPACE)
            .is_some()
        {
            return Err(Error::new(
                Status::Unsupported,
                "directory.extensions",
                "Live metadata publication requires an extension-aware transactional application writer; use exact pack/unpack for sealed extensions",
            ));
        }
        let declared: BTreeSet<_> = manifest["databases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|db| db["path"].as_str().unwrap().to_owned())
            .collect();
        if hot && declared != databases.keys().cloned().collect() {
            return Err(Error::invalid(
                "directory.databases",
                "Hot capture requires exactly one connection for every declared database",
            ));
        }
        let mut snapshots = Vec::new();
        let mut overrides = BTreeMap::new();
        for (name, connection) in databases {
            let snapshot = crate::package::database_snapshot(connection, limits, end)?;
            overrides.insert(name.clone(), snapshot.path().to_owned());
            snapshots.push(snapshot);
        }
        let (raw, inventory) = Source::directory_locked(
            &self.root,
            self.lock.clone(),
            BTreeMap::new(),
            &BTreeSet::new(),
            limits,
            end,
        )?;
        let omitted = if hot {
            inventory
                .names
                .iter()
                .filter(|name| declared.iter().any(|db| sidecar(name, db)))
                .cloned()
                .collect()
        } else {
            BTreeSet::new()
        };
        let mut source = raw;
        source.overlay(overrides, &omitted)?;
        source.retain_listing()?;
        let metadata = limits.tempdir("darkbox-hot-metadata-")?;
        let profile = manifest["application"]["profilePath"].as_str().unwrap();
        let (_, listing) = source.fork(limits, end)?;
        let index = listing
            .names
            .iter()
            .position(|name| name == profile)
            .ok_or_else(|| Error::invalid("profile.missing", "Profile is missing"))?;
        let bytes = crate::read_metadata(&mut source.entry(index, profile)?.reader, limits, end)?;
        let profile_copy = metadata.path().join("profile.md");
        write_file(&profile_copy, &bytes)?;
        source.overlay(
            BTreeMap::from([(profile.to_owned(), profile_copy)]),
            &BTreeSet::new(),
        )?;
        let (_, directory) = source.fork(limits, end)?;
        check_quiescence(&mut source, &directory.names, &manifest)?;
        Ok(HotCapture {
            root: self.root.clone(),
            source,
            directory,
            manifest,
            snapshots,
            metadata,
            limits: limits.clone(),
            end,
        })
    }
}

/// Frozen listing and database/profile snapshots. After preparation, additions
/// may resume. Retain every listed resource unchanged until this handle drops.
pub struct HotCapture {
    root: PathBuf,
    source: Source,
    directory: crate::container::Directory,
    manifest: Value,
    snapshots: Vec<crate::package::DatabaseSnapshot>,
    metadata: tempfile::TempDir,
    limits: Limits,
    end: std::time::Instant,
}
impl HotCapture {
    pub fn write_backup(
        self,
        destination: impl AsRef<Path>,
        options: &VerificationOptions<'_>,
    ) -> Result<Report, Error> {
        let destination = crate::transfer::output_path(destination.as_ref(), &[&self.root])?;
        let limits = self.limits.clone();
        let end = self.end;
        let prepared = self.prepare(options)?;
        crate::transfer::pack_verified(prepared.verified, &destination, &limits, options, end)
    }
    pub fn write_delta(
        self,
        base: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        options: &VerificationOptions<'_>,
    ) -> Result<Report, Error> {
        let destination =
            crate::transfer::output_path(destination.as_ref(), &[&self.root, base.as_ref()])?;
        let limits = self.limits.clone();
        let end = self.end;
        let prepared = self.prepare(options)?;
        crate::transfer::delta_from_verified(
            base.as_ref(),
            prepared.verified,
            &destination,
            &limits,
            options,
            end,
        )
    }
    fn prepare(self, options: &VerificationOptions<'_>) -> Result<Prepared, Error> {
        let Self {
            root,
            mut source,
            directory,
            mut manifest,
            snapshots,
            metadata,
            limits,
            end,
        } = self;
        let limits = &limits;
        let declared: BTreeSet<_> = manifest["databases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|db| db["path"].as_str().unwrap().to_owned())
            .collect();
        let mut digests = BTreeMap::new();
        let mut trusted = Vec::new();
        let mut total = 0u64;
        for (index, name) in directory.names.iter().enumerate() {
            crate::container::check_deadline(end)?;
            if name.ends_with('/') || name == "manifest.json" {
                continue;
            }
            let mut file = source.entry(index, name)?;
            let eligible = crate::resource_inventory::dynamic(&manifest, name)
                && !declared.contains(name)
                && manifest["application"]["profilePath"] != name.as_str()
                && !name.starts_with("extensions/");
            let digest = if let Some(hash) = eligible
                .then(|| {
                    options
                        .trusted_digests
                        .and_then(|cache| cache.sha256(name, file.size))
                })
                .flatten()
            {
                if hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(Error::invalid(
                        "directory.trusted_digest",
                        "Invalid trusted SHA-256",
                    )
                    .at(name));
                }
                let digest = EntryDigest {
                    path: name.clone(),
                    size: file.size,
                    sha256: hash,
                };
                trusted.push(digest.clone());
                total = total
                    .checked_add(file.size)
                    .ok_or_else(|| Error::limit("Snapshot size overflow"))?;
                digest
            } else {
                let scan = crate::stream(&mut file.reader, None, false, limits, &mut total, end)?;
                if scan.size != file.size {
                    return Err(Error::invalid(
                        "directory.changed",
                        "Resource size changed during snapshot",
                    )
                    .at(name));
                }
                EntryDigest {
                    path: name.clone(),
                    size: scan.size,
                    sha256: scan.sha256,
                }
            };
            if total > limits.max_total_bytes {
                return Err(Error::limit("Snapshot exceeds total limits"));
            }
            digests.insert(name.clone(), digest);
        }
        crate::resource_inventory::update(&mut manifest, &digests);
        let bytes = crate::creation::serialized_manifest(&manifest, limits.max_metadata_bytes)?;
        let manifest_path = metadata.path().join("manifest.json");
        write_file(&manifest_path, &bytes)?;
        source.overlay(
            BTreeMap::from([("manifest.json".into(), manifest_path)]),
            &BTreeSet::new(),
        )?;
        let pair = source.fork(limits, end)?;
        // Reuse hashes from this coordinated pass, while still checking metadata,
        // canonical bytes, database snapshots, file prefixes and profile callbacks.
        let cache = PassDigests(&digests);
        let verification = VerificationOptions {
            trusted_digests: Some(&cache),
            ..VerificationOptions::default()
        };
        // Caller callbacks and policy must remain in force. They may require full
        // resource staging, in which case verification deliberately rereads them.
        let mut verified = if manifest["extensions"]
            .as_object()
            .is_some_and(|e| !e.is_empty())
            || options.require_profile
            || options.require_protection
            || options
                .profiles
                .get(
                    manifest["application"]["id"].as_str().unwrap(),
                    manifest["application"]["formatVersion"].as_str().unwrap(),
                )
                .is_some()
        {
            crate::transfer::Verified::from_source(&root, pair, limits, options, end)?
        } else {
            crate::transfer::Verified::from_source(&root, pair, limits, &verification, end)?
        };
        verified
            .report
            .trusted_resources
            .retain(|entry| trusted.contains(entry));
        if verified.report.trusted_resources.is_empty() {
            verified.report.scope = "common_machine_checks";
            verified
                .report
                .checks
                .retain(|check| *check != "directory.incremental");
            verified.report.checks.push("directory.bytes");
            verified
                .report
                .diagnostics
                .retain(|d| d.code != "directory.trusted_resources");
        }
        Ok(Prepared {
            verified,
            manifest: bytes,
            _snapshots: snapshots,
            _metadata: metadata,
        })
    }
}
struct PassDigests<'a>(&'a BTreeMap<String, EntryDigest>);
impl crate::TrustedDigests for PassDigests<'_> {
    fn sha256(&self, path: &str, size: u64) -> Option<String> {
        self.0
            .get(path)
            .filter(|d| d.size == size)
            .map(|d| d.sha256.clone())
    }
}
struct Prepared {
    verified: crate::transfer::Verified,
    manifest: Vec<u8>,
    _snapshots: Vec<crate::package::DatabaseSnapshot>,
    _metadata: tempfile::TempDir,
}
fn require_live(manifest: &Value) -> Result<(), Error> {
    if !matches!(
        manifest["darkbox"]["version"].as_str(),
        Some("1.3.0" | "1.4.0" | "1.5.0")
    ) || !manifest["packageId"].is_string()
    {
        return Err(Error::new(
            Status::Unsupported,
            "directory.version",
            "Live storage requires Darkbox 1.3.0 and a stable packageId",
        ));
    }
    Ok(())
}
fn write_file(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut file = File::create(path).map_err(crate::io_failure)?;
    file.write_all(bytes).map_err(crate::io_failure)?;
    file.sync_all().map_err(crate::io_failure)
}
fn sync_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|f| f.sync_all())
        .map_err(crate::io_failure)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn last_guard_unlocks_even_with_a_duplicated_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("library");
        let guard = lock(&root, true).unwrap();
        // A duplicate models the shared open-file description inherited by fork.
        let duplicate = guard.0.try_clone().unwrap();
        let retained = guard.clone();
        drop(guard);
        assert!(lock(&root, false).is_err());
        drop(retained);
        let reader = lock(&root, false).unwrap();
        drop(duplicate);
        drop(reader);
        assert!(lock(&root, true).is_ok());
    }
}
