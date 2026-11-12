use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, Metadata},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

pub(crate) fn directory(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(crate::io_failure)?
            .join(path)
    };
    let mut missing = Vec::new();
    let mut ancestor = absolute.as_path();
    while !ancestor.exists() {
        missing.push(ancestor.to_owned());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| invalid("Missing filesystem root"))?;
    }
    fs::create_dir_all(&absolute).map_err(crate::io_failure)?;
    for created in missing.iter().rev() {
        sync_dir(created)?;
        sync_dir(created.parent().unwrap())?;
    }
    if !fs::symlink_metadata(path)
        .map_err(crate::io_failure)?
        .is_dir()
    {
        return Err(invalid("Sync root must be a real directory"));
    }
    fs::canonicalize(path).map_err(crate::io_failure)
}
pub(crate) fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(crate::io_failure)?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
pub(crate) fn safe_path(root: &Path, relative: &str, create: bool) -> Result<PathBuf> {
    crate::paths::validate(relative)?;
    checked_path(root, relative, create)
}
pub(crate) fn checked_path(root: &Path, relative: &str, create: bool) -> Result<PathBuf> {
    if relative.is_empty()
        || relative.contains('\\')
        || relative.contains('\0')
        || Path::new(relative).is_absolute()
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid("Unsafe relative diagnostic path"));
    }
    let mut path = root.to_owned();
    let parts: Vec<_> = relative.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta)
                if meta.file_type().is_symlink() || (i + 1 < parts.len() && !meta.is_dir()) =>
            {
                return Err(invalid("Sync path has a symlink/non-directory parent").at(relative));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if i + 1 < parts.len() && create {
                    match fs::create_dir(&path) {
                        Ok(()) => sync_dir(path.parent().unwrap())?,
                        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(e) => return Err(crate::io_failure(e)),
                    }
                    if !fs::symlink_metadata(&path)
                        .map_err(crate::io_failure)?
                        .is_dir()
                    {
                        return Err(invalid("Sync parent changed"));
                    }
                }
            }
            Err(e) => return Err(crate::io_failure(e)),
        }
    }
    Ok(path)
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return false;
        }
    }
    a.is_file() && b.is_file() && a.len() == b.len() && a.modified().ok() == b.modified().ok()
}
fn same_cached(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.ctime() != b.ctime() || a.ctime_nsec() != b.ctime_nsec() || a.nlink() != b.nlink() {
            return false;
        }
    }
    same(a, b)
}
pub(crate) fn open_regular(root: &Path, relative: &str, maximum: u64) -> Result<(File, Metadata)> {
    let path = checked_path(root, relative, false)?;
    let before = fs::symlink_metadata(&path).map_err(crate::io_failure)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(invalid("Sync input is not a regular file").at(relative));
    }
    if before.len() > maximum {
        return Err(super::limit("Sync input bytes").at(relative));
    }
    let file = File::open(path).map_err(crate::io_failure)?;
    if !same(&before, &file.metadata().map_err(crate::io_failure)?) {
        return Err(super::pending_bytes("Sync input changed while opening").at(relative));
    }
    Ok((file, before))
}
pub(crate) fn read_regular(root: &Path, relative: &str, maximum: usize) -> Result<Vec<u8>> {
    for attempt in 0..3 {
        match read_regular_once(root, relative, maximum) {
            Err(error) if error.code == "sync.pending_bytes" && attempt < 2 => {
                // A VFS upload can settle cached file attributes immediately
                // after close/rename. Retry a complete read with every witness
                // check intact; never accept the bytes of an unstable attempt.
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            result => return result,
        }
    }
    unreachable!("Bounded read attempts always return")
}
fn read_regular_once(root: &Path, relative: &str, maximum: usize) -> Result<Vec<u8>> {
    let (mut file, before) = open_regular(root, relative, maximum as u64)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(crate::io_failure)?;
    if bytes.len() > maximum {
        return Err(super::limit("Sync input bytes").at(relative));
    }
    if !same(&before, &file.metadata().map_err(crate::io_failure)?)
        || !same(
            &before,
            &fs::symlink_metadata(checked_path(root, relative, false)?)
                .map_err(crate::io_failure)?,
        )
    {
        return Err(super::pending_bytes("Sync input changed during read").at(relative));
    }
    Ok(bytes)
}
pub(crate) fn publish_bytes(
    root: &Path,
    relative: &str,
    bytes: &[u8],
    limits: &crate::Limits,
) -> Result<()> {
    let end = crate::transfer::deadline(limits)?;
    let path = safe_path(root, relative, true)?;
    let mut candidate =
        tempfile::NamedTempFile::new_in(path.parent().unwrap()).map_err(crate::io_failure)?;
    candidate
        .write_all(bytes)
        .and_then(|()| candidate.as_file().sync_all())
        .map_err(crate::io_failure)?;
    match super::publication::persist(candidate, &path, end) {
        Ok(_) => sync_dir(path.parent().unwrap()),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = read_regular(root, relative, bytes.len());
            if existing.as_ref().is_ok_and(|actual| actual == bytes) {
                File::open(&path)
                    .and_then(|file| file.sync_all())
                    .map_err(crate::io_failure)?;
                sync_dir(path.parent().unwrap())
            } else if advertised(relative.rsplit('/').next().unwrap_or("")).is_some() {
                Err(super::pending_bytes("Existing content-addressed publication is incomplete or mismatched; retry without replacing it").at(relative))
            } else {
                Err(fork("Immutable publication path contains different bytes").at(relative))
            }
        }
        Err(e) => Err(super::publication::error(e.error)),
    }
}

pub(crate) fn read_expected(root: &Path, reference: &FileRef, maximum: usize) -> Result<Vec<u8>> {
    let path = safe_path(root, &reference.path, false)?;
    if let Err(error) = fs::symlink_metadata(&path) {
        return Err(if error.kind() == std::io::ErrorKind::NotFound {
            super::pending_bytes("Pinned domain resource has not arrived")
        } else {
            crate::io_failure(error)
        });
    }
    let bytes = read_regular(root, &reference.path, maximum)?;
    if reference.size.0 != bytes.len() as u64 || reference.sha256 != sha256(&bytes) {
        return Err(
            super::pending_bytes("Pinned domain resource is incomplete or mismatched")
                .at(&reference.path),
        );
    }
    Ok(bytes)
}
pub(crate) fn read_domain(root: &Path, bytes: &[u8]) -> Result<Domain> {
    let descriptor: DomainRoot = decode(bytes, MAX_SEGMENT_BYTES)?;
    if descriptor.mapping.path != "profile/mapping.json"
        || descriptor.profile.path != "profile/profile.md"
        || descriptor
            .baseline
            .as_ref()
            .is_some_and(|reference| reference.path != "profile/base.json")
    {
        return Err(invalid("Pinned domain resource path differs"));
    }
    let mapping = read_expected(root, &descriptor.mapping, MAX_SEGMENT_BYTES)?;
    let profile = read_expected(root, &descriptor.profile, MAX_SEGMENT_BYTES)?;
    let baseline = descriptor
        .baseline
        .as_ref()
        .map(|reference| read_expected(root, reference, MAX_BASELINE_BYTES))
        .transpose()?;
    Domain::from_parts_with_baseline(bytes, &mapping, &profile, baseline.as_deref())
}

/// A private local immutable object store. It must not be the exchange directory.
#[derive(Clone, Debug)]
pub struct ObjectStore {
    root: PathBuf,
    limits: SyncLimits,
    trusted: Option<Arc<Mutex<VerifiedObjects>>>,
}

#[derive(Debug)]
struct VerifiedObjects {
    entries: BTreeMap<Blob, Metadata>,
    order: VecDeque<Blob>,
    capacity: usize,
    #[cfg(test)]
    full_checks: usize,
}
impl VerifiedObjects {
    fn forget(&mut self, blob: &Blob) {
        if self.entries.remove(blob).is_some() {
            self.order.retain(|known| known != blob);
        }
    }
    fn remember(&mut self, blob: &Blob, witness: Metadata) {
        if !self.entries.contains_key(blob) {
            while self.entries.len() >= self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.entries.remove(&old);
                }
            }
            self.order.push_back(blob.clone());
        }
        self.entries.insert(blob.clone(), witness);
    }
}
impl ObjectStore {
    pub fn open(path: impl AsRef<Path>, limits: SyncLimits) -> Result<Self> {
        Ok(Self {
            root: directory(path.as_ref())?,
            limits,
            trusted: None,
        })
    }
    /// Reuse bounded verification witnesses for application-owned immutable
    /// objects. The caller must prevent every external content mutation.
    /// Metadata is an invalidation hint, not proof of unchanged bytes. Cloned
    /// handles share the cache; zero capacity retains full verification.
    pub fn with_trusted_immutable_cache(mut self, capacity: usize) -> Self {
        self.trusted = (capacity != 0).then(|| {
            Arc::new(Mutex::new(VerifiedObjects {
                entries: BTreeMap::new(),
                order: VecDeque::new(),
                capacity,
                #[cfg(test)]
                full_checks: 0,
            }))
        });
        self
    }
    /// Invalidate all trusted witnesses, including those shared with clones.
    pub fn clear_verification_cache(&self) {
        if let Some(cache) = &self.trusted {
            let mut cache = cache.lock().unwrap_or_else(|error| error.into_inner());
            cache.entries.clear();
            cache.order.clear();
        }
    }
    /// Always hash the complete object, regardless of the selected cache policy.
    pub fn verify(&self, blob: &Blob) -> Result<bool> {
        Ok(self.full_witness(blob)?.is_some())
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    pub fn put(&self, reader: &mut dyn Read) -> Result<Blob> {
        self.put_inner(reader, None)
    }
    pub fn put_expected(&self, reader: &mut dyn Read, expected: &Blob) -> Result<Blob> {
        expected.validate()?;
        self.put_inner(reader, Some(expected))
    }
    fn put_inner(&self, reader: &mut dyn Read, expected: Option<&Blob>) -> Result<Blob> {
        let end = crate::transfer::deadline(&self.limits.io)?;
        let mut temp = tempfile::NamedTempFile::new_in(&self.root).map_err(crate::io_failure)?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            crate::container::check_deadline(end)?;
            let n = reader.read(&mut buffer).map_err(crate::io_failure)?;
            if n == 0 {
                break;
            }
            size = size
                .checked_add(n as u64)
                .ok_or_else(|| super::limit("Object length"))?;
            if size > self.limits.io.max_entry_bytes || expected.is_some_and(|b| size > b.size.0) {
                return Err(super::limit("Object length"));
            }
            hash.update(&buffer[..n]);
            temp.write_all(&buffer[..n]).map_err(crate::io_failure)?;
        }
        let blob = Blob {
            sha256: format!("{:x}", hash.finalize()),
            size: Counter(size),
        };
        if expected.is_some_and(|b| b != &blob) {
            return Err(invalid("Object bytes do not match expected digest/length"));
        }
        temp.as_file().sync_all().map_err(crate::io_failure)?;
        let relative = blob.relative_path()?;
        let target = safe_path(&self.root, &relative, true)?;
        match super::publication::persist(temp, &target, end) {
            Ok(_) => sync_dir(target.parent().unwrap())?,
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !self.contains(&blob)? {
                    return Err(crate::Error::invalid(
                        "sync.object_conflict",
                        "Existing immutable object is damaged",
                    ));
                }
                File::open(&target)
                    .and_then(|file| file.sync_all())
                    .map_err(crate::io_failure)?;
                sync_dir(target.parent().unwrap())?;
            }
            Err(e) => return Err(super::publication::error(e.error)),
        }
        Ok(blob)
    }
    pub(crate) fn witness(&self, blob: &Blob) -> Result<Option<Metadata>> {
        blob.validate()?;
        if blob.size.0 > self.limits.io.max_entry_bytes {
            return Err(super::limit(
                "Referenced object exceeds the configured entry-byte policy",
            ));
        }
        let remembered = self.trusted.as_ref().and_then(|cache| {
            cache
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .entries
                .get(blob)
                .cloned()
        });
        if let Some(witness) = remembered
            && witness.modified().is_ok()
            && self.matches_witness(blob, &witness, same_cached)?
        {
            return Ok(Some(witness));
        }
        self.full_witness(blob)
    }
    fn full_witness(&self, blob: &Blob) -> Result<Option<Metadata>> {
        if let Some(cache) = &self.trusted {
            let mut cache = cache.lock().unwrap_or_else(|error| error.into_inner());
            cache.forget(blob);
            #[cfg(test)]
            {
                cache.full_checks += 1;
            }
        }
        let witness = verify_blob(&self.root, blob, &self.limits)?;
        if let (Some(cache), Some(witness)) = (&self.trusted, &witness) {
            cache
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remember(blob, witness.clone());
        }
        Ok(witness)
    }
    pub(crate) fn unchanged(&self, blob: &Blob, witness: &Metadata) -> Result<bool> {
        self.matches_witness(blob, witness, same)
    }
    fn matches_witness(
        &self,
        blob: &Blob,
        witness: &Metadata,
        matches: fn(&Metadata, &Metadata) -> bool,
    ) -> Result<bool> {
        let path = safe_path(&self.root, &blob.relative_path()?, false)?;
        match fs::symlink_metadata(path) {
            Ok(actual) => Ok(!actual.file_type().is_symlink() && matches(witness, &actual)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(crate::io_failure(e)),
        }
    }
    pub fn contains(&self, blob: &Blob) -> Result<bool> {
        Ok(self.witness(blob)?.is_some())
    }
    pub fn with_blob<T>(
        &self,
        blob: &Blob,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<T> {
        let witness = self
            .witness(blob)?
            .ok_or_else(|| invalid("Local immutable object missing or damaged"))?;
        let (mut file, before) = open_regular(
            &self.root,
            &blob.relative_path()?,
            self.limits.io.max_entry_bytes,
        )?;
        if !same(&witness, &before) {
            return Err(invalid("Object changed after verification"));
        }
        let result = read(&mut file)?;
        if !same(&before, &file.metadata().map_err(crate::io_failure)?)
            || !self.unchanged(blob, &before)?
        {
            return Err(invalid("Object changed while reading"));
        }
        Ok(result)
    }
    pub fn import(&self, exchange: &Exchange, blob: &Blob) -> Result<bool> {
        if self.root.starts_with(&exchange.root) || exchange.root.starts_with(&self.root) {
            return Err(invalid("Local objects and exchange must be separate"));
        }
        if self.contains(blob)? {
            return Ok(true);
        }
        if verify_blob(&exchange.root, blob, &self.limits)?.is_none() {
            return Ok(false);
        }
        let (mut file, _) = open_regular(
            &exchange.root,
            &blob.relative_path()?,
            self.limits.io.max_entry_bytes,
        )?;
        self.put_expected(&mut file, blob)?;
        Ok(true)
    }
}
fn verify_blob(root: &Path, blob: &Blob, limits: &SyncLimits) -> Result<Option<Metadata>> {
    blob.validate()?;
    if blob.size.0 > limits.io.max_entry_bytes {
        return Err(super::limit(
            "Referenced object exceeds the configured entry-byte policy",
        ));
    }
    let relative = blob.relative_path()?;
    let path = safe_path(root, &relative, false)?;
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(crate::io_failure(e)),
        _ => {}
    }
    let (mut file, before) = open_regular(root, &relative, limits.io.max_entry_bytes)?;
    if before.len() != blob.size.0 {
        return Ok(None);
    }
    let end = crate::transfer::deadline(&limits.io)?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        crate::container::check_deadline(end)?;
        let n = file.read(&mut buffer).map_err(crate::io_failure)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > blob.size.0 {
            return Ok(None);
        }
        hash.update(&buffer[..n]);
    }
    let valid = size == blob.size.0
        && format!("{:x}", hash.finalize()) == blob.sha256
        && same(&before, &file.metadata().map_err(crate::io_failure)?)
        && same(
            &before,
            &fs::symlink_metadata(path).map_err(crate::io_failure)?,
        );
    Ok(valid.then_some(before))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplicaDescriptor {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub replica_id: String,
    pub device_id: String,
    pub label: String,
}
impl ReplicaDescriptor {
    pub fn validate(&self, domain: &Domain) -> Result<()> {
        version(&self.kind, &self.protocol_version, "darkbox-sync-replica")?;
        domain.bind(&self.sync_id, &self.root_sha256)?;
        if !hex(&self.replica_id, 32) || !hex(&self.device_id, 32) || self.label.len() > 1024 {
            return Err(invalid("Replica descriptor"));
        }
        Ok(())
    }
    pub fn relative_path(&self) -> Result<String> {
        let bytes = canonical(self)?;
        Ok(format!(
            "replicas/{}/replica-{:016x}-{}.json",
            self.replica_id,
            bytes.len(),
            sha256(&bytes)
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Segment {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub replica_id: String,
    pub first: Counter,
    pub last: Counter,
    pub transactions: Vec<SyncTransaction>,
}
impl Segment {
    pub fn new(domain: &Domain, transactions: Vec<SyncTransaction>) -> Result<Self> {
        let first = transactions
            .first()
            .ok_or_else(|| invalid("Empty segment"))?;
        let segment = Self {
            kind: "darkbox-sync-segment".into(),
            protocol_version: VERSION.into(),
            sync_id: domain.root().sync_id.clone(),
            root_sha256: domain.root_hash().into(),
            replica_id: first.replica_id.clone(),
            first: first.sequence,
            last: transactions.last().unwrap().sequence,
            transactions,
        };
        segment.validate(domain)?;
        Ok(segment)
    }
    pub fn validate(&self, domain: &Domain) -> Result<()> {
        version(&self.kind, &self.protocol_version, "darkbox-sync-segment")?;
        domain.bind(&self.sync_id, &self.root_sha256)?;
        if !hex(&self.replica_id, 32)
            || self.transactions.is_empty()
            || self.transactions.len() > MAX_SEGMENT_TRANSACTIONS
            || self.first.0 == 0
            || self
                .last
                .0
                .checked_sub(self.first.0)
                .and_then(|n| n.checked_add(1))
                != Some(self.transactions.len() as u64)
        {
            return Err(invalid("Segment bounds"));
        }
        for (i, tx) in self.transactions.iter().enumerate() {
            tx.shape(domain)?;
            if tx.replica_id != self.replica_id
                || self.first.0.checked_add(i as u64) != Some(tx.sequence.0)
            {
                return Err(invalid("Segment is not contiguous"));
            }
            if i > 0 && tx.previous.as_deref() != Some(self.transactions[i - 1].hash()?.as_str()) {
                return Err(invalid("Segment chain differs"));
            }
        }
        if canonical(self)?.len() > MAX_SEGMENT_BYTES {
            return Err(super::limit("Segment bytes"));
        }
        Ok(())
    }
    pub fn relative_path(&self) -> Result<String> {
        let bytes = canonical(self)?;
        Ok(format!(
            "replicas/{}/segments/{:020}-{:020}-{:016x}-{}.json",
            self.replica_id,
            self.first.0,
            self.last.0,
            bytes.len(),
            sha256(&bytes)
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub replica_id: String,
    pub serial: Counter,
    pub frontier: Frontier,
}
impl Receipt {
    pub fn validate(&self, domain: &Domain) -> Result<()> {
        version(&self.kind, &self.protocol_version, "darkbox-sync-receipt")?;
        domain.bind(&self.sync_id, &self.root_sha256)?;
        validate_frontier(&self.frontier)?;
        if !hex(&self.replica_id, 32) || self.serial.0 == 0 {
            return Err(invalid("Receipt identity"));
        }
        Ok(())
    }
    pub fn relative_path(&self) -> Result<String> {
        let bytes = canonical(self)?;
        Ok(format!(
            "replicas/{}/receipts/{:020}-{:016x}-{}.json",
            self.replica_id,
            self.serial.0,
            bytes.len(),
            sha256(&bytes)
        ))
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ScanDiagnostic {
    pub path: String,
    pub code: &'static str,
    pub message: String,
}
#[derive(Clone, Debug, Default)]
pub struct ExchangeScan {
    pub replicas: BTreeMap<String, ReplicaDescriptor>,
    pub transactions: Vec<SyncTransaction>,
    pub receipts: Vec<Receipt>,
    pub snapshots: Vec<SnapshotDescriptor>,
    pub diagnostics: Vec<ScanDiagnostic>,
}

#[derive(Default)]
pub(crate) struct ScanEvidence {
    pub(crate) fork: Vec<Vec<u8>>,
    pub(crate) copies: Vec<SyncTransaction>,
}
/// Immutable exchange transport. Its pinned root is rechecked on every scan/write.
#[derive(Clone, Debug)]
pub struct Exchange {
    pub(crate) root: PathBuf,
    domain: Domain,
    limits: SyncLimits,
    pub(crate) generation_guard: Option<(SyncRepository, String)>,
}
impl Exchange {
    pub fn create(path: impl AsRef<Path>, domain: Domain, limits: SyncLimits) -> Result<Self> {
        let root = directory(path.as_ref())?;
        publish_bytes(&root, "profile/profile.md", domain.profile(), &limits.io)?;
        publish_bytes(
            &root,
            "profile/mapping.json",
            &canonical(domain.mapping())?,
            &limits.io,
        )?;
        if let Some(base) = domain.baseline() {
            publish_bytes(&root, "profile/base.json", &canonical(base)?, &limits.io)?;
        }
        publish_bytes(
            &root,
            "library.json",
            &canonical(domain.root())?,
            &limits.io,
        )?;
        Ok(Self {
            root,
            domain,
            limits,
            generation_guard: None,
        })
    }
    pub fn open(path: impl AsRef<Path>, pinned_root: &str, limits: SyncLimits) -> Result<Self> {
        let root = fs::canonicalize(path.as_ref()).map_err(crate::io_failure)?;
        if !fs::symlink_metadata(path.as_ref())
            .map_err(crate::io_failure)?
            .is_dir()
        {
            return Err(invalid("Exchange root is not a directory"));
        }
        let bytes = read_regular(&root, "library.json", MAX_SEGMENT_BYTES)?;
        if sha256(&bytes) != pinned_root {
            decode::<DomainRoot>(&bytes, MAX_SEGMENT_BYTES).map_err(|_| {
                super::pending_bytes("Selected exchange root is incomplete or noncanonical")
            })?;
            read_domain(&root, &bytes).map_err(|_| {
                super::pending_bytes("Selected root/profile bytes are incomplete or mismatched")
            })?;
            return Err(crate::Error::invalid(
                "sync.root_mismatch",
                "Selected exchange root differs from the pinned identity",
            ));
        }
        let domain = read_domain(&root, &bytes)?;
        Ok(Self {
            root,
            domain,
            limits,
            generation_guard: None,
        })
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
    fn check_root(&self) -> Result<()> {
        self.check_root_with_evidence(&mut Vec::new())
    }
    fn check_root_with_evidence(&self, evidence: &mut Vec<Vec<u8>>) -> Result<()> {
        if let Some((repository, generation)) = &self.generation_guard {
            repository.check_generation(generation)?;
        }
        let actual = read_regular(&self.root, "library.json", MAX_SEGMENT_BYTES)?;
        let pinned = canonical(self.domain.root())?;
        if actual != pinned {
            let parsed = decode::<DomainRoot>(&actual, MAX_SEGMENT_BYTES)
                .map_err(|_| super::pending_bytes("Exchange root is incomplete or noncanonical"))?;
            if parsed.sync_id == self.domain.root().sync_id {
                let mapping = read_regular(&self.root, "profile/mapping.json", MAX_SEGMENT_BYTES)?;
                let profile = read_regular(&self.root, "profile/profile.md", MAX_SEGMENT_BYTES)?;
                read_domain(&self.root, &actual).map_err(|_| {
                    super::pending_bytes(
                        "Changed root does not yet have complete matching profile resources",
                    )
                })?;
                evidence.extend([
                    pinned,
                    canonical(self.domain.mapping())?,
                    self.domain.profile().to_vec(),
                    actual,
                    mapping,
                    profile,
                ]);
                return Err(fork("Exchange root changed under the same domain identity"));
            }
            return Err(invalid(
                "Selected exchange now belongs to a different domain",
            ));
        }
        Ok(())
    }
    pub fn publish_replica(&self, replica: &ReplicaDescriptor) -> Result<()> {
        self.check_root()?;
        replica.validate(&self.domain)?;
        publish_bytes(
            &self.root,
            &replica.relative_path()?,
            &canonical(replica)?,
            &self.limits.io,
        )
    }
    pub fn publish_segment(&self, segment: &Segment) -> Result<()> {
        self.check_root()?;
        segment.validate(&self.domain)?;
        publish_bytes(
            &self.root,
            &segment.relative_path()?,
            &canonical(segment)?,
            &self.limits.io,
        )
    }
    pub fn publish_receipt(&self, receipt: &Receipt) -> Result<()> {
        self.check_root()?;
        receipt.validate(&self.domain)?;
        publish_bytes(
            &self.root,
            &receipt.relative_path()?,
            &canonical(receipt)?,
            &self.limits.io,
        )
    }
    pub fn publish_object(&self, store: &ObjectStore, blob: &Blob) -> Result<()> {
        self.check_root()?;
        if store.root.starts_with(&self.root) || self.root.starts_with(&store.root) {
            return Err(invalid("Local objects and exchange overlap"));
        }
        let destination = ObjectStore {
            root: self.root.clone(),
            limits: self.limits.clone(),
            trusted: None,
        };
        store.with_blob(blob, |reader|destination.put_expected(reader,blob).map(|_|())).map_err(|error|{
            if error.code=="sync.object_conflict"{super::pending_bytes("Existing exchange object is incomplete or mismatched; retry without replacing it")}else{error}
        })
    }
    pub fn scan(&self) -> Result<ExchangeScan> {
        self.scan_with_evidence(&mut ScanEvidence::default())
    }
    pub(crate) fn scan_with_evidence(&self, evidence: &mut ScanEvidence) -> Result<ExchangeScan> {
        self.check_root_with_evidence(&mut evidence.fork)?;
        let end = crate::transfer::deadline(&self.limits.io)?;
        let mut result = ExchangeScan::default();
        let mut files = Vec::new();
        let replicas = safe_path(&self.root, "replicas", false)?;
        if replicas.exists() {
            collect(
                &self.root,
                &replicas,
                &mut files,
                &mut result.diagnostics,
                &self.limits,
                end,
            )?;
        }
        files.sort();
        let mut segments = Vec::new();
        let mut descriptor_bytes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut receipt_digests = BTreeMap::new();
        let mut conflicted_receipts = BTreeSet::new();
        let mut retained_bytes = 0u64;
        for relative in files {
            crate::container::check_deadline(end)?;
            let name = relative.rsplit('/').next().unwrap();
            if !name.ends_with(".json") {
                result.diagnostics.push(diag(
                    &relative,
                    "sync.ignored",
                    "Not a canonical protocol record",
                ));
                continue;
            }
            let bytes = match read_regular(&self.root, &relative, MAX_SEGMENT_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    result
                        .diagnostics
                        .push(diag(&relative, "sync.pending_bytes", e.message));
                    continue;
                }
            };
            retained_bytes = retained_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| super::limit("Scan JSON bytes"))?;
            if retained_bytes > self.limits.max_history_bytes {
                return Err(super::limit("Scan retained JSON budget"));
            }
            let advertised = advertised(name);
            let digest = sha256(&bytes);
            let exact_advertisement = advertised
                .as_ref()
                .is_some_and(|(size, hash)| *size == bytes.len() as u64 && hash == &digest);
            if advertised.is_some() && !exact_advertisement {
                result.diagnostics.push(diag(
                    &relative,
                    "sync.pending_bytes",
                    "Length/digest incomplete or mismatched",
                ));
                continue;
            }
            let value: serde_json::Value = match decode(&bytes, MAX_SEGMENT_BYTES) {
                Ok(v) => v,
                Err(e) => {
                    result.diagnostics.push(diag(
                        &relative,
                        if exact_advertisement {
                            "sync.invalid_record"
                        } else {
                            "sync.ignored"
                        },
                        e.message,
                    ));
                    continue;
                }
            };
            let candidate = (|| -> Result<()> {
                match value["kind"].as_str() {
                    Some("darkbox-sync-replica") => {
                        let descriptor: ReplicaDescriptor = decode(&bytes, MAX_SEGMENT_BYTES)?;
                        descriptor.validate(&self.domain)?;
                        if let Some(old) = descriptor_bytes.get(&descriptor.replica_id)
                            && old != &bytes
                        {
                            evidence.fork.extend([old.clone(), bytes]);
                            return Err(fork("Replica descriptor identity fork"));
                        }
                        descriptor_bytes.insert(descriptor.replica_id.clone(), bytes);
                        if descriptor.relative_path()? == relative {
                            result
                                .replicas
                                .insert(descriptor.replica_id.clone(), descriptor);
                        } else {
                            result.diagnostics.push(diag(
                                &relative,
                                "sync.ignored",
                                "Noncanonical replica descriptor used only for identity checks",
                            ));
                        }
                    }
                    Some("darkbox-sync-segment") => {
                        let segment: Segment = decode(&bytes, MAX_SEGMENT_BYTES)?;
                        segment.validate(&self.domain)?;
                        let canonical = segment.relative_path()? == relative;
                        if !canonical {
                            result.diagnostics.push(diag(
                                &relative,
                                "sync.ignored",
                                "Verified noncanonical copy, fork/duplicate evidence only",
                            ));
                        }
                        segments.push((segment, canonical));
                    }
                    Some("darkbox-sync-receipt") => {
                        let receipt: Receipt = decode(&bytes, MAX_SEGMENT_BYTES)?;
                        receipt.validate(&self.domain)?;
                        let key = (receipt.replica_id.clone(), receipt.serial);
                        if receipt_digests
                            .insert(key.clone(), digest.clone())
                            .is_some_and(|old| old != digest)
                        {
                            conflicted_receipts.insert(key);
                            result.diagnostics.push(diag(
                                &relative,
                                "sync.invalid_record",
                                "Conflicting advisory receipt serial",
                            ));
                        }
                        if receipt.relative_path()? == relative {
                            result.receipts.push(receipt);
                        } else {
                            result.diagnostics.push(diag(
                                &relative,
                                "sync.ignored",
                                "Noncanonical advisory receipt",
                            ));
                        }
                    }
                    Some("darkbox-sync-snapshot") => {
                        let snapshot: SnapshotDescriptor = decode(&bytes, MAX_SEGMENT_BYTES)?;
                        snapshot.validate(&self.domain)?;
                        if snapshot.relative_path()? != relative {
                            return Err(invalid("Noncanonical snapshot descriptor path"));
                        }
                        result.snapshots.push(snapshot);
                    }
                    _ => result.diagnostics.push(diag(
                        &relative,
                        "sync.ignored",
                        "Unknown record kind",
                    )),
                }
                Ok(())
            })();
            if let Err(e) = candidate {
                if e.code == "sync.fork" {
                    return Err(e.at(relative));
                }
                result.diagnostics.push(diag(
                    &relative,
                    if e.status == crate::Status::Unsupported {
                        "sync.unsupported"
                    } else {
                        "sync.invalid_record"
                    },
                    e.message,
                ));
            }
        }
        result.receipts.retain(|receipt| {
            !conflicted_receipts.contains(&(receipt.replica_id.clone(), receipt.serial))
        });
        let mut identities: BTreeMap<_, (SyncTransaction, bool)> = BTreeMap::new();
        for (segment, canonical) in segments {
            let has_descriptor = result.replicas.contains_key(&segment.replica_id);
            if canonical && !has_descriptor {
                result.diagnostics.push(diag(
                    &segment.relative_path()?,
                    "sync.pending_dependency",
                    "Replica descriptor missing",
                ));
            }
            for tx in segment.transactions {
                let key = (tx.replica_id.clone(), tx.sequence);
                let authoritative = canonical && has_descriptor;
                if let Some((old, emitted)) = identities.get_mut(&key) {
                    if old != &tx {
                        evidence.fork.extend([old.bytes()?, tx.bytes()?]);
                        return Err(fork(
                            "Exchange contains two histories at one replica sequence",
                        ));
                    }
                    *emitted |= authoritative;
                } else {
                    identities.insert(key, (tx, authoritative));
                }
                if identities.len() > self.limits.max_transactions {
                    return Err(super::limit("Scan transaction count"));
                }
            }
        }
        for (tx, authoritative) in identities.into_values() {
            if authoritative {
                result.transactions.push(tx);
            } else {
                evidence.copies.push(tx);
            }
        }
        Ok(result)
    }
}
fn diag(path: &str, code: &'static str, message: impl Into<String>) -> ScanDiagnostic {
    ScanDiagnostic {
        path: path.into(),
        code,
        message: message.into(),
    }
}
fn advertised(name: &str) -> Option<(u64, String)> {
    let stem = name.strip_suffix(".json")?;
    let (prefix, hash) = stem.rsplit_once('-')?;
    let length = prefix.rsplit('-').next()?;
    if length.len() != 16 || !hex(length, 16) || !hex(hash, 64) {
        return None;
    }
    Some((u64::from_str_radix(length, 16).ok()?, hash.into()))
}
fn collect(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
    ignored: &mut Vec<ScanDiagnostic>,
    limits: &SyncLimits,
    end: Instant,
) -> Result<()> {
    let mut stack = vec![directory.to_owned()];
    let mut seen = 0;
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).map_err(crate::io_failure)? {
            crate::container::check_deadline(end)?;
            seen += 1;
            if seen > limits.max_scan_files {
                return Err(super::limit("Sync scan entry count"));
            }
            let entry = entry.map_err(crate::io_failure)?;
            let kind = entry.file_type().map_err(crate::io_failure)?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|_| invalid("Sync path escaped its root"))?;
            let Some(relative) = relative.to_str() else {
                ignored.push(diag(
                    &relative.to_string_lossy(),
                    "sync.ignored",
                    "Non-UTF-8 names cannot be canonical protocol paths",
                ));
                continue;
            };
            if kind.is_dir() {
                let parts: Vec<_> = relative.split('/').collect();
                let canonical = match parts.as_slice() {
                    ["replicas", replica] => hex(replica, 32),
                    ["replicas", replica, "segments" | "snapshots" | "receipts"] => {
                        hex(replica, 32)
                    }
                    _ => false,
                };
                if canonical {
                    stack.push(path);
                } else {
                    ignored.push(diag(relative, "sync.ignored", "Unknown protocol subtree"));
                }
            } else {
                files.push(relative.into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod verified_object_tests {
    use super::*;

    fn full_checks(store: &ObjectStore) -> usize {
        store.trusted.as_ref().unwrap().lock().unwrap().full_checks
    }

    #[test]
    fn trusted_reads_share_bounded_witnesses_and_full_verification_can_be_forced() {
        let root = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(root.path(), SyncLimits::default())
            .unwrap()
            .with_trusted_immutable_cache(1);
        let first = store
            .put(&mut b"first immutable object".as_slice())
            .unwrap();
        assert!(store.contains(&first).unwrap());
        assert_eq!(full_checks(&store), 1);
        let clone = store.clone();
        let bytes = clone
            .with_blob(&first, |reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).map_err(crate::io_failure)?;
                Ok(bytes)
            })
            .unwrap();
        assert_eq!(bytes, b"first immutable object");
        assert_eq!(
            full_checks(&store),
            1,
            "cached reading must not hash the object again"
        );
        assert!(clone.verify(&first).unwrap());
        assert_eq!(full_checks(&store), 2);
        let second = store
            .put(&mut b"second immutable object".as_slice())
            .unwrap();
        assert!(clone.contains(&second).unwrap());
        assert_eq!(full_checks(&store), 3);
        assert_eq!(
            store
                .trusted
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .entries
                .len(),
            1
        );
        assert!(store.contains(&first).unwrap());
        assert_eq!(
            full_checks(&store),
            4,
            "evicted witnesses require a complete check"
        );
        clone.clear_verification_cache();
        assert!(store.contains(&first).unwrap());
        assert_eq!(full_checks(&store), 5);
        assert!(
            store
                .clone()
                .with_trusted_immutable_cache(0)
                .trusted
                .is_none()
        );
    }

    #[test]
    fn changed_missing_and_callback_modified_objects_cannot_reuse_a_witness() {
        let root = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(root.path(), SyncLimits::default())
            .unwrap()
            .with_trusted_immutable_cache(4);
        let original = b"original immutable data";
        let blob = store.put(&mut original.as_slice()).unwrap();
        assert!(store.contains(&blob).unwrap());
        let path = store.path().join(blob.relative_path().unwrap());
        let error = store
            .with_blob(&blob, |reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).map_err(crate::io_failure)?;
                fs::write(&path, vec![b'x'; original.len()]).map_err(crate::io_failure)?;
                File::open(&path)
                    .map_err(crate::io_failure)?
                    .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
                    .map_err(crate::io_failure)?;
                Ok(bytes)
            })
            .unwrap_err();
        assert_eq!(error.code, "sync.invalid");
        assert!(!store.contains(&blob).unwrap());
        assert!(
            !ObjectStore::open(root.path(), SyncLimits::default())
                .unwrap()
                .contains(&blob)
                .unwrap()
        );
        fs::remove_file(&path).unwrap();
        assert!(!store.contains(&blob).unwrap());
        store.put_expected(&mut original.as_slice(), &blob).unwrap();
        assert!(store.contains(&blob).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn creating_a_read_only_hard_link_during_access_invalidates_only_the_cache() {
        let root = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(root.path(), SyncLimits::default())
            .unwrap()
            .with_trusted_immutable_cache(2);
        let blob = store.put(&mut b"immutable media".as_slice()).unwrap();
        assert!(store.contains(&blob).unwrap());
        store
            .with_blob(&blob, |reader| {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes).map_err(crate::io_failure)?;
                fs::hard_link(
                    store.path().join(blob.relative_path()?),
                    root.path().join("materialized"),
                )
                .map_err(crate::io_failure)?;
                assert_eq!(bytes, b"immutable media");
                Ok(())
            })
            .unwrap();
        assert!(store.contains(&blob).unwrap());
        assert_eq!(full_checks(&store), 2);
    }

    #[test]
    #[cfg(unix)]
    fn trusted_cache_rejects_replacement_and_symlinks_even_with_matching_size_and_mtime() {
        let root = tempfile::tempdir().unwrap();
        let store = ObjectStore::open(root.path(), SyncLimits::default())
            .unwrap()
            .with_trusted_immutable_cache(2);
        let blob = store.put(&mut b"original".as_slice()).unwrap();
        assert!(store.contains(&blob).unwrap());
        let path = store.path().join(blob.relative_path().unwrap());
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let replacement = root.path().join("replacement");
        fs::write(&replacement, b"replaced").unwrap();
        File::open(&replacement)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(!store.contains(&blob).unwrap());
        fs::remove_file(&path).unwrap();
        store.put(&mut b"original".as_slice()).unwrap();
        assert!(store.contains(&blob).unwrap());
        fs::rename(&path, &replacement).unwrap();
        std::os::unix::fs::symlink(&replacement, &path).unwrap();
        assert!(store.contains(&blob).is_err());
    }
}
