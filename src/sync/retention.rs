use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionPolicy {
    pub retention_seconds: Counter,
    pub keep_checkpoints: Counter,
    pub checkpoint_interval_seconds: Counter,
    pub checkpoint_transactions: Counter,
    pub checkpoint_history_bytes: Counter,
}
impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            retention_seconds: Counter(30 * 86400),
            keep_checkpoints: Counter(2),
            checkpoint_interval_seconds: Counter(7 * 86400),
            checkpoint_transactions: Counter(10_000),
            checkpoint_history_bytes: Counter(16 * 1024 * 1024),
        }
    }
}
impl RetentionPolicy {
    fn validate(&self) -> Result<()> {
        if self.retention_seconds.0 == 0
            || self.keep_checkpoints.0 < 2
            || self.checkpoint_interval_seconds.0 == 0
            || self.checkpoint_transactions.0 == 0
            || self.checkpoint_history_bytes.0 == 0
        {
            return Err(invalid(
                "Retention policy requires a grace window, at least two checkpoints and positive thresholds",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryRoot {
    pub kind: String,
    pub protocol_version: String,
    pub repository_id: String,
    pub package_id: String,
    pub application: Application,
    pub mapping_sha256: String,
    pub profile_sha256: String,
    pub policy: RetentionPolicy,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Generation {
    pub kind: String,
    pub protocol_version: String,
    pub repository_sha256: String,
    pub ordinal: Counter,
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<String>,
    pub created_at: Counter,
    pub checkpoint: SnapshotDescriptor,
}
impl Generation {
    pub fn id(&self) -> Result<String> {
        Ok(sha256(&canonical(self)?))
    }
    pub fn relative_path(&self) -> Result<String> {
        let bytes = canonical(self)?;
        Ok(format!(
            "generations/{:020}-{:016x}-{}.json",
            self.ordinal.0,
            bytes.len(),
            sha256(&bytes)
        ))
    }
    fn domain_path(&self) -> String {
        format!("domains/{:020}/{}", self.ordinal.0, self.checkpoint.sync_id)
    }
    fn validate(&self, repository: &SyncRepository) -> Result<()> {
        super::wire::version(
            &self.kind,
            &self.protocol_version,
            "darkbox-sync-generation",
        )?;
        if self.repository_sha256 != repository.hash
            || self.parent.as_ref().is_some_and(|id| !hex(id, 64))
            || self.replaces.iter().any(|id| !hex(id, 64))
            || !self.replaces.windows(2).all(|pair| pair[0] < pair[1])
            || self
                .parent
                .as_ref()
                .is_some_and(|id| self.replaces.contains(id))
            || (self.ordinal.0 == 0) != self.parent.is_none()
            || !hex(&self.checkpoint.sync_id, 32)
            || !hex(&self.checkpoint.root_sha256, 64)
        {
            return Err(invalid("Generation identity or parent differs"));
        }
        super::wire::version(
            &self.checkpoint.kind,
            &self.checkpoint.protocol_version,
            "darkbox-sync-snapshot",
        )?;
        super::wire::validate_frontier(&self.checkpoint.frontier)?;
        if !hex(&self.checkpoint.replica_id, 32)
            || !hex(&self.checkpoint.package.sha256, 64)
            || !hex(&self.checkpoint.state_sha256, 64)
            || self.checkpoint.package.size.0 == 0
            || self.checkpoint.package.size.0 > repository.limits.io.max_archive_bytes
        {
            return Err(invalid("Generation checkpoint identity or size"));
        }
        let expected = format!(
            "replicas/{}/snapshots/{}.darkbox",
            self.checkpoint.replica_id, self.checkpoint.package.sha256
        );
        if self.checkpoint.package.path != expected {
            return Err(invalid("Generation checkpoint path differs"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseStatus {
    Current,
    Superseded { retire_at: Counter },
    Expired,
}
#[derive(Clone, Debug, Default)]
pub struct PruneReport {
    pub generations: Vec<String>,
    pub removed_files: usize,
}
/// A membership-free cloud exchange containing independently complete generations.
#[derive(Clone, Debug)]
pub struct SyncRepository {
    root: PathBuf,
    descriptor: RepositoryRoot,
    hash: String,
    high_water: std::sync::Arc<std::sync::Mutex<Option<(Counter, String)>>>,
    limits: SyncLimits,
}
impl SyncRepository {
    pub fn create(
        path: impl AsRef<Path>,
        domain: &Domain,
        policy: RetentionPolicy,
        limits: SyncLimits,
    ) -> Result<Self> {
        policy.validate()?;
        let descriptor = RepositoryRoot {
            kind: "darkbox-sync-repository".into(),
            protocol_version: VERSION.into(),
            repository_id: random_id()?,
            package_id: domain.root().package_id.clone(),
            application: domain.root().application.clone(),
            mapping_sha256: sha256(&canonical(domain.mapping())?),
            profile_sha256: sha256(domain.profile()),
            policy,
        };
        let bytes = canonical(&descriptor)?;
        let root = super::exchange::directory(path.as_ref())?;
        super::exchange::publish_bytes(&root, "repository.json", &bytes)?;
        Ok(Self {
            root,
            descriptor,
            hash: sha256(&bytes),
            high_water: Default::default(),
            limits,
        })
    }
    pub fn open(path: impl AsRef<Path>, pinned_hash: &str, limits: SyncLimits) -> Result<Self> {
        if !fs::symlink_metadata(path.as_ref())
            .map_err(crate::io_failure)?
            .is_dir()
        {
            return Err(invalid("Repository root must be a real directory"));
        }
        let root = fs::canonicalize(path.as_ref()).map_err(crate::io_failure)?;
        let bytes = super::exchange::read_regular(&root, "repository.json", MAX_SEGMENT_BYTES)?;
        if sha256(&bytes) != pinned_hash {
            return Err(invalid("Repository root differs from the pinned identity"));
        }
        let descriptor: RepositoryRoot = decode(&bytes, MAX_SEGMENT_BYTES)?;
        super::wire::version(
            &descriptor.kind,
            &descriptor.protocol_version,
            "darkbox-sync-repository",
        )?;
        descriptor.policy.validate()?;
        if !hex(&descriptor.repository_id, 32)
            || !hex(&descriptor.package_id, 32)
            || !hex(&descriptor.mapping_sha256, 64)
            || !hex(&descriptor.profile_sha256, 64)
        {
            return Err(invalid("Repository identity"));
        }
        Ok(Self {
            root,
            descriptor,
            hash: pinned_hash.into(),
            high_water: Default::default(),
            limits,
        })
    }
    fn private_staging(&self, prefix: &str) -> Result<tempfile::TempDir> {
        let temporary = self.limits.io.tempdir(prefix)?;
        if temporary.path().starts_with(&self.root) {
            return Err(invalid(
                "Synchronization staging must remain outside the cloud repository",
            ));
        }
        Ok(temporary)
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    pub fn root_hash(&self) -> &str {
        &self.hash
    }
    pub fn policy(&self) -> &RetentionPolicy {
        &self.descriptor.policy
    }
    fn check_root(&self) -> Result<()> {
        if super::exchange::read_regular(&self.root, "repository.json", MAX_SEGMENT_BYTES)?
            != canonical(&self.descriptor)?
        {
            return Err(fork("Repository policy changed under its pinned identity"));
        }
        Ok(())
    }
    fn check_domain(&self, domain: &Domain) -> Result<()> {
        if domain.root().package_id != self.descriptor.package_id
            || domain.root().application != self.descriptor.application
            || sha256(&canonical(domain.mapping())?) != self.descriptor.mapping_sha256
            || sha256(domain.profile()) != self.descriptor.profile_sha256
        {
            return Err(invalid(
                "Generation changes the repository profile contract",
            ));
        }
        Ok(())
    }
    /// Read complete immutable control records. A partially arriving authoritative record waits.
    pub fn generations(&self) -> Result<Vec<Generation>> {
        self.check_root()?;
        let directory = super::exchange::safe_path(&self.root, "generations", false)?;
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let end = crate::transfer::deadline(&self.limits.io)?;
        let mut generations = BTreeMap::new();
        let mut bytes_read = 0u64;
        for (count, entry) in fs::read_dir(directory)
            .map_err(crate::io_failure)?
            .enumerate()
        {
            crate::container::check_deadline(end)?;
            if count >= self.limits.max_scan_files {
                return Err(super::limit("Generation control entries"));
            }
            let entry = entry.map_err(crate::io_failure)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.ends_with(".json") || !entry.file_type().map_err(crate::io_failure)?.is_file()
            {
                continue;
            }
            let path = format!("generations/{name}");
            let bytes = super::exchange::read_regular(&self.root, &path, MAX_SEGMENT_BYTES)?;
            bytes_read = bytes_read
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| super::limit("Generation metadata"))?;
            if bytes_read > self.limits.max_history_bytes {
                return Err(super::limit("Generation metadata budget"));
            }
            let generation = match decode::<Generation>(&bytes, MAX_SEGMENT_BYTES) {
                Ok(generation) => generation,
                Err(error) if canonical_generation_name(name) => {
                    return Err(super::pending_bytes(error.message));
                }
                Err(_) => continue,
            };
            generation.validate(self)?;
            if generation.relative_path()? != path {
                // Valid renamed control records are conflict evidence, never a selected head.
                if canonical_generation_name(name) {
                    return Err(super::pending_bytes(
                        "Generation control hash or length is incomplete",
                    ));
                }
                let id = generation.id()?;
                generations.entry(id).or_insert((generation, false));
            } else {
                generations.insert(generation.id()?, (generation, true));
            }
        }
        let mut result: Vec<_> = generations.into_values().map(|(g, _)| g).collect();
        result.sort_by_key(|generation| generation.ordinal);
        let known: BTreeMap<_, _> = result
            .iter()
            .map(|g| Ok((g.id()?, g)))
            .collect::<Result<_>>()?;
        for generation in &result {
            if let Some(parent) = generation.parent.as_ref().and_then(|id| known.get(id))
                && (parent.ordinal >= generation.ordinal
                    || parent.created_at > generation.created_at)
            {
                return Err(invalid("Generation chain or creation time regressed"));
            }
        }
        Ok(result)
    }
    pub fn current(&self) -> Result<Generation> {
        for certificate in self.retirement_records()? {
            if let Some(witness) = certificate
                .witnesses
                .iter()
                .max_by_key(|generation| generation.ordinal)
            {
                let mut high_water = self
                    .high_water
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                if high_water
                    .as_ref()
                    .is_none_or(|(ordinal, _)| *ordinal < witness.ordinal)
                {
                    *high_water = Some((witness.ordinal, witness.id()?));
                }
            }
        }
        let generations = self.generations()?;
        let current = generations
            .last()
            .ok_or_else(|| super::pending_bytes("Initial complete generation has not arrived"))?;
        if generations
            .iter()
            .filter(|generation| generation.ordinal == current.ordinal)
            .count()
            != 1
        {
            return Err(generation_conflict());
        }
        let bytes =
            super::exchange::read_regular(&self.root, &current.relative_path()?, MAX_SEGMENT_BYTES)
                .map_err(|_| {
                    super::pending_bytes(
                        "Selected generation is only a renamed copy or has not arrived completely",
                    )
                })?;
        if bytes != canonical(current)? {
            return Err(super::pending_bytes("Generation control bytes differ"));
        }
        let mut high_water = self
            .high_water
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let identity = current.id()?;
        if let Some((ordinal, id)) = high_water.as_ref() {
            if *ordinal > current.ordinal {
                return Err(super::pending_bytes(
                    "The most recently observed generation is temporarily missing",
                ));
            }
            if *ordinal == current.ordinal && id != &identity {
                return Err(generation_conflict());
            }
        }
        *high_water = Some((current.ordinal, identity));
        Ok(current.clone())
    }
    pub fn base_status(&self, domain: &Domain, now: u64) -> Result<BaseStatus> {
        self.check_domain(domain)?;
        self.current()?;
        let generations = self.generations()?;
        let current = generations
            .last()
            .ok_or_else(|| super::pending_bytes("No complete generation"))?;
        if current.checkpoint.root_sha256 == domain.root_hash() {
            return Ok(BaseStatus::Current);
        }
        let old = generations
            .iter()
            .find(|generation| generation.checkpoint.root_sha256 == domain.root_hash());
        let successor = old.map(Generation::id).transpose()?.and_then(|id| {
            generations
                .iter()
                .find(|generation| generation.parent.as_ref() == Some(&id))
        });
        if let Some(successor) = successor {
            let retire_at = successor
                .created_at
                .0
                .checked_add(self.policy().retention_seconds.0)
                .ok_or_else(|| unsupported("Generation expiry overflow"))?;
            if now < retire_at {
                return Ok(BaseStatus::Superseded {
                    retire_at: Counter(retire_at),
                });
            }
        }
        Ok(BaseStatus::Expired)
    }
    pub fn exchange(&self, generation: &Generation) -> Result<Exchange> {
        generation.validate(self)?;
        let path = super::exchange::safe_path(&self.root, &generation.domain_path(), false)?;
        let mut exchange = Exchange::open(
            path,
            &generation.checkpoint.root_sha256,
            self.limits.clone(),
        )?;
        self.check_domain(exchange.domain())?;
        generation.checkpoint.validate(exchange.domain())?;
        exchange.generation_guard = Some((self.clone(), generation.id()?));
        Ok(exchange)
    }
    pub(crate) fn check_generation(&self, id: &str) -> Result<()> {
        if self.current()?.id()? != id {
            return Err(crate::Error::new(
                crate::Status::OperationalError,
                "sync.generation_changed",
                "The base was superseded; preserve unpublished edits and rebase before publishing",
            ));
        }
        Ok(())
    }
    pub fn checkpoint(
        &self,
        generation: &Generation,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<SyncSnapshot> {
        let exchange = self.exchange(generation)?;
        // Fetch is also used for retained generations, so it does not invoke the write guard.
        let path = super::exchange::safe_path(
            exchange.path(),
            &generation.checkpoint.package.path,
            false,
        )?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(super::pending_bytes(
                    "Generation checkpoint has not arrived",
                ));
            }
            Err(error) => return Err(crate::io_failure(error)),
        };
        if !metadata.is_file() {
            return Err(invalid("Generation checkpoint is not a regular file"));
        }
        if metadata.len() != generation.checkpoint.package.size.0 {
            return Err(super::pending_bytes(
                "Generation checkpoint length is incomplete",
            ));
        }
        let digest = crate::writer::file_digest(
            &path,
            self.limits.io.max_archive_bytes,
            crate::transfer::deadline(&self.limits.io)?,
        )?;
        let digest: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if digest != generation.checkpoint.package.sha256 {
            return Err(super::pending_bytes(
                "Generation checkpoint digest is incomplete",
            ));
        }
        let snapshot = SyncSnapshot::fetch(
            &exchange,
            &generation.checkpoint,
            self.limits.clone(),
            options,
        )?;
        self.check_domain(snapshot.history().domain())?;
        Ok(snapshot)
    }
    pub fn publish_initial(
        &self,
        snapshot: &SyncSnapshot,
        adapter: &dyn SyncProjection,
        now: u64,
    ) -> Result<Generation> {
        if !self.generations()?.is_empty() {
            return Err(invalid("Initial generation already exists"));
        }
        self.publish(snapshot, None, &[], adapter, now)
    }
    fn publish(
        &self,
        snapshot: &SyncSnapshot,
        parent: Option<&Generation>,
        replaces: &[Generation],
        adapter: &dyn SyncProjection,
        now: u64,
    ) -> Result<Generation> {
        self.check_root()?;
        self.check_domain(snapshot.history().domain())?;
        snapshot.verify_projection(adapter)?;
        if let Some(parent) = parent {
            if (replaces.is_empty() && self.current()?.id()? != parent.id()?)
                || now < parent.created_at.0
            {
                return Err(generation_conflict());
            }
            if snapshot.history().domain().root_hash() == parent.checkpoint.root_sha256 {
                return Err(invalid("Compaction requires a fresh generation domain"));
            }
        }
        let ordinal = Counter(
            parent
                .into_iter()
                .chain(replaces.iter())
                .map(|generation| generation.ordinal.0)
                .max()
                .map_or(Ok(0), |ordinal| {
                    ordinal
                        .checked_add(1)
                        .ok_or_else(|| unsupported("Generation ordinal exhausted"))
                })?,
        );
        let domain = snapshot.history().domain();
        let path = super::exchange::safe_path(
            &self.root,
            &format!("domains/{:020}/{}", ordinal.0, domain.root().sync_id),
            true,
        )?;
        let exchange = Exchange::create(path, domain.clone(), self.limits.clone())?;
        let publisher = ReplicaDescriptor {
            kind: "darkbox-sync-replica".into(),
            protocol_version: VERSION.into(),
            sync_id: domain.root().sync_id.clone(),
            root_sha256: domain.root_hash().into(),
            replica_id: random_id()?,
            device_id: random_id()?,
            label: "checkpoint publisher".into(),
        };
        exchange.publish_replica(&publisher)?;
        let checkpoint = snapshot.publish(&exchange, &publisher)?;
        let generation = Generation {
            kind: "darkbox-sync-generation".into(),
            protocol_version: VERSION.into(),
            repository_sha256: self.hash.clone(),
            ordinal,
            parent: parent.map(Generation::id).transpose()?,
            replaces: {
                let mut ids = replaces
                    .iter()
                    .map(Generation::id)
                    .collect::<Result<Vec<_>>>()?;
                ids.sort();
                ids.dedup();
                ids
            },
            created_at: Counter(now),
            checkpoint,
        };
        generation.validate(self)?;
        // The control record is published last, after the entire independently usable package.
        super::exchange::publish_bytes(
            &self.root,
            &generation.relative_path()?,
            &canonical(&generation)?,
        )?;
        Ok(generation)
    }
    pub fn compaction_due(&self, history: &History, now: u64) -> Result<bool> {
        let current = self.current()?;
        if current.checkpoint.root_sha256 != history.domain().root_hash() {
            return Err(generation_conflict());
        }
        let bytes: u64 = history
            .transaction_bytes()
            .map(|bytes| bytes.len() as u64 + 1)
            .sum();
        Ok(
            history.len() as u64 >= self.policy().checkpoint_transactions.0
                || bytes >= self.policy().checkpoint_history_bytes.0
                || (!history.is_empty()
                    && now.saturating_sub(current.created_at.0)
                        >= self.policy().checkpoint_interval_seconds.0),
        )
    }
    pub fn compact(
        &self,
        source: &SyncSnapshot,
        objects: &ObjectStore,
        adapter: &dyn SyncProjection,
        now: u64,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<Generation> {
        if objects.path().starts_with(&self.root) || self.root.starts_with(objects.path()) {
            return Err(invalid("Compaction objects must remain private"));
        }
        let parent = self.current()?;
        if parent.checkpoint.root_sha256 != source.history().domain().root_hash() {
            return Err(generation_conflict());
        }
        source.verify_projection(adapter)?;
        source.import_objects(objects)?;
        let scratch = self.private_staging("darkbox-sync-compact-")?;
        let path = scratch.path().join("checkpoint.darkbox");
        build_compact(
            source,
            objects,
            adapter,
            &path,
            self.limits.io.clone(),
            options,
        )?;
        let snapshot = SyncSnapshot::open(path, self.limits.clone(), options)?;
        self.publish(&snapshot, Some(&parent), &[], adapter, now)
    }
    /// Remove only expired ancestors. Complete current checkpoints are independently verified first.
    pub fn prune(
        &self,
        now: u64,
        adapter: &dyn SyncProjection,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<PruneReport> {
        self.current()?;
        let generations = self.generations()?;
        let current = generations
            .last()
            .ok_or_else(|| super::pending_bytes("No generation to retain"))?;
        let snapshot = self.checkpoint(current, options)?;
        snapshot.verify_projection(adapter)?;
        let head = current.id()?;
        self.prune_verified(now, current, &generations, &head)
    }
}
fn canonical_generation_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    let parts: Vec<_> = stem.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 20
        && parts[0].bytes().all(|c| c.is_ascii_digit())
        && hex(parts[1], 16)
        && hex(parts[2], 64)
}
fn generation_conflict() -> crate::Error {
    crate::Error::new(
        crate::Status::OperationalError,
        "sync.generation_conflict",
        "Concurrent or changed checkpoint generations require explicit reconciliation; pruning is stopped",
    )
}
fn remove_owned_tree(root: &Path, directory: &Path, maximum: usize) -> Result<usize> {
    let mut stack = vec![directory.to_owned()];
    let mut count = 0;
    while let Some(path) = stack.pop() {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| invalid("Retention escaped repository"))?
            .to_str()
            .ok_or_else(|| invalid("Non-UTF-8 generation path"))?;
        let checked = super::exchange::checked_path(root, relative, false)?;
        let metadata = fs::symlink_metadata(&checked).map_err(crate::io_failure)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("Retention refuses symlinks"));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(checked).map_err(crate::io_failure)? {
                count += 1;
                if count > maximum {
                    return Err(super::limit("Retention entry count"));
                }
                stack.push(entry.map_err(crate::io_failure)?.path());
            }
        } else if !metadata.is_file() {
            return Err(invalid("Retention refuses special files"));
        }
    }
    // The standard-library remover uses no-follow directory-relative traversal on
    // the supported Linux/macOS targets, including races during recursive deletion.
    fs::remove_dir_all(directory).map_err(crate::io_failure)?;
    super::exchange::sync_dir(directory.parent().unwrap())?;
    Ok(count)
}

fn build_compact(
    source: &SyncSnapshot,
    objects: &ObjectStore,
    adapter: &dyn SyncProjection,
    output: &Path,
    limits: crate::Limits,
    options: &crate::VerificationOptions<'_>,
) -> Result<()> {
    let compact = source.history().compact()?;
    let manifest = source.package().manifest();
    let mut builder = SnapshotBuilder::new(
        output,
        manifest.clone(),
        &compact,
        objects,
        adapter,
        limits,
        options,
    )?;
    copy_snapshot_extras(source, &mut builder)?;
    builder.finish()?;
    Ok(())
}

pub struct RebaseTarget<'a> {
    pub destination: &'a Path,
    pub objects: &'a ObjectStore,
    pub recovery_path: Option<&'a Path>,
}
pub struct PreparedRebase {
    pub library: crate::DirectoryLibrary,
    pub generation: Generation,
    pub source_revision: Counter,
    pub recovery: Option<PathBuf>,
}
impl SyncRepository {
    /// Build a fresh local library. Existing source paths remain available until the
    /// application checks this preparation under its write barrier and adopts it.
    pub fn prepare_rebase(
        &self,
        session: &SyncSession<'_>,
        connection: &rusqlite::Connection,
        target: RebaseTarget<'_>,
        adapter: &dyn SyncProjection,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<PreparedRebase> {
        let RebaseTarget {
            destination,
            objects,
            recovery_path,
        } = target;
        let destination =
            crate::transfer::output_path(destination, &[self.path(), session.working_path()])?;
        if destination.starts_with(self.path())
            || destination.starts_with(session.working_path())
            || objects.path().starts_with(self.path())
            || self.path().starts_with(objects.path())
            || objects.path().starts_with(&destination)
            || destination.starts_with(objects.path())
        {
            return Err(invalid(
                "Rebase targets and private objects must remain outside the cloud and source library",
            ));
        }
        self.check_domain(session.domain())?;
        self.observe_local_binding(connection)?;
        let generation = self.current()?;
        if generation.checkpoint.root_sha256 == session.domain().root_hash() {
            return Err(invalid("Session already uses the current base"));
        }
        let checkpoint = self.checkpoint(&generation, options)?;
        checkpoint.verify_projection(adapter)?;
        let read = connection.unchecked_transaction().map_err(sql)?;
        let source = session.history(&read)?;
        let mut revision = session.revision(&read)?;
        let queued = session.queued_count(&read)?;
        let pending = session.pending_count(&read)?;
        read.commit().map_err(sql)?;
        let covered = checkpoint
            .history()
            .domain()
            .baseline()
            .is_some_and(|base| {
                base.source_root_sha256 == source.domain().root_hash()
                    && base.source_frontier == source.frontier()
            });
        let recovery = if !covered || queued > 0 || pending > 0 {
            let path = recovery_path.ok_or_else(|| crate::Error::new(crate::Status::OperationalError, "sync.recovery_required", "The old base has edits that cannot be certified as covered; supply a private recovery package path"))?;
            let output = crate::transfer::output_path(path, &[&self.root])?;
            if output.starts_with(&self.root) || output.starts_with(session.working_path()) {
                return Err(invalid("Recovery must remain outside the cloud repository"));
            }
            let receipt = session.export_recovery(connection, &output, adapter, options)?;
            revision = receipt.source_revision;
            Some(output)
        } else {
            None
        };
        session.check_rebase_revision(connection, revision)?;
        self.check_generation(&generation.id()?)?;
        let staging = tempfile::Builder::new()
            .prefix(".darkbox-rebase-")
            .tempdir_in(destination.parent().unwrap())
            .map_err(crate::io_failure)?;
        let candidate = staging.path().join("library");
        let library = checkpoint.bootstrap(&candidate, objects, adapter)?;
        let database = super::exchange::safe_path(
            library.path(),
            &checkpoint
                .history()
                .domain()
                .mapping()
                .storage
                .database_path,
            false,
        )?;
        let mut local = rusqlite::Connection::open(&database).map_err(sql)?;
        local
            .execute_batch(
                "PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;",
            )
            .map_err(sql)?;
        let transaction = local.transaction().map_err(sql)?;
        adapter.copy_local(connection, &transaction, checkpoint.history().domain())?;
        if transaction.is_autocommit() {
            return Err(invalid("Local-column adapter ended its owning transaction"));
        }
        adapter.verify(
            &transaction,
            checkpoint.history().domain(),
            &checkpoint.history().state(),
        )?;
        let binding = RepositoryBinding {
            repository_sha256: self.hash.clone(),
            generation_sha256: generation.id()?,
            ordinal: generation.ordinal,
            root_sha256: generation.checkpoint.root_sha256.clone(),
        };
        super::journal::set_meta(&transaction, "repository_generation", &canonical(&binding)?)?;
        transaction.commit().map_err(sql)?;
        local.close().map_err(|(_, error)| sql(error))?;
        fs::File::open(database)
            .and_then(|file| file.sync_all())
            .map_err(crate::io_failure)?;
        session.check_rebase_revision(connection, revision)?;
        self.check_generation(&generation.id()?)?;
        drop(library);
        let library = crate::DirectoryLibrary::adopt_prepared(&candidate, &destination)?;
        Ok(PreparedRebase {
            library,
            generation,
            source_revision: revision,
            recovery,
        })
    }
    pub fn check_prepared_rebase(
        &self,
        session: &SyncSession<'_>,
        connection: &rusqlite::Connection,
        prepared: &PreparedRebase,
    ) -> Result<()> {
        session.check_rebase_revision(connection, prepared.source_revision)?;
        self.check_generation(&prepared.generation.id()?)
    }
}

pub struct ResolutionTarget<'a> {
    pub objects: &'a ObjectStore,
    pub recovery_directory: &'a Path,
    pub now: u64,
}
impl SyncRepository {
    /// Explicitly choose a reconciled state. Every observed branch is first exported
    /// to a complete private recovery package. This is never an automatic winner rule.
    pub fn resolve_with_checkpoint(
        &self,
        selected: &Generation,
        source: &SyncSnapshot,
        target: ResolutionTarget<'_>,
        adapter: &dyn SyncProjection,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<Generation> {
        let generations = self.generations()?;
        let selected_id = selected.id()?;
        if !generations
            .iter()
            .any(|generation| generation.id().is_ok_and(|id| id == selected_id))
            || source.history().domain().root_hash() != selected.checkpoint.root_sha256
        {
            return Err(invalid(
                "Resolution source does not match the explicitly selected branch",
            ));
        }
        if generations
            .iter()
            .any(|generation| generation.created_at.0 > target.now)
        {
            return Err(invalid("Resolution time precedes an observed generation"));
        }
        let replacements: Vec<_> = generations
            .iter()
            .filter(|generation| generation.id().is_ok_and(|id| id != selected_id))
            .cloned()
            .collect();
        if replacements.is_empty() {
            return Err(invalid("Resolution needs competing retained branches"));
        }
        let output = crate::transfer::output_path(target.recovery_directory, &[&self.root])?;
        if output.starts_with(&self.root)
            || target.objects.path().starts_with(&self.root)
            || self.root.starts_with(target.objects.path())
        {
            return Err(invalid("Resolution recovery must be private"));
        }
        let staging = tempfile::Builder::new()
            .prefix(".darkbox-resolution-")
            .tempdir_in(output.parent().unwrap())
            .map_err(crate::io_failure)?;
        let candidate = staging.path().join("recovery");
        fs::create_dir(&candidate).map_err(crate::io_failure)?;
        let ids: BTreeSet<_> = generations
            .iter()
            .map(Generation::id)
            .collect::<Result<_>>()?;
        for generation in &generations {
            self.export_generation(
                generation,
                &candidate.join(format!("{}.darkbox", generation.id()?)),
                adapter,
                options,
            )?;
        }
        super::exchange::publish_bytes(&candidate, "generations.json", &canonical(&generations)?)?;
        super::exchange::sync_dir(&candidate)?;
        fs::create_dir(&output).map_err(crate::io_failure)?;
        if let Err(error) = fs::rename(&candidate, &output) {
            let _ = fs::remove_dir(&output);
            return Err(crate::io_failure(error));
        }
        super::exchange::sync_dir(output.parent().unwrap())?;
        let fresh: BTreeSet<_> = self
            .generations()?
            .iter()
            .map(Generation::id)
            .collect::<Result<_>>()?;
        if fresh != ids {
            return Err(generation_conflict());
        }
        source.import_objects(target.objects)?;
        let scratch = self.private_staging("darkbox-sync-resolution-")?;
        let package = scratch.path().join("selected.darkbox");
        build_compact(
            source,
            target.objects,
            adapter,
            &package,
            self.limits.io.clone(),
            options,
        )?;
        let selected_snapshot = SyncSnapshot::open(package, self.limits.clone(), options)?;
        self.publish(
            &selected_snapshot,
            Some(selected),
            &replacements,
            adapter,
            target.now,
        )
    }
    pub fn export_generation(
        &self,
        generation: &Generation,
        output: &Path,
        adapter: &dyn SyncProjection,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<()> {
        let output = crate::transfer::output_path(output, &[&self.root])?;
        if output.starts_with(&self.root) {
            return Err(invalid("Generation recovery must remain private"));
        }
        let source = self.checkpoint(generation, options)?;
        let mut exchange = self.exchange(generation)?;
        exchange.generation_guard = None;
        let scan = exchange.scan()?;
        if scan
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code != "sync.ignored")
        {
            return Err(super::pending_bytes(
                "Branch recovery requires every observed record to be complete and supported",
            ));
        }
        let transactions = source
            .history()
            .transactions()
            .cloned()
            .chain(scan.transactions)
            .collect();
        let history = History::replay(
            source.history().domain().clone(),
            transactions,
            self.limits.clone(),
        )?;
        let scratch = self.private_staging("darkbox-sync-branch-")?;
        let objects = ObjectStore::open(scratch.path().join("objects"), self.limits.clone())?;
        source.import_objects(&objects)?;
        for blob in history.blobs()? {
            if !objects.import(&exchange, &blob)? {
                return Err(super::pending_bytes(
                    "Branch recovery is waiting for historical media",
                ));
            }
        }
        let mut builder = SnapshotBuilder::new(
            &output,
            source.package().manifest().clone(),
            &history,
            &objects,
            adapter,
            self.limits.io.clone(),
            options,
        )?;
        copy_snapshot_extras(&source, &mut builder)?;
        builder.finish()?;
        Ok(())
    }
}
fn copy_snapshot_extras(source: &SyncSnapshot, builder: &mut SnapshotBuilder<'_>) -> Result<()> {
    let manifest = source.package().manifest();
    let spec = crate::creation::specification(manifest)?;
    let canonical_paths: BTreeSet<_> = spec
        .files
        .iter()
        .map(|file| file.path)
        .chain(std::iter::once(crate::versions::CATALOG_PATH))
        .collect();
    for resource in source.package().resources() {
        if resource.path == "manifest.json"
            || canonical_paths.contains(resource.path.as_str())
            || resource.path == manifest["application"]["profilePath"]
            || resource.path == source.history().domain().mapping().storage.database_path
            || resource.path.starts_with(&format!("{PREFIX}/"))
        {
            continue;
        }
        builder.add_reader(&resource.path, source.package().resource(&resource.path)?)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepositoryBinding {
    repository_sha256: String,
    generation_sha256: String,
    ordinal: Counter,
    root_sha256: String,
}
impl SyncRepository {
    fn observe_local_binding(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<Option<RepositoryBinding>> {
        use rusqlite::OptionalExtension;
        let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='_darkbox_sync_meta' AND type='table')", [], |row| row.get(0)).map_err(sql)?;
        if !exists {
            return Ok(None);
        }
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM _darkbox_sync_meta WHERE key='repository_generation'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        let binding: RepositoryBinding = decode(&bytes, 4096)?;
        if binding.repository_sha256 != self.hash
            || !hex(&binding.generation_sha256, 64)
            || !hex(&binding.root_sha256, 64)
        {
            return Err(invalid(
                "Local generation binding differs from this repository",
            ));
        }
        let mut high_water = self
            .high_water
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if high_water
            .as_ref()
            .is_none_or(|(ordinal, _)| *ordinal < binding.ordinal)
        {
            *high_water = Some((binding.ordinal, binding.generation_sha256.clone()));
        } else if high_water.as_ref().is_some_and(|(ordinal, id)| {
            *ordinal == binding.ordinal && id != &binding.generation_sha256
        }) {
            return Err(generation_conflict());
        }
        Ok(Some(binding))
    }
    /// Persist the observed generation alongside the local journal, without device membership.
    pub fn bind_session(
        &self,
        session: &SyncSession<'_>,
        connection: &rusqlite::Connection,
        generation: &Generation,
    ) -> Result<()> {
        session.revision(connection)?;
        self.observe_local_binding(connection)?;
        self.check_generation(&generation.id()?)?;
        if session.domain().root_hash() != generation.checkpoint.root_sha256 {
            return Err(invalid("Session belongs to another generation"));
        }
        let binding = RepositoryBinding {
            repository_sha256: self.hash.clone(),
            generation_sha256: generation.id()?,
            ordinal: generation.ordinal,
            root_sha256: generation.checkpoint.root_sha256.clone(),
        };
        super::journal::set_meta(connection, "repository_generation", &canonical(&binding)?)
    }
    pub fn open_session<'a>(
        &self,
        library: &'a mut crate::DirectoryLibrary,
        connection: &mut rusqlite::Connection,
        objects: ObjectStore,
        session_options: SessionOptions,
        adapter: &dyn SyncProjection,
    ) -> Result<SyncSession<'a>> {
        if library.path().starts_with(&self.root)
            || self.root.starts_with(library.path())
            || objects.path().starts_with(&self.root)
            || self.root.starts_with(objects.path())
        {
            return Err(invalid(
                "Working libraries and private objects must remain outside the cloud repository",
            ));
        }
        self.observe_local_binding(connection)?;
        let generation = self.current()?;
        let exchange = self.exchange(&generation)?;
        let session = SyncSession::open(
            library,
            connection,
            exchange.domain().clone(),
            objects,
            session_options,
            adapter,
        )?;
        self.bind_session(&session, connection, &generation)?;
        Ok(session)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Retirement {
    pub kind: String,
    pub protocol_version: String,
    pub repository_sha256: String,
    pub retired_before: Counter,
    pub checked_at: Counter,
    pub witnesses: Vec<Generation>,
}
impl Retirement {
    fn relative_path(&self) -> Result<String> {
        let bytes = canonical(self)?;
        Ok(format!(
            "retention/{:020}-{:016x}-{}.json",
            self.retired_before.0,
            bytes.len(),
            sha256(&bytes)
        ))
    }
    fn validate(&self, repository: &SyncRepository) -> Result<()> {
        super::wire::version(
            &self.kind,
            &self.protocol_version,
            "darkbox-sync-retirement",
        )?;
        if self.repository_sha256 != repository.hash
            || self.retired_before.0 == 0
            || self.witnesses.is_empty()
        {
            return Err(invalid("Retirement identity or witness set"));
        }
        let mut known = BTreeMap::new();
        for generation in &self.witnesses {
            generation.validate(repository)?;
            if known.insert(generation.id()?, generation).is_some() {
                return Err(invalid("Repeated retirement witness"));
            }
        }
        let head = self
            .witnesses
            .iter()
            .max_by_key(|generation| generation.ordinal)
            .unwrap();
        if self
            .witnesses
            .iter()
            .filter(|generation| generation.ordinal == head.ordinal)
            .count()
            != 1
            || head.ordinal.0.saturating_sub(self.retired_before.0)
                < repository.policy().keep_checkpoints.0 - 1
        {
            return Err(invalid("Retirement removes a retained checkpoint"));
        }
        let mut reachable = BTreeSet::new();
        let mut stack = vec![head];
        while let Some(descendant) = stack.pop() {
            if !reachable.insert(descendant.id()?) {
                continue;
            }
            for id in descendant.parent.iter().chain(&descendant.replaces) {
                if let Some(parent) = known.get(id).copied() {
                    if parent.ordinal >= descendant.ordinal
                        || parent.created_at > descendant.created_at
                    {
                        return Err(invalid("Retirement witness ancestry"));
                    }
                    stack.push(parent);
                }
            }
        }
        let boundary = self
            .witnesses
            .iter()
            .find(|generation| {
                generation.ordinal == self.retired_before
                    && reachable.contains(&generation.id().unwrap_or_default())
            })
            .ok_or_else(|| invalid("Retirement boundary is not covered"))?;
        if boundary
            .created_at
            .0
            .checked_add(repository.policy().retention_seconds.0)
            .is_none_or(|expiry| expiry > self.checked_at.0)
            || reachable.len() != self.witnesses.len()
        {
            return Err(invalid("Retirement grace period or witness closure"));
        }
        Ok(())
    }
}
impl SyncRepository {
    fn retirement_records(&self) -> Result<Vec<Retirement>> {
        let directory = super::exchange::safe_path(&self.root, "retention", false)?;
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        let mut bytes_read = 0u64;
        for (count, entry) in fs::read_dir(directory)
            .map_err(crate::io_failure)?
            .enumerate()
        {
            if count >= self.limits.max_scan_files {
                return Err(super::limit("Retention control entries"));
            }
            let entry = entry.map_err(crate::io_failure)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !canonical_generation_name(name) {
                continue;
            }
            let relative = format!("retention/{name}");
            let bytes = super::exchange::read_regular(&self.root, &relative, MAX_BASELINE_BYTES)?;
            bytes_read = bytes_read
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| super::limit("Retention records"))?;
            if bytes_read > self.limits.max_history_bytes {
                return Err(super::limit("Retention record budget"));
            }
            let record: Retirement = decode(&bytes, MAX_BASELINE_BYTES)
                .map_err(|error| super::pending_bytes(error.message))?;
            if record.relative_path()? != relative {
                return Err(super::pending_bytes(
                    "Retention control bytes are incomplete",
                ));
            }
            record.validate(self)?;
            result.push(record);
        }
        result.sort_by_key(|record| record.retired_before);
        Ok(result)
    }
    pub fn retired_before(&self) -> Result<Counter> {
        self.check_root()?;
        Ok(self
            .retirement_records()?
            .last()
            .map_or(Counter(0), |record| record.retired_before))
    }
    fn prune_verified(
        &self,
        now: u64,
        current: &Generation,
        generations: &[Generation],
        head: &str,
    ) -> Result<PruneReport> {
        let previous_records = self.retirement_records()?;
        if previous_records
            .iter()
            .any(|record| record.checked_at.0 > now)
        {
            return Err(crate::Error::new(
                crate::Status::OperationalError,
                "sync.retention_clock",
                "A retirement proof is ahead of the local maintenance clock; deletion is postponed",
            ));
        }

        let previous_floor = previous_records
            .last()
            .map_or(Counter(0), |record| record.retired_before);
        let known: BTreeMap<_, _> = generations
            .iter()
            .map(|generation| Ok((generation.id()?, generation)))
            .collect::<Result<_>>()?;
        let mut reachable = BTreeSet::new();
        let mut stack = vec![current];
        while let Some(descendant) = stack.pop() {
            if !reachable.insert(descendant.id()?) {
                continue;
            }
            for id in descendant.parent.iter().chain(&descendant.replaces) {
                if let Some(parent) = known.get(id).copied() {
                    if parent.ordinal >= descendant.ordinal
                        || parent.created_at > descendant.created_at
                    {
                        return Err(invalid("Invalid generation ancestry during retention"));
                    }
                    stack.push(parent);
                }
            }
        }
        if generations.iter().any(|generation| {
            generation.ordinal >= previous_floor
                && generation.id().is_ok_and(|id| !reachable.contains(&id))
        }) {
            return Err(generation_conflict());
        }
        let floor = generations
            .iter()
            .filter(|generation| {
                reachable.contains(&generation.id().unwrap_or_default())
                    && current.ordinal.0.saturating_sub(generation.ordinal.0)
                        >= self.policy().keep_checkpoints.0 - 1
                    && generation
                        .created_at
                        .0
                        .checked_add(self.policy().retention_seconds.0)
                        .is_some_and(|expiry| now >= expiry)
            })
            .map(|generation| generation.ordinal)
            .max()
            .unwrap_or(previous_floor)
            .max(previous_floor);
        let certificate = if floor > previous_floor {
            let mut witnesses: Vec<_> = generations
                .iter()
                .filter(|generation| {
                    generation.ordinal >= floor
                        && reachable.contains(&generation.id().unwrap_or_default())
                })
                .cloned()
                .collect();
            witnesses.sort_by_key(|generation| generation.ordinal);
            let record = Retirement {
                kind: "darkbox-sync-retirement".into(),
                protocol_version: VERSION.into(),
                repository_sha256: self.hash.clone(),
                retired_before: floor,
                checked_at: Counter(now),
                witnesses,
            };
            record.validate(self)?;
            self.check_generation(head)?;
            super::exchange::publish_bytes(
                &self.root,
                &record.relative_path()?,
                &canonical(&record)?,
            )?;
            Some(record)
        } else {
            previous_records.last().cloned()
        };
        let mut report = PruneReport::default();
        let domains = super::exchange::safe_path(&self.root, "domains", false)?;
        if domains.exists() {
            for (count, entry) in fs::read_dir(&domains)
                .map_err(crate::io_failure)?
                .enumerate()
            {
                if count >= self.limits.max_scan_files {
                    return Err(super::limit("Generation namespace count"));
                }
                let entry = entry.map_err(crate::io_failure)?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.len() != 20 || !name.bytes().all(|byte| byte.is_ascii_digit()) {
                    continue;
                }
                let ordinal: u64 = name
                    .parse()
                    .map_err(|_| invalid("Generation namespace ordinal"))?;
                if ordinal >= floor.0 {
                    continue;
                }
                self.check_generation(head)?;
                report.removed_files +=
                    remove_owned_tree(&self.root, &entry.path(), self.limits.max_scan_files)?;
            }
        }
        for generation in generations
            .iter()
            .filter(|generation| generation.ordinal < floor)
        {
            self.check_generation(head)?;
            let relative = generation.relative_path()?;
            let path = super::exchange::safe_path(&self.root, &relative, false)?;
            if path.exists() {
                if super::exchange::read_regular(&self.root, &relative, MAX_SEGMENT_BYTES)?
                    != canonical(generation)?
                {
                    return Err(invalid("Expired generation control changed"));
                }
                fs::remove_file(path).map_err(crate::io_failure)?;
                report.generations.push(generation.id()?);
            }
        }
        if let Some(certificate) = certificate {
            let retained = certificate.relative_path()?;
            for record in previous_records {
                let relative = record.relative_path()?;
                if relative != retained && record.retired_before <= floor {
                    self.check_generation(head)?;
                    fs::remove_file(super::exchange::safe_path(&self.root, &relative, false)?)
                        .map_err(crate::io_failure)?;
                }
            }
        }
        super::exchange::sync_dir(&self.root.join("generations"))?;
        if self.root.join("retention").exists() {
            super::exchange::sync_dir(&self.root.join("retention"))?;
        }
        Ok(report)
    }
}
