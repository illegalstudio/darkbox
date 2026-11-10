use super::*;
use crate::extensions::{EntryDigest, ExtensionContext, ExtensionVerifier};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

pub fn working_extension(domain: &Domain) -> Value {
    json!({"version":VERSION,"required":true,"data":{
    "mode":"working","syncId":domain.root().sync_id,"rootSha256":domain.root_hash(),
    "rootPath":format!("{PREFIX}/root.json"),"mappingPath":format!("{PREFIX}/mapping.json"),
    "journalDatabase":domain.mapping().storage.database_path,"journalSchemaVersion":VERSION}})
}
pub fn sealed_extension(domain: &Domain) -> Value {
    json!({"version":VERSION,"required":true,"data":{
    "mode":"sealed","syncId":domain.root().sync_id,"rootSha256":domain.root_hash(),
    "rootPath":format!("{PREFIX}/root.json"),"mappingPath":format!("{PREFIX}/mapping.json"),"checkpointPath":format!("{PREFIX}/checkpoint.json")}})
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    version: String,
    required: bool,
    data: DescriptorData,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
enum DescriptorData {
    #[serde(rename_all = "camelCase")]
    Working {
        sync_id: String,
        root_sha256: String,
        root_path: String,
        mapping_path: String,
        journal_database: String,
        journal_schema_version: String,
    },
    #[serde(rename_all = "camelCase")]
    Sealed {
        sync_id: String,
        root_sha256: String,
        root_path: String,
        mapping_path: String,
        checkpoint_path: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotObject {
    pub sha256: String,
    pub size: Counter,
    pub path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Checkpoint {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub frontier: Frontier,
    pub history: FileRef,
    pub state: FileRef,
    pub objects: Vec<SnapshotObject>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotDescriptor {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub replica_id: String,
    pub package: FileRef,
    pub frontier: Frontier,
    pub state_sha256: String,
}
impl SnapshotDescriptor {
    pub fn validate(&self, domain: &Domain) -> Result<()> {
        version(&self.kind, &self.protocol_version, "darkbox-sync-snapshot")?;
        domain.bind(&self.sync_id, &self.root_sha256)?;
        validate_frontier(&self.frontier)?;
        if !hex(&self.replica_id, 32)
            || !hex(&self.package.sha256, 64)
            || !hex(&self.state_sha256, 64)
            || self.package.path
                != format!(
                    "replicas/{}/snapshots/{}.darkbox",
                    self.replica_id, self.package.sha256
                )
        {
            return Err(invalid("Snapshot descriptor"));
        }
        Ok(())
    }
    pub fn relative_path(&self) -> Result<String> {
        let bytes = canonical(self)?;
        Ok(format!(
            "replicas/{}/snapshots/{:016x}-{}.json",
            self.replica_id,
            bytes.len(),
            sha256(&bytes)
        ))
    }
}
fn descriptor(manifest: &Value) -> Result<Descriptor> {
    let descriptor: Descriptor = serde_json::from_value(manifest["extensions"][NAMESPACE].clone())
        .map_err(|e| invalid(e.to_string()))?;
    if descriptor.version != VERSION {
        return Err(unsupported("Sync extension version"));
    }
    if !descriptor.required {
        return Err(invalid("Sync extension must be required"));
    }
    Ok(descriptor)
}
fn bound_resource(
    inventory: &BTreeMap<String, EntryDigest>,
    reference: &FileRef,
    maximum: u64,
) -> Result<()> {
    crate::paths::validate(&reference.path)?;
    if reference.size.0 > maximum {
        return Err(super::limit("Sync metadata/history resource"));
    }
    let actual = inventory
        .get(&reference.path)
        .ok_or_else(|| invalid("Checkpoint resource is absent").at(&reference.path))?;
    if actual.size != reference.size.0
        || actual.sha256 != reference.sha256
        || !hex(&reference.sha256, 64)
    {
        return Err(invalid("Checkpoint resource digest/length differs").at(&reference.path));
    }
    Ok(())
}
fn read_history(bytes: &[u8], domain: &Domain, limits: &SyncLimits) -> Result<History> {
    if bytes.len() as u64 > limits.max_history_bytes {
        return Err(super::limit("Checkpoint history bytes"));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(invalid("History JSONL must end with LF"));
    }
    let mut transactions = Vec::new();
    if !bytes.is_empty() {
        for line in bytes[..bytes.len() - 1].split(|b| *b == b'\n') {
            if transactions.len() >= limits.max_transactions {
                return Err(super::limit("Checkpoint transactions"));
            }
            transactions.push(decode::<SyncTransaction>(line, MAX_TRANSACTION_BYTES)?);
        }
    }
    if !transactions
        .windows(2)
        .all(|p| (&p[0].replica_id, p[0].sequence) < (&p[1].replica_id, p[1].sequence))
    {
        return Err(invalid("Checkpoint history is not unique and sorted"));
    }
    History::replay(domain.clone(), transactions, limits.clone())
}
fn verify_core(
    manifest: &Value,
    inventory: &BTreeMap<String, EntryDigest>,
    limits: &SyncLimits,
    mut read: impl FnMut(&str, u64) -> Result<Vec<u8>>,
) -> Result<(History, Checkpoint)> {
    if manifest["darkbox"]["version"] != "1.5.0"
        || manifest["extensions"]
            .get(crate::protection::NAMESPACE)
            .is_some()
    {
        return Err(unsupported(
            "Sync v1 requires unprotected common 1.5.0 storage",
        ));
    }
    let descriptor = descriptor(manifest)?;
    let (sync_id, root_hash, root_path, mapping_path, checkpoint_path) = match descriptor.data {
        DescriptorData::Sealed {
            sync_id,
            root_sha256,
            root_path,
            mapping_path,
            checkpoint_path,
        } => (
            sync_id,
            root_sha256,
            root_path,
            mapping_path,
            checkpoint_path,
        ),
        DescriptorData::Working {
            sync_id,
            root_sha256,
            root_path,
            mapping_path,
            journal_database,
            journal_schema_version,
        } => {
            // Working metadata is deliberately not a portable sealed checkpoint.
            if !hex(&sync_id, 32)
                || !hex(&root_sha256, 64)
                || root_path != format!("{PREFIX}/root.json")
                || mapping_path != format!("{PREFIX}/mapping.json")
                || journal_schema_version != VERSION
            {
                return Err(invalid("Working sync descriptor"));
            }
            crate::paths::validate(&journal_database)?;
            return Err(crate::Error::new(
                crate::Status::NotQuiescent,
                "sync.working",
                "Working sync libraries require the owning application or a complete sync checkpoint; generic readers never reconstruct their journal",
            ));
        }
    };
    if root_path != format!("{PREFIX}/root.json")
        || mapping_path != format!("{PREFIX}/mapping.json")
        || checkpoint_path != format!("{PREFIX}/checkpoint.json")
    {
        return Err(invalid("Sync namespace paths differ"));
    }
    let profile_path = manifest["application"]["profilePath"]
        .as_str()
        .ok_or_else(|| invalid("Application profile absent"))?;
    let domain = Domain::from_parts(
        &read(&root_path, MAX_SEGMENT_BYTES as u64)?,
        &read(&mapping_path, MAX_SEGMENT_BYTES as u64)?,
        &read(profile_path, MAX_SEGMENT_BYTES as u64)?,
    )?;
    domain.bind(&sync_id, &root_hash)?;
    domain.check_manifest(manifest)?;
    let checkpoint: Checkpoint = decode(
        &read(&checkpoint_path, limits.max_history_bytes)?,
        limits.max_history_bytes.min(usize::MAX as u64) as usize,
    )?;
    version(
        &checkpoint.kind,
        &checkpoint.protocol_version,
        "darkbox-sync-checkpoint",
    )?;
    domain.bind(&checkpoint.sync_id, &checkpoint.root_sha256)?;
    validate_frontier(&checkpoint.frontier)?;
    if checkpoint.history.path != format!("{PREFIX}/history.jsonl")
        || checkpoint.state.path != format!("{PREFIX}/state.json")
    {
        return Err(invalid("Checkpoint history/state paths"));
    }
    bound_resource(inventory, &checkpoint.history, limits.max_history_bytes)?;
    bound_resource(inventory, &checkpoint.state, limits.io.max_entry_bytes)?;
    let history = read_history(
        &read(&checkpoint.history.path, limits.max_history_bytes)?,
        &domain,
        limits,
    )?;
    if history.frontier() != checkpoint.frontier
        || canonical(&history.state())? != read(&checkpoint.state.path, limits.io.max_entry_bytes)?
    {
        return Err(invalid(
            "Checkpoint state/frontier differs from causal replay",
        ));
    }
    let expected: Vec<_> = history.blobs()?.into_iter().collect();
    if expected.len() != checkpoint.objects.len() {
        return Err(invalid("Checkpoint object closure differs"));
    }
    let mut paths = BTreeSet::new();
    for (blob, object) in expected.iter().zip(&checkpoint.objects) {
        if blob.sha256 != object.sha256 || blob.size != object.size || !paths.insert(&object.path) {
            return Err(invalid("Checkpoint object index order/identity differs"));
        }
        bound_resource(
            inventory,
            &FileRef {
                path: object.path.clone(),
                size: object.size,
                sha256: object.sha256.clone(),
            },
            limits.io.max_entry_bytes,
        )?;
    }
    Ok((history, checkpoint))
}

/// Common verification checks core replay and all referenced byte digests.
/// Application materialization is explicitly left to a registered profile adapter.
#[derive(Clone, Debug)]
pub struct SyncVerifier {
    pub max_history_bytes: u64,
    pub max_transactions: usize,
}
impl Default for SyncVerifier {
    fn default() -> Self {
        let limits = SyncLimits::default();
        Self {
            max_history_bytes: limits.max_history_bytes,
            max_transactions: limits.max_transactions,
        }
    }
}
impl ExtensionVerifier for SyncVerifier {
    fn namespace(&self) -> &str {
        NAMESPACE
    }
    fn supports(&self, version: &str) -> bool {
        version == VERSION
    }
    fn resources_to_stage(&self, manifest: &Value) -> Option<BTreeSet<String>> {
        let mut paths = BTreeSet::from([
            format!("{PREFIX}/root.json"),
            format!("{PREFIX}/mapping.json"),
            format!("{PREFIX}/checkpoint.json"),
            format!("{PREFIX}/history.jsonl"),
            format!("{PREFIX}/state.json"),
        ]);
        if let Some(profile) = manifest["application"]["profilePath"].as_str() {
            paths.insert(profile.into());
        }
        Some(paths)
    }
    fn verify(&self, context: &ExtensionContext<'_>, report: &mut crate::Report) -> Result<()> {
        let limits = SyncLimits {
            io: context.limits.clone(),
            max_history_bytes: self.max_history_bytes,
            max_transactions: self.max_transactions,
            ..Default::default()
        };
        verify_core(
            context.manifest,
            context.inventory,
            &limits,
            |path, maximum| {
                crate::container::check_deadline(context.deadline)?;
                if context.inventory.get(path).is_none_or(|d| d.size > maximum) {
                    return Err(super::limit("Sync staged resource absent or oversized").at(path));
                }
                context.read(path)
            },
        )?;
        report.checks.extend([
            "sync.causal_history",
            "sync.logical_state",
            "sync.object_closure",
        ]);
        report.note("sync.projection_unchecked","Sync core state verified; application database projection requires the pinned application adapter");
        Ok(())
    }
    fn prepare_streamed_package(
        &self,
        previous: Option<&Value>,
        manifest: &mut Value,
        _inventory: &BTreeMap<String, EntryDigest>,
    ) -> Result<()> {
        if previous.is_some() {
            return Err(unsupported(
                "Sync checkpoints are immutable; create a new checkpoint",
            ));
        }
        match descriptor(manifest)?.data {
            DescriptorData::Sealed { .. } => Ok(()),
            DescriptorData::Working { .. } => Err(unsupported(
                "Export working sync state through a complete sync checkpoint",
            )),
        }
    }
}

/// Produce a fresh closed projection and full causal checkpoint. Additional profile
/// resources/caches can be streamed through `add_path`/`add_reader` before finish.
pub struct SnapshotBuilder<'a> {
    writer: crate::PackageWriter<'a>,
}
impl<'a> SnapshotBuilder<'a> {
    pub fn new(
        destination: impl AsRef<Path>,
        mut manifest: Value,
        history: &History,
        objects: &ObjectStore,
        adapter: &dyn SyncProjection,
        limits: crate::Limits,
        options: &'a crate::VerificationOptions<'a>,
    ) -> Result<Self> {
        if options.trusted_digests.is_some() {
            return Err(unsupported(
                "Complete sync checkpoint creation requires full byte verification",
            ));
        }
        let destination = crate::transfer::output_path(destination.as_ref(), &[])?;
        let domain = history.domain();
        update_journal_declarations(&mut manifest, domain, false)?;
        domain.check_manifest(&manifest)?;
        projection_binding(domain, adapter)?;
        if !manifest["databases"].as_array().is_some_and(|a| {
            a.iter()
                .any(|d| d["path"] == domain.mapping().storage.database_path)
        }) {
            return Err(invalid("Authoritative snapshot database is not declared"));
        }
        let scratch = limits.tempdir("darkbox-sync-checkpoint-")?;
        let database = scratch.path().join("projection.sqlite");
        let mut connection = Connection::open(&database).map_err(sql)?;
        connection
            .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA foreign_keys=ON;")
            .map_err(sql)?;
        let transaction = connection.transaction().map_err(sql)?;
        adapter.initialize(&transaction, domain)?;
        adapter.validate_mapping(domain, &transaction)?;
        adapter.project(
            &transaction,
            domain,
            &History::new(domain.clone(), history.limits().clone()).state(),
            &history.state(),
        )?;
        adapter.verify(&transaction, domain, &history.state())?;
        transaction.commit().map_err(sql)?;
        connection.close().map_err(|(_, e)| sql(e))?;
        let mut history_bytes = Vec::new();
        for bytes in history.transaction_bytes() {
            history_bytes.extend_from_slice(bytes);
            history_bytes.push(b'\n');
        }
        if history_bytes.len() as u64 > history.limits().max_history_bytes {
            return Err(super::limit("Checkpoint JSONL byte budget"));
        }
        let state = canonical(&history.state())?;
        let mut indexed = Vec::new();
        for blob in history.blobs()? {
            if !objects.contains(&blob)? {
                return Err(invalid(
                    "Complete checkpoint requires every historical object",
                ));
            }
            indexed.push(SnapshotObject {
                sha256: blob.sha256.clone(),
                size: blob.size,
                path: format!("{PREFIX}/{}", blob.relative_path()?),
            });
        }
        let checkpoint = Checkpoint {
            kind: "darkbox-sync-checkpoint".into(),
            protocol_version: VERSION.into(),
            sync_id: domain.root().sync_id.clone(),
            root_sha256: domain.root_hash().into(),
            frontier: history.frontier(),
            history: FileRef {
                path: format!("{PREFIX}/history.jsonl"),
                size: Counter(history_bytes.len() as u64),
                sha256: sha256(&history_bytes),
            },
            state: FileRef {
                path: format!("{PREFIX}/state.json"),
                size: Counter(state.len() as u64),
                sha256: sha256(&state),
            },
            objects: indexed,
        };
        if !manifest["extensions"].is_object() {
            manifest["extensions"] = json!({});
        }
        manifest["extensions"][NAMESPACE] = sealed_extension(domain);
        let profile = manifest["application"]["profilePath"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut files = vec![
            (format!("{PREFIX}/root.json"), canonical(domain.root())?),
            (
                format!("{PREFIX}/mapping.json"),
                canonical(domain.mapping())?,
            ),
            (format!("{PREFIX}/checkpoint.json"), canonical(&checkpoint)?),
            (checkpoint.history.path.clone(), history_bytes),
            (checkpoint.state.path.clone(), state),
            (profile, domain.profile().to_vec()),
        ];
        let mut paths: Vec<_> = files.iter().map(|(p, _)| p.clone()).collect();
        paths.push(domain.mapping().storage.database_path.clone());
        paths.extend(checkpoint.objects.iter().map(|o| o.path.clone()));
        ensure_folders(&mut manifest, &paths)?;
        let mut writer =
            crate::PackageWriter::new_locked(destination, manifest, limits, options, None, None)?;
        writer.add_path(&domain.mapping().storage.database_path, &database)?;
        for (path, bytes) in files.drain(..) {
            writer.add_reader(&path, bytes.as_slice())?;
        }
        for object in &checkpoint.objects {
            objects.with_blob(
                &Blob {
                    sha256: object.sha256.clone(),
                    size: object.size,
                },
                |reader| writer.add_reader(&object.path, reader),
            )?;
        }
        Ok(Self { writer })
    }
    pub fn add_path(&mut self, path: &str, source: impl AsRef<Path>) -> Result<()> {
        self.writer.add_path(path, source).map(|_| ())
    }
    pub fn add_reader(&mut self, path: &str, reader: impl Read) -> Result<()> {
        self.writer.add_reader(path, reader).map(|_| ())
    }
    pub fn finish(self) -> Result<crate::Report> {
        self.writer.finish()
    }
}
fn ensure_folders(manifest: &mut Value, paths: &[String]) -> Result<()> {
    let folders = manifest["folders"]
        .as_array_mut()
        .ok_or_else(|| invalid("Missing folder inventory"))?;
    let mut names: BTreeSet<String> = folders
        .iter()
        .filter_map(|f| f["path"].as_str().map(str::to_owned))
        .collect();
    for path in paths {
        crate::paths::validate(path)?;
        let parts: Vec<_> = path.split('/').collect();
        for i in 1..parts.len() {
            let parent = parts[..i].join("/");
            if names.insert(parent.clone()) {
                folders.push(
                    json!({"path":parent,"description":"Synchronization checkpoint resources"}),
                );
            }
        }
    }
    folders.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(())
}

/// A complete independently replayed checkpoint, retaining its immutable package bytes.
#[derive(Clone)]
pub struct SyncSnapshot {
    package: crate::Package,
    history: History,
    checkpoint: Checkpoint,
    package_hash: String,
}
impl SyncSnapshot {
    pub fn open(
        path: impl AsRef<Path>,
        limits: SyncLimits,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<Self> {
        Self::from_package(
            crate::Package::open(path, limits.io.clone(), options)?,
            limits,
        )
    }
    pub fn from_package(package: crate::Package, limits: SyncLimits) -> Result<Self> {
        if !package.report().trusted_resources.is_empty() {
            return Err(unsupported(
                "Complete sync checkpoint opening requires full byte verification",
            ));
        }

        let inventory: BTreeMap<_, _> = package
            .resources()
            .map(|d| (d.path.clone(), d.clone()))
            .collect();
        let (history, checkpoint) =
            verify_core(package.manifest(), &inventory, &limits, |path, maximum| {
                if inventory.get(path).is_none_or(|d| d.size > maximum) {
                    return Err(super::limit("Checkpoint resource limit"));
                }
                let mut bytes = Vec::new();
                package
                    .resource(path)?
                    .take(maximum.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(crate::io_failure)?;
                if bytes.len() as u64 > maximum {
                    return Err(super::limit("Checkpoint resource bytes"));
                }
                Ok(bytes)
            })?;
        let hash = crate::writer::file_digest(
            package.archive_path(),
            limits.io.max_archive_bytes,
            crate::transfer::deadline(&limits.io)?,
        )?;
        let package_hash = hash.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Self {
            package,
            history,
            checkpoint,
            package_hash,
        })
    }
    pub fn fetch(
        exchange: &Exchange,
        descriptor: &SnapshotDescriptor,
        limits: SyncLimits,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<Self> {
        descriptor.validate(exchange.domain())?;
        let path = super::exchange::safe_path(exchange.path(), &descriptor.package.path, false)?;
        let snapshot = Self::open(&path, limits, options)?;
        snapshot.history.domain().bind(
            &exchange.domain().root().sync_id,
            exchange.domain().root_hash(),
        )?;
        if snapshot.package_hash != descriptor.package.sha256
            || fs::metadata(snapshot.package.archive_path())
                .map_err(crate::io_failure)?
                .len()
                != descriptor.package.size.0
            || snapshot.checkpoint.frontier != descriptor.frontier
            || snapshot.checkpoint.state.sha256 != descriptor.state_sha256
        {
            return Err(invalid("Snapshot does not match its transport descriptor"));
        }
        Ok(snapshot)
    }
    pub fn history(&self) -> &History {
        &self.history
    }
    pub fn package(&self) -> &crate::Package {
        &self.package
    }
    pub fn package_hash(&self) -> &str {
        &self.package_hash
    }
    pub fn verify_projection(&self, adapter: &dyn SyncProjection) -> Result<()> {
        projection_binding(self.history.domain(), adapter)?;
        let database = self
            .package
            .database(&self.history.domain().mapping().storage.database_path)?;
        database.with_connection(|db| {
            adapter.validate_mapping(self.history.domain(), db)?;
            adapter.verify(db, self.history.domain(), &self.history.state())
        })
    }
    pub fn import_objects(&self, store: &ObjectStore) -> Result<()> {
        for object in &self.checkpoint.objects {
            let mut reader = self.package.resource(&object.path)?;
            store.put_expected(
                &mut reader,
                &Blob {
                    sha256: object.sha256.clone(),
                    size: object.size,
                },
            )?;
        }
        Ok(())
    }
    pub fn publish(
        &self,
        exchange: &Exchange,
        replica: &ReplicaDescriptor,
    ) -> Result<SnapshotDescriptor> {
        self.history.domain().bind(
            &exchange.domain().root().sync_id,
            exchange.domain().root_hash(),
        )?;
        exchange.publish_replica(replica)?;
        let size = fs::metadata(self.package.archive_path())
            .map_err(crate::io_failure)?
            .len();
        let descriptor = SnapshotDescriptor {
            kind: "darkbox-sync-snapshot".into(),
            protocol_version: VERSION.into(),
            sync_id: self.history.domain().root().sync_id.clone(),
            root_sha256: self.history.domain().root_hash().into(),
            replica_id: replica.replica_id.clone(),
            package: FileRef {
                path: format!(
                    "replicas/{}/snapshots/{}.darkbox",
                    replica.replica_id, self.package_hash
                ),
                size: Counter(size),
                sha256: self.package_hash.clone(),
            },
            frontier: self.history.frontier(),
            state_sha256: self.checkpoint.state.sha256.clone(),
        };
        descriptor.validate(exchange.domain())?;
        publish_package(
            exchange.path(),
            &descriptor.package,
            self.package.archive_path(),
            &self.history.limits().io,
        )?;
        super::exchange::publish_bytes(
            exchange.path(),
            &descriptor.relative_path()?,
            &canonical(&descriptor)?,
        )?;
        Ok(descriptor)
    }
    /// Rebuild privately from history and atomically adopt an absent local directory.
    /// Local installation configuration and session identity are created separately.
    pub fn bootstrap(
        &self,
        destination: impl AsRef<Path>,
        objects: &ObjectStore,
        adapter: &dyn SyncProjection,
    ) -> Result<crate::DirectoryLibrary> {
        require_working_writer(self.package.manifest())?;
        self.verify_projection(adapter)?;
        self.import_objects(objects)?;
        let domain = self.history.domain();
        let limits = &self.history.limits().io;
        let destination = crate::transfer::output_path(destination.as_ref(), &[])?;
        let scratch = tempfile::Builder::new()
            .prefix(".darkbox-sync-bootstrap-")
            .tempdir_in(destination.parent().unwrap())
            .map_err(crate::io_failure)?;
        let mut manifest = self.package.manifest().clone();
        manifest["extensions"][NAMESPACE] = working_extension(domain);
        update_journal_declarations(&mut manifest, domain, true)?;
        manifest
            .as_object_mut()
            .unwrap()
            .remove("resourceInventory");
        let candidate = scratch.path().join("library");
        let library = crate::DirectoryLibrary::initialize(
            &candidate,
            manifest.clone(),
            std::str::from_utf8(domain.profile()).unwrap(),
            limits.clone(),
        )?;
        let canonical_paths: BTreeSet<_> = crate::creation::specification(&manifest)?
            .files
            .iter()
            .map(|f| f.path)
            .chain(std::iter::once(crate::versions::CATALOG_PATH))
            .collect();
        let profile = manifest["application"]["profilePath"].as_str().unwrap();
        for resource in self.package.resources() {
            if resource.path == "manifest.json"
                || resource.path == profile
                || canonical_paths.contains(resource.path.as_str())
                || resource.path.starts_with(&format!("{PREFIX}/"))
                || resource.path == domain.mapping().storage.database_path
            {
                continue;
            }
            let path = super::exchange::safe_path(library.path(), &resource.path, true)?;
            self.package.export_resource(&resource.path, path)?;
        }
        super::exchange::publish_bytes(
            library.path(),
            &format!("{PREFIX}/root.json"),
            &canonical(domain.root())?,
        )?;
        super::exchange::publish_bytes(
            library.path(),
            &format!("{PREFIX}/mapping.json"),
            &canonical(domain.mapping())?,
        )?;
        let database = super::exchange::safe_path(
            library.path(),
            &domain.mapping().storage.database_path,
            true,
        )?;
        let mut connection = Connection::open(&database).map_err(sql)?;
        connection
            .execute_batch("PRAGMA journal_mode=DELETE;PRAGMA foreign_keys=ON;")
            .map_err(sql)?;
        let tx = connection.transaction().map_err(sql)?;
        adapter.initialize(&tx, domain)?;
        adapter.validate_mapping(domain, &tx)?;
        adapter.project(
            &tx,
            domain,
            &History::new(domain.clone(), self.history.limits().clone()).state(),
            &self.history.state(),
        )?;
        adapter.verify(&tx, domain, &self.history.state())?;
        initialize_journal(&tx, domain)?;
        for transaction in self.history.transactions() {
            tx.execute(
                "INSERT INTO _darkbox_sync_history(replica,sequence,bytes) VALUES(?1,?2,?3)",
                params![
                    transaction.replica_id,
                    transaction.sequence.0.to_string(),
                    transaction.bytes()?
                ],
            )
            .map_err(sql)?;
        }
        set_meta(&tx, "state", &canonical(&self.history.state())?)?;
        tx.commit().map_err(sql)?;
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(sql)?;
        if integrity != "ok"
            || connection
                .prepare("PRAGMA foreign_key_check")
                .map_err(sql)?
                .query([])
                .map_err(sql)?
                .next()
                .map_err(sql)?
                .is_some()
        {
            return Err(invalid("Rebuilt bootstrap database integrity failed"));
        }
        connection.close().map_err(|(_, e)| sql(e))?;
        File::open(database)
            .and_then(|f| f.sync_all())
            .map_err(crate::io_failure)?;
        drop(library);
        crate::DirectoryLibrary::adopt_prepared(&candidate, &destination)
    }
}
fn publish_package(
    root: &Path,
    reference: &FileRef,
    source: &Path,
    limits: &crate::Limits,
) -> Result<()> {
    let target = super::exchange::safe_path(root, &reference.path, true)?;
    let mut temp =
        tempfile::NamedTempFile::new_in(target.parent().unwrap()).map_err(crate::io_failure)?;
    let mut reader = File::open(source).map_err(crate::io_failure)?;
    let end = crate::transfer::deadline(limits)?;
    let mut hash = sha2::Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 65536];
    use sha2::Digest;
    loop {
        crate::container::check_deadline(end)?;
        let n = reader.read(&mut buffer).map_err(crate::io_failure)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > reference.size.0 || total > limits.max_archive_bytes {
            return Err(super::limit("Snapshot package bytes"));
        }
        hash.update(&buffer[..n]);
        temp.write_all(&buffer[..n]).map_err(crate::io_failure)?;
    }
    if total != reference.size.0 || format!("{:x}", hash.finalize()) != reference.sha256 {
        return Err(invalid("Snapshot package changed"));
    }
    temp.as_file().sync_all().map_err(crate::io_failure)?;
    match temp.persist_noclobber(&target) {
        Ok(_) => super::exchange::sync_dir(target.parent().unwrap()),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let actual = crate::writer::file_digest(&target, limits.max_archive_bytes, end)?;
            let hash: String = actual.iter().map(|b| format!("{b:02x}")).collect();
            if fs::symlink_metadata(&target)
                .map_err(crate::io_failure)?
                .is_file()
                && hash == reference.sha256
            {
                Ok(())
            } else {
                Err(super::pending_bytes(
                    "Existing checkpoint publication is incomplete or mismatched; retry without replacing it",
                ))
            }
        }
        Err(e) => Err(crate::io_failure(e.error)),
    }
}

/// Select by verified causal coverage; physical timestamps have no meaning.
pub fn select_snapshot(snapshots: &[SyncSnapshot]) -> Result<Option<&SyncSnapshot>> {
    if snapshots.is_empty() {
        return Ok(None);
    }
    let first = &snapshots[0];
    let mut all = Vec::new();
    for snapshot in snapshots {
        first.history.domain().bind(
            &snapshot.history.domain().root().sync_id,
            snapshot.history.domain().root_hash(),
        )?;
        all.extend(snapshot.history.transactions().cloned());
    }
    History::replay(
        first.history.domain().clone(),
        all,
        first.history.limits().clone(),
    )?;
    let dominates = |a: &Frontier, b: &Frontier| {
        b.iter().all(|tip| {
            a.iter()
                .any(|other| other.replica_id == tip.replica_id && other.sequence >= tip.sequence)
        })
    };
    let maxima: Vec<_> = snapshots
        .iter()
        .filter(|candidate| {
            !snapshots.iter().any(|other| {
                dominates(&other.checkpoint.frontier, &candidate.checkpoint.frontier)
                    && !dominates(&candidate.checkpoint.frontier, &other.checkpoint.frontier)
            })
        })
        .collect();
    Ok(maxima.into_iter().max_by(|a, b| {
        let weight = |s: &SyncSnapshot| {
            s.checkpoint
                .frontier
                .iter()
                .map(|t| t.sequence.0 as u128)
                .sum::<u128>()
        };
        weight(a)
            .cmp(&weight(b))
            .then_with(|| b.package_hash.cmp(&a.package_hash))
    }))
}

pub(crate) fn update_journal_declarations(
    manifest: &mut Value,
    domain: &Domain,
    working: bool,
) -> Result<()> {
    let database = manifest["databases"]
        .as_array_mut()
        .and_then(|rows| {
            rows.iter_mut()
                .find(|d| d["path"] == domain.mapping().storage.database_path)
        })
        .ok_or_else(|| invalid("Authoritative database declaration missing"))?;
    let tables = database["tables"]
        .as_array_mut()
        .ok_or_else(|| invalid("Missing table inventory"))?;
    const NAMES: [&str; 5] = [
        "_darkbox_sync_meta",
        "_darkbox_sync_history",
        "_darkbox_sync_pending",
        "_darkbox_sync_outbox",
        "_darkbox_sync_forks",
    ];
    tables.retain(|row| !NAMES.iter().any(|name| row["name"] == *name));
    if working {
        for name in NAMES {
            tables
                .push(json!({"name":name,"description":"Darkbox causal synchronization journal"}));
        }
    }
    tables.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(())
}
