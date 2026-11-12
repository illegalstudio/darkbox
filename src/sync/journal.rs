use super::*;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::Mutex,
};

/// Trusted, version-pinned application code. Never load this code from a package.
/// `project` must preserve local-only values and persist a deterministic conflict view.
pub trait SyncProjection {
    fn id(&self) -> &str;
    fn version(&self) -> &str;
    fn validate_mapping(&self, domain: &Domain, connection: &Connection) -> Result<()>;
    fn project(
        &self,
        transaction: &Transaction<'_>,
        domain: &Domain,
        previous: &LogicalState,
        next: &LogicalState,
    ) -> Result<()>;
    fn verify(&self, connection: &Connection, domain: &Domain, state: &LogicalState) -> Result<()>;
    /// Preserve installation-local columns for stable record IDs during rebase/recovery.
    fn copy_local(
        &self,
        _source: &Connection,
        _destination: &Transaction<'_>,
        domain: &Domain,
    ) -> Result<()> {
        if domain
            .mapping()
            .collections
            .iter()
            .any(|collection| !collection.local_columns.is_empty())
        {
            return Err(unsupported(
                "The application adapter must implement local-column preservation for rebase and recovery",
            ));
        }
        Ok(())
    }
    /// Initialize a fresh private database for bootstrap/snapshot projection.
    fn initialize(&self, _transaction: &Transaction<'_>, _domain: &Domain) -> Result<()> {
        Err(unsupported(
            "Projection adapter cannot initialize a fresh database",
        ))
    }
}
pub(crate) fn projection_binding(domain: &Domain, adapter: &dyn SyncProjection) -> Result<()> {
    if adapter.id() != domain.mapping().projection.id
        || adapter.version() != domain.mapping().projection.version
    {
        return Err(unsupported(
            "Sync projection adapter identity/version differs",
        ));
    }
    Ok(())
}
pub(crate) const JOURNAL_SCHEMA:&str="
CREATE TABLE IF NOT EXISTS _darkbox_sync_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS _darkbox_sync_history(replica TEXT NOT NULL, sequence TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(replica,sequence)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS _darkbox_sync_pending(replica TEXT NOT NULL, sequence TEXT NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(replica,sequence)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS _darkbox_sync_outbox(replica TEXT NOT NULL, sequence TEXT NOT NULL, bytes BLOB NOT NULL, published INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(replica,sequence)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS _darkbox_sync_forks(hash TEXT PRIMARY KEY, bytes BLOB NOT NULL) WITHOUT ROWID;
";
fn meta(connection: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    connection
        .query_row(
            "SELECT value FROM _darkbox_sync_meta WHERE key=?1",
            [key],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)
}
pub(crate) fn set_meta(connection: &Connection, key: &str, value: &[u8]) -> Result<()> {
    connection.execute("INSERT INTO _darkbox_sync_meta(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value]).map_err(sql)?;
    Ok(())
}
pub(crate) fn initialize_journal(connection: &Connection, domain: &Domain) -> Result<()> {
    connection.execute_batch(JOURNAL_SCHEMA).map_err(sql)?;
    let root = canonical(domain.root())?;
    match meta(connection, "root")? {
        Some(existing) if existing != root => {
            return Err(fork("Local journal is pinned to another domain"));
        }
        Some(_) => {}
        None => {
            let count:i64=connection.query_row("SELECT (SELECT count(*) FROM _darkbox_sync_history)+(SELECT count(*) FROM _darkbox_sync_pending)+(SELECT count(*) FROM _darkbox_sync_outbox)",[],|r|r.get(0)).map_err(sql)?;
            if count != 0 {
                return Err(invalid("Unbound nonempty sync journal"));
            }
            set_meta(connection, "root", &root)?;
        }
    }
    if meta(connection, "cache_revision")?.is_none() {
        set_meta(connection, "cache_revision", &canonical(&Counter(0))?)?;
    }
    Ok(())
}
fn cache_revision(connection: &Connection) -> Result<Counter> {
    decode(
        &meta(connection, "cache_revision")?.unwrap_or_else(|| b"\"0\"".to_vec()),
        64,
    )
}
fn bump_revision(connection: &Connection) -> Result<Counter> {
    let next = Counter(
        cache_revision(connection)?
            .0
            .checked_add(1)
            .ok_or_else(|| unsupported("Local cache revision exhausted"))?,
    );
    set_meta(connection, "cache_revision", &canonical(&next)?)?;
    Ok(next)
}
pub(crate) fn load_history(
    connection: &Connection,
    domain: &Domain,
    limits: &SyncLimits,
) -> Result<History> {
    if meta(connection, "root")?.as_deref() != Some(canonical(domain.root())?.as_slice()) {
        return Err(fork("Local journal root differs"));
    }
    if meta(connection, "forked")?.is_some() {
        return Err(fork(
            "Domain has retained fork evidence; recover into a new domain",
        ));
    }
    let mut statement = connection
        .prepare("SELECT bytes FROM _darkbox_sync_history")
        .map_err(sql)?;
    let mut rows = statement.query([]).map_err(sql)?;
    let mut transactions = Vec::new();
    let mut size = 0u64;
    while let Some(row) = rows.next().map_err(sql)? {
        let bytes: Vec<u8> = row.get(0).map_err(sql)?;
        size = size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| super::limit("Local history bytes"))?;
        if transactions.len() >= limits.max_transactions || size > limits.max_history_bytes {
            return Err(super::limit("Local history budget"));
        }
        transactions.push(decode(&bytes, MAX_TRANSACTION_BYTES)?);
    }
    History::replay(domain.clone(), transactions, limits.clone())
}
fn check_budget(connection: &Connection, limits: &SyncLimits) -> Result<()> {
    let (count,size):(i64,i64)=connection.query_row("SELECT (SELECT count(*) FROM _darkbox_sync_history)+(SELECT count(*) FROM _darkbox_sync_pending), coalesce((SELECT sum(length(bytes)) FROM _darkbox_sync_history),0)+coalesce((SELECT sum(length(bytes)) FROM _darkbox_sync_pending),0)",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(sql)?;
    let size = size
        .checked_add(count)
        .ok_or_else(|| super::limit("History framing budget"))?;
    if count < 0
        || size < 0
        || count as usize > limits.max_transactions
        || size as u64 > limits.max_history_bytes
    {
        return Err(super::limit("Persistent sync history/pending budget"));
    }
    let (meta_count,meta_bytes,outbox_bytes):(i64,i64,i64)=connection.query_row("SELECT (SELECT count(*) FROM _darkbox_sync_meta),coalesce((SELECT sum(length(value)) FROM _darkbox_sync_meta),0),coalesce((SELECT sum(length(bytes)) FROM _darkbox_sync_outbox),0)",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).map_err(sql)?;
    if meta_count < 0
        || meta_bytes < 0
        || outbox_bytes < 0
        || meta_count as usize > limits.max_scan_files
        || meta_bytes as u64 > limits.io.max_entry_bytes
        || outbox_bytes as u64 > limits.max_history_bytes
    {
        return Err(super::limit("Sync metadata/outbox budget"));
    }
    Ok(())
}
fn existing(connection: &Connection, replica: &str, sequence: Counter) -> Result<Vec<Vec<u8>>> {
    let mut statement=connection.prepare("SELECT bytes FROM _darkbox_sync_history WHERE replica=?1 AND sequence=?2 UNION ALL SELECT bytes FROM _darkbox_sync_pending WHERE replica=?1 AND sequence=?2").map_err(sql)?;
    statement
        .query_map(params![replica, sequence.0.to_string()], |r| r.get(0))
        .map_err(sql)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(sql)
}
fn mark_fork(connection: &mut Connection, evidence: &[Vec<u8>]) -> Result<()> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sql)?;
    for bytes in evidence {
        tx.execute(
            "INSERT OR IGNORE INTO _darkbox_sync_forks(hash,bytes) VALUES(?1,?2)",
            params![sha256(bytes), bytes],
        )
        .map_err(sql)?;
    }
    set_meta(&tx, "forked", b"1")?;
    tx.commit().map_err(sql)
}

/// Attach metadata under an application write barrier. The library must already
/// use common 1.5.0 and the exact unprotected application profile for this domain.
/// Existing application data is imported through the registered profile, never guessed.
pub fn attach_working(
    library: &crate::DirectoryLibrary,
    domain: &Domain,
    limits: &crate::Limits,
) -> Result<()> {
    let root = library.path();
    let original =
        super::exchange::read_regular(root, "manifest.json", limits.max_metadata_bytes as usize)?;
    let mut manifest = crate::json::parse(&original)?;
    crate::creation::specification(&manifest)?;
    domain.check_manifest(&manifest)?;
    require_working_writer(&manifest)?;
    if manifest["extensions"]
        .get(NAMESPACE)
        .is_some_and(|existing| existing != &working_extension(domain))
    {
        return Err(invalid("Existing sync descriptor differs"));
    }
    let profile = manifest["application"]["profilePath"]
        .as_str()
        .ok_or_else(|| invalid("Missing application profile path"))?;
    if super::exchange::read_regular(root, profile, MAX_SEGMENT_BYTES)? != domain.profile() {
        return Err(invalid("Working application profile bytes differ"));
    }
    super::exchange::publish_bytes(
        root,
        &format!("{PREFIX}/root.json"),
        &canonical(domain.root())?,
    )?;
    super::exchange::publish_bytes(
        root,
        &format!("{PREFIX}/mapping.json"),
        &canonical(domain.mapping())?,
    )?;
    if let Some(base) = domain.baseline() {
        super::exchange::publish_bytes(root, &format!("{PREFIX}/base.json"), &canonical(base)?)?;
    }
    if !manifest["extensions"].is_object() {
        manifest["extensions"] = serde_json::json!({});
    }
    manifest["extensions"][NAMESPACE] = working_extension(domain);
    super::snapshot::update_journal_declarations(&mut manifest, domain, true)?;
    let folders = manifest["folders"]
        .as_array_mut()
        .ok_or_else(|| invalid("Missing folders"))?;
    for path in ["extensions", PREFIX] {
        if !folders.iter().any(|f| f["path"] == path) {
            folders.push(
                serde_json::json!({"path":path,"description":"Darkbox synchronization metadata"}),
            );
        }
    }
    folders.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    // Working manifests are not sealed snapshots. The next seal/capture rebuilds inventory.
    manifest
        .as_object_mut()
        .unwrap()
        .remove("resourceInventory");
    let bytes = crate::creation::serialized_manifest(&manifest, limits.max_metadata_bytes)?;
    if super::exchange::read_regular(root, "manifest.json", limits.max_metadata_bytes as usize)?
        != original
    {
        return Err(invalid("Manifest changed during sync attachment"));
    }
    let mut temp = tempfile::NamedTempFile::new_in(root).map_err(crate::io_failure)?;
    use std::io::Write;
    temp.write_all(&bytes)
        .and_then(|()| temp.as_file().sync_all())
        .map_err(crate::io_failure)?;
    temp.persist(root.join("manifest.json"))
        .map_err(|e| crate::io_failure(e.error))?;
    super::exchange::sync_dir(root)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryJournal {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub source_revision: Counter,
    pub frontier: Frontier,
    pub outgoing: Vec<SyncTransaction>,
    pub incoming: Vec<SyncTransaction>,
    pub missing_objects: Vec<Blob>,
}

/// Metadata-only pending status. Local publication does not certify cloud upload.
#[derive(Clone, Debug)]
pub struct PendingStatus {
    pub replica_id: String,
    pub sequence: Counter,
    pub missing_dependencies: Frontier,
    pub missing_objects: Vec<Blob>,
    pub ready_to_validate: bool,
}

/// One writable incarnation, borrowing the local working-library guard exclusively.
/// It never reuses an old incarnation after reopening or restoring a database.
#[derive(Clone, Debug)]
pub struct SessionOptions {
    pub device_id: String,
    pub label: String,
    pub limits: SyncLimits,
}
impl SessionOptions {
    pub fn new(device_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
            label: label.into(),
            limits: SyncLimits::default(),
        }
    }
}
/// Allocated under the same SQLite write transaction as the edit.
pub struct BatchContext<'a> {
    pub history: &'a History,
    pub replica_id: &'a str,
    pub sequence: Counter,
}
impl BatchContext<'_> {
    pub fn dot(&self, index: usize) -> Result<Dot> {
        if index >= MAX_OPERATIONS {
            return Err(invalid("Operation index exceeds protocol bound"));
        }
        Ok(Dot {
            replica_id: self.replica_id.into(),
            sequence: self.sequence,
            index: Counter(index as u64),
        })
    }
}
enum SessionLibrary<'a> {
    Borrowed(&'a mut crate::DirectoryLibrary),
    Owned(crate::DirectoryLibrary),
}
impl SessionLibrary<'_> {
    fn path(&self) -> &Path {
        match self {
            Self::Borrowed(library) => library.path(),
            Self::Owned(library) => library.path(),
        }
    }
}

/// A working session borrowing an exclusive library guard.
pub struct SyncSession<'a> {
    cache: Mutex<Option<(Counter, History)>>,
    library: SessionLibrary<'a>,
    domain: Domain,
    replica: ReplicaDescriptor,
    objects: ObjectStore,
    limits: SyncLimits,
}

/// A working session that retains its library guard without self references.
pub struct OwnedSyncSession(SyncSession<'static>);

/// Opening failed while retaining the caller's exclusive library guard.
pub struct OwnedSessionError {
    pub error: crate::Error,
    pub library: Box<crate::DirectoryLibrary>,
}
impl std::fmt::Debug for OwnedSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedSessionError")
            .field("error", &self.error)
            .field("library", &self.library.path())
            .finish()
    }
}
impl std::fmt::Display for OwnedSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for OwnedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl OwnedSessionError {
    pub fn into_parts(self) -> (crate::Error, crate::DirectoryLibrary) {
        (self.error, *self.library)
    }
}

impl std::ops::Deref for OwnedSyncSession {
    type Target = SyncSession<'static>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl OwnedSyncSession {
    pub fn open(
        library: crate::DirectoryLibrary,
        connection: &mut Connection,
        domain: Domain,
        objects: ObjectStore,
        options: SessionOptions,
        adapter: &dyn SyncProjection,
    ) -> std::result::Result<Self, OwnedSessionError> {
        Self::open_with(library, |library| {
            SyncSession::open(library, connection, domain, objects, options, adapter)
        })
    }

    pub(crate) fn open_with(
        mut library: crate::DirectoryLibrary,
        open: impl for<'a> FnOnce(&'a mut crate::DirectoryLibrary) -> Result<SyncSession<'a>>,
    ) -> std::result::Result<Self, OwnedSessionError> {
        let result = open(&mut library).map(|session| {
            let SyncSession {
                cache,
                domain,
                replica,
                objects,
                limits,
                library: _,
            } = session;
            (cache, domain, replica, objects, limits)
        });
        match result {
            Ok((cache, domain, replica, objects, limits)) => Ok(Self(SyncSession {
                cache,
                library: SessionLibrary::Owned(library),
                domain,
                replica,
                objects,
                limits,
            })),
            Err(error) => Err(OwnedSessionError {
                error,
                library: Box::new(library),
            }),
        }
    }

    /// Return the still-guarded library. Close the application's SQLite handles
    /// before sealing it; this method does not checkpoint or close connections.
    pub fn close(self) -> crate::DirectoryLibrary {
        match self.0.library {
            SessionLibrary::Owned(library) => library,
            SessionLibrary::Borrowed(_) => unreachable!("Owned session invariant"),
        }
    }
}

impl<'a> SyncSession<'a> {
    pub fn open(
        library: &'a mut crate::DirectoryLibrary,
        connection: &mut Connection,
        domain: Domain,
        objects: ObjectStore,
        options: SessionOptions,
        adapter: &dyn SyncProjection,
    ) -> Result<Self> {
        let SessionOptions {
            device_id,
            label,
            limits,
        } = options;
        let manifest = crate::json::parse(&super::exchange::read_regular(
            library.path(),
            "manifest.json",
            limits.io.max_metadata_bytes as usize,
        )?)?;
        crate::creation::specification(&manifest)?;
        domain.check_manifest(&manifest)?;
        require_working_writer(&manifest)?;
        if manifest["extensions"][NAMESPACE] != working_extension(&domain) {
            return Err(invalid("Working sync metadata is absent or inconsistent"));
        }
        if super::exchange::read_regular(
            library.path(),
            &format!("{PREFIX}/root.json"),
            MAX_SEGMENT_BYTES,
        )? != canonical(domain.root())?
            || super::exchange::read_regular(
                library.path(),
                &format!("{PREFIX}/mapping.json"),
                MAX_SEGMENT_BYTES,
            )? != canonical(domain.mapping())?
        {
            return Err(invalid("Working domain resources differ"));
        }
        if let Some(base) = domain.baseline()
            && super::exchange::read_regular(
                library.path(),
                &format!("{PREFIX}/base.json"),
                MAX_BASELINE_BYTES,
            )? != canonical(base)?
        {
            return Err(invalid("Working compact baseline differs"));
        }
        let profile_path = manifest["application"]["profilePath"]
            .as_str()
            .ok_or_else(|| invalid("Application profile path is absent"))?;
        if super::exchange::read_regular(library.path(), profile_path, MAX_SEGMENT_BYTES)?
            != domain.profile()
        {
            return Err(invalid(
                "Working profile bytes differ from the pinned domain",
            ));
        }
        check_connection(library.path(), &domain, connection)?;
        projection_binding(&domain, adapter)?;
        adapter.validate_mapping(&domain, connection)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        initialize_journal(&tx, &domain)?;
        let history = load_history(&tx, &domain, &limits)?;
        let revision = cache_revision(&tx)?;
        let replica_id: String = tx
            .query_row("SELECT lower(hex(randomblob(16)))", [], |r| r.get(0))
            .map_err(sql)?;
        let replica = ReplicaDescriptor {
            kind: "darkbox-sync-replica".into(),
            protocol_version: VERSION.into(),
            sync_id: domain.root().sync_id.clone(),
            root_sha256: domain.root_hash().into(),
            replica_id,
            device_id,
            label,
        };
        replica.validate(&domain)?;
        let key = format!("replica:{}", replica.replica_id);
        if meta(&tx, &key)?.is_some() {
            return Err(fork("Random incarnation identity collision"));
        }
        set_meta(&tx, &key, &canonical(&replica)?)?;
        check_budget(&tx, &limits)?;
        tx.commit().map_err(sql)?;
        Ok(Self {
            cache: Mutex::new(Some((revision, history))),
            library: SessionLibrary::Borrowed(library),
            domain,
            replica,
            objects,
            limits,
        })
    }
    pub fn working_path(&self) -> &Path {
        self.library.path()
    }
    pub fn replica(&self) -> &ReplicaDescriptor {
        &self.replica
    }
    pub fn objects(&self) -> &ObjectStore {
        &self.objects
    }
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
    fn check(&self, connection: &Connection) -> Result<()> {
        check_connection(self.library.path(), &self.domain, connection)
    }
    fn take_history(&self, connection: &Connection) -> Result<(Counter, History)> {
        if meta(connection, "root")?.as_deref() != Some(canonical(self.domain.root())?.as_slice()) {
            return Err(fork("Local journal root differs"));
        }
        if meta(connection, "forked")?.is_some() {
            return Err(fork("Domain has retained fork evidence"));
        }
        let revision = cache_revision(connection)?;
        if let Some((old, history)) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).take()
            && old == revision
        {
            return Ok((revision, history));
        }
        Ok((
            revision,
            load_history(connection, &self.domain, &self.limits)?,
        ))
    }
    pub fn history(&self, connection: &Connection) -> Result<History> {
        self.check(connection)?;
        let (revision, history) = self.take_history(connection)?;
        let result = history.clone();
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace((revision, history));
        Ok(result)
    }
    /// The projection callback and exact outgoing bytes commit together in this main DB.
    pub fn edit(
        &self,
        connection: &mut Connection,
        operations: Vec<Operation>,
        adapter: &dyn SyncProjection,
    ) -> Result<SyncTransaction> {
        self.edit_with(connection, adapter, |_| Ok(operations))
    }
    pub fn edit_with(
        &self,
        connection: &mut Connection,
        adapter: &dyn SyncProjection,
        build: impl FnOnce(&BatchContext<'_>) -> Result<Vec<Operation>>,
    ) -> Result<SyncTransaction> {
        self.check(connection)?;
        projection_binding(&self.domain, adapter)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sql)?;
        let (base_revision, mut history) = self.take_history(&tx)?;
        let previous = history.state();
        let sequence = Counter(
            history
                .frontier()
                .iter()
                .find(|t| t.replica_id == self.replica.replica_id)
                .map_or(Some(1), |t| t.sequence.0.checked_add(1))
                .ok_or_else(|| unsupported("Replica sequence exhausted"))?,
        );
        let operations = build(&BatchContext {
            history: &history,
            replica_id: &self.replica.replica_id,
            sequence,
        })?;
        let outgoing = history.prepare(&self.replica.replica_id, operations)?;
        tx.rollback().map_err(sql)?;
        let mut witnesses = Vec::new();
        for blob in outgoing.blobs()? {
            let witness = self
                .objects
                .witness(&blob)?
                .ok_or_else(|| invalid("Cannot commit an unavailable local resource"))?;
            witnesses.push((blob, witness));
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if meta(&tx, "forked")?.is_some() {
            return Err(fork("Domain has retained fork evidence"));
        }
        if cache_revision(&tx)? != base_revision {
            return Err(crate::Error::new(
                crate::Status::OperationalError,
                "sync.revision_changed",
                "Sync state changed while preparing the edit; rebuild the operation group",
            ));
        }
        adapter.verify(&tx, &self.domain, &previous)?;
        for (blob, witness) in &witnesses {
            if !self.objects.unchanged(blob, witness)? {
                return Err(invalid("Resource changed before commit"));
            }
        }
        history.accept(outgoing.clone())?;
        adapter.project(&tx, &self.domain, &previous, &history.state())?;
        if tx.is_autocommit() {
            return Err(invalid("Projection ended the owning transaction"));
        }
        adapter.verify(&tx, &self.domain, &history.state())?;
        let bytes = outgoing.bytes()?;
        tx.execute(
            "INSERT INTO _darkbox_sync_history(replica,sequence,bytes) VALUES(?1,?2,?3)",
            params![outgoing.replica_id, outgoing.sequence.0.to_string(), bytes],
        )
        .map_err(sql)?;
        tx.execute(
            "INSERT INTO _darkbox_sync_outbox(replica,sequence,bytes) VALUES(?1,?2,?3)",
            params![outgoing.replica_id, outgoing.sequence.0.to_string(), bytes],
        )
        .map_err(sql)?;
        set_meta(&tx, "state", &canonical(&history.state())?)?;
        check_budget(&tx, &self.limits)?;
        for (blob, witness) in &witnesses {
            if !self.objects.unchanged(blob, witness)? {
                return Err(invalid("Resource changed during projection"));
            }
        }
        let revision = bump_revision(&tx)?;
        tx.commit().map_err(sql)?;
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replace((revision, history));
        Ok(outgoing)
    }
    /// Durable receipt of a complete transaction, independent of object/dependency arrival.
    pub fn receive(&self, connection: &mut Connection, bytes: &[u8]) -> Result<()> {
        self.check(connection)?;
        let incoming: SyncTransaction = decode(bytes, MAX_TRANSACTION_BYTES)?;
        incoming.shape(&self.domain)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        if meta(&tx, "forked")?.is_some() {
            return Err(fork("Domain is already forked"));
        }
        let old = existing(&tx, &incoming.replica_id, incoming.sequence)?;
        if old.iter().any(|b| b != bytes) {
            tx.rollback().map_err(sql)?;
            let mut evidence = old;
            evidence.push(bytes.to_vec());
            mark_fork(connection, &evidence)?;
            return Err(fork("Received a conflicting transaction identity"));
        }
        if old.is_empty() {
            tx.execute(
                "INSERT INTO _darkbox_sync_pending(replica,sequence,bytes) VALUES(?1,?2,?3)",
                params![incoming.replica_id, incoming.sequence.0.to_string(), bytes],
            )
            .map_err(sql)?;
            check_budget(&tx, &self.limits)?;
            bump_revision(&tx)?;
        }
        tx.commit().map_err(sql)
    }
    /// Each ready incoming group is one application/frontier commit. A malformed
    /// group remains pending and is reported after applying independent ready chains.
    pub fn apply_ready(
        &self,
        connection: &mut Connection,
        adapter: &dyn SyncProjection,
    ) -> Result<usize> {
        self.check(connection)?;
        projection_binding(&self.domain, adapter)?;
        check_budget(connection, &self.limits)?;
        let requested = {
            let mut query = connection
                .prepare("SELECT bytes FROM _darkbox_sync_pending")
                .map_err(sql)?;
            let mut rows = query.query([]).map_err(sql)?;
            let mut blobs = BTreeSet::new();
            while let Some(row) = rows.next().map_err(sql)? {
                let bytes: Vec<u8> = row.get(0).map_err(sql)?;
                let transaction: SyncTransaction = decode(&bytes, MAX_TRANSACTION_BYTES)?;
                blobs.extend(transaction.blobs()?);
            }
            blobs
        };
        let mut witnesses = BTreeMap::new();
        for blob in requested {
            if let Some(witness) = self.objects.witness(&blob)? {
                witnesses.insert(blob, witness);
            }
        }
        let mut applied = 0;
        let mut rejected = BTreeSet::new();
        let mut first_rejection = None;
        let end = crate::transfer::deadline(&self.limits.io)?;
        loop {
            crate::container::check_deadline(end)?;
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql)?;
            let (mut revision, mut history) = self.take_history(&tx)?;
            check_budget(&tx, &self.limits)?;
            let pending = {
                let mut q=tx.prepare("SELECT bytes FROM _darkbox_sync_pending ORDER BY replica,length(sequence),sequence").map_err(sql)?;
                q.query_map([], |r| r.get::<_, Vec<u8>>(0))
                    .map_err(sql)?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(sql)?
            };
            let mut changed = false;
            for bytes in pending {
                crate::container::check_deadline(end)?;
                let incoming: SyncTransaction = decode(&bytes, MAX_TRANSACTION_BYTES)?;
                let identity = (incoming.replica_id.clone(), incoming.sequence);
                if rejected.contains(&identity) {
                    continue;
                }
                if let Err(e) = history.check_known_hashes(&incoming) {
                    let mut evidence = existing(&tx, &incoming.replica_id, incoming.sequence)?;
                    evidence.push(bytes);
                    tx.rollback().map_err(sql)?;
                    mark_fork(connection, &evidence)?;
                    return Err(e);
                }
                let mut available = true;
                for blob in incoming.blobs()? {
                    if !witnesses
                        .get(&blob)
                        .map(|witness| self.objects.unchanged(&blob, witness))
                        .transpose()?
                        .unwrap_or(false)
                    {
                        available = false;
                        break;
                    }
                }
                if !available {
                    continue;
                }
                let previous = history.state();
                let status = match history.accept(incoming.clone()) {
                    Ok(status) => status,
                    Err(error) if matches!(error.code, "sync.invalid" | "sync.unsupported") => {
                        first_rejection.get_or_insert_with(|| {
                            error.at(format!("{}:{}", incoming.replica_id, incoming.sequence.0))
                        });
                        rejected.insert(identity);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                if matches!(status, ApplyStatus::Pending(_)) {
                    continue;
                }
                if status == ApplyStatus::Applied {
                    adapter.verify(&tx, &self.domain, &previous)?;
                    adapter.project(&tx, &self.domain, &previous, &history.state())?;
                    if tx.is_autocommit() {
                        return Err(invalid("Projection ended the owning transaction"));
                    }
                    adapter.verify(&tx, &self.domain, &history.state())?;
                    tx.execute(
                        "INSERT INTO _darkbox_sync_history(replica,sequence,bytes)VALUES(?1,?2,?3)",
                        params![incoming.replica_id, incoming.sequence.0.to_string(), bytes],
                    )
                    .map_err(sql)?;
                    set_meta(&tx, "state", &canonical(&history.state())?)?;
                    for blob in incoming.blobs()? {
                        if !witnesses
                            .get(&blob)
                            .map(|witness| self.objects.unchanged(&blob, witness))
                            .transpose()?
                            .unwrap_or(false)
                        {
                            return Err(invalid("Incoming resource changed during projection"));
                        }
                    }
                    revision = bump_revision(&tx)?;
                    applied += 1;
                }
                tx.execute(
                    "DELETE FROM _darkbox_sync_pending WHERE replica=?1 AND sequence=?2",
                    params![incoming.replica_id, incoming.sequence.0.to_string()],
                )
                .map_err(sql)?;
                changed = true;
                break;
            }
            if changed {
                check_budget(&tx, &self.limits)?;
            }
            tx.commit().map_err(sql)?;
            self.cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .replace((revision, history));
            if !changed {
                return first_rejection.map_or(Ok(applied), Err);
            }
        }
    }
    pub fn receive_exchange(
        &self,
        connection: &mut Connection,
        exchange: &Exchange,
    ) -> Result<ExchangeScan> {
        self.check(connection)?;
        self.check_exchange(exchange)?;
        let mut evidence = super::exchange::ScanEvidence::default();
        let scan = match exchange.scan_with_evidence(&mut evidence) {
            Ok(s) => s,
            Err(e) if e.code == "sync.fork" => {
                mark_fork(connection, &evidence.fork)?;
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        for copy in evidence.copies {
            let bytes = copy.bytes()?;
            let mut old = existing(connection, &copy.replica_id, copy.sequence)?;
            if old.iter().any(|known| known != &bytes) {
                old.push(bytes);
                mark_fork(connection, &old)?;
                return Err(fork("Exchange transaction conflicts with local history"));
            }
        }
        let mut imported = BTreeSet::new();
        for transaction in &scan.transactions {
            // Check exact identity bytes before skipping any previously applied
            // work. Pending receipts still need objects delivered in later scans.
            self.receive(connection, &transaction.bytes()?)?;
            let applied: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM _darkbox_sync_history WHERE replica=?1 AND sequence=?2)",
                params![transaction.replica_id, transaction.sequence.0.to_string()],
                |row| row.get(0),
            ).map_err(sql)?;
            if !applied {
                for blob in transaction.blobs()? {
                    if imported.insert(blob.clone()) {
                        self.objects.import(exchange, &blob)?;
                    }
                }
            }
        }
        Ok(scan)
    }
    fn check_exchange(&self, exchange: &Exchange) -> Result<()> {
        self.domain.bind(
            &exchange.domain().root().sync_id,
            exchange.domain().root_hash(),
        )?;
        if self.library.path().starts_with(exchange.path())
            || exchange.path().starts_with(self.library.path())
            || self.objects.path().starts_with(exchange.path())
            || exchange.path().starts_with(self.objects.path())
        {
            return Err(invalid(
                "Live library/local objects must be outside the selected exchange",
            ));
        }
        Ok(())
    }
    /// Publish queued exact bytes, including uncompleted earlier incarnations.
    pub fn publish_pending(&self, connection: &Connection, exchange: &Exchange) -> Result<usize> {
        self.publish_outgoing(connection, exchange, false)
    }
    /// Explicitly repair missing local publications from retained committed outbox bytes.
    pub fn repair_publications(
        &self,
        connection: &Connection,
        exchange: &Exchange,
    ) -> Result<usize> {
        self.publish_outgoing(connection, exchange, true)
    }
    fn publish_outgoing(
        &self,
        connection: &Connection,
        exchange: &Exchange,
        repair: bool,
    ) -> Result<usize> {
        self.check(connection)?;
        self.check_exchange(exchange)?;
        // Freeze history, outbox and its descriptors under one short read snapshot.
        // A concurrent edit may commit after this snapshot; it remains queued.
        let (outgoing, descriptors) = {
            let read = connection.unchecked_transaction().map_err(sql)?;
            let history = self.history(&read)?;
            check_budget(&read, &self.limits)?;
            let query = if repair {
                "SELECT bytes FROM _darkbox_sync_outbox ORDER BY replica,length(sequence),sequence"
            } else {
                "SELECT bytes FROM _darkbox_sync_outbox WHERE published=0 ORDER BY replica,length(sequence),sequence"
            };
            let outgoing = {
                let mut statement = read.prepare(query).map_err(sql)?;
                statement
                    .query_map([], |row| row.get::<_, Vec<u8>>(0))
                    .map_err(sql)?
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(sql)?
            };
            let mut descriptors =
                BTreeMap::from([(self.replica.replica_id.clone(), self.replica.clone())]);
            let mut transactions = Vec::new();
            for bytes in outgoing {
                let transaction: SyncTransaction = decode(&bytes, MAX_TRANSACTION_BYTES)?;
                if !history.contains_transaction(&transaction) {
                    return Err(invalid("Outbox bytes differ from committed history"));
                }
                if !descriptors.contains_key(&transaction.replica_id) {
                    let descriptor: ReplicaDescriptor = decode(
                        &meta(&read, &format!("replica:{}", transaction.replica_id))?
                            .ok_or_else(|| invalid("Outgoing incarnation descriptor is absent"))?,
                        MAX_SEGMENT_BYTES,
                    )?;
                    if descriptor.replica_id != transaction.replica_id {
                        return Err(invalid("Outgoing incarnation descriptor differs"));
                    }
                    descriptors.insert(transaction.replica_id.clone(), descriptor);
                }
                transactions.push(transaction);
            }
            read.commit().map_err(sql)?;
            (transactions, descriptors)
        };
        for descriptor in descriptors.into_values() {
            exchange.publish_replica(&descriptor)?;
        }
        let mut count = 0;
        for transaction in outgoing {
            for blob in transaction.blobs()? {
                exchange.publish_object(&self.objects, &blob)?;
            }
            exchange.publish_segment(&Segment::new(&self.domain, vec![transaction.clone()])?)?;
            connection
                .execute(
                    "UPDATE _darkbox_sync_outbox SET published=1 WHERE replica=?1 AND sequence=?2",
                    params![transaction.replica_id, transaction.sequence.0.to_string()],
                )
                .map_err(sql)?;
            count += 1;
        }
        Ok(count)
    }
    pub fn publish_receipt(
        &self,
        connection: &mut Connection,
        exchange: &Exchange,
    ) -> Result<Receipt> {
        self.check(connection)?;
        self.check_exchange(exchange)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)?;
        let history = load_history(&tx, &self.domain, &self.limits)?;
        let key = format!("receipt_serial:{}", self.replica.replica_id);
        let old = meta(&tx, &key)?
            .map(|bytes| decode::<Counter>(&bytes, 64))
            .transpose()?
            .unwrap_or_default();
        let serial = Counter(
            old.0
                .checked_add(1)
                .ok_or_else(|| unsupported("Receipt counter exhausted"))?,
        );
        let receipt = Receipt {
            kind: "darkbox-sync-receipt".into(),
            protocol_version: VERSION.into(),
            sync_id: self.domain.root().sync_id.clone(),
            root_sha256: self.domain.root_hash().into(),
            replica_id: self.replica.replica_id.clone(),
            serial,
            frontier: history.frontier(),
        };
        set_meta(&tx, &key, &canonical(&serial)?)?;
        set_meta(
            &tx,
            &format!("receipt:{}:{}", self.replica.replica_id, serial.0),
            &canonical(&receipt)?,
        )?;
        tx.commit().map_err(sql)?;
        exchange.publish_replica(&self.replica)?;
        exchange.publish_receipt(&receipt)?;
        Ok(receipt)
    }
    pub fn pending(&self, connection: &Connection) -> Result<Vec<PendingStatus>> {
        self.check(connection)?;
        check_budget(connection, &self.limits)?;
        let history = self.history(connection)?;
        let end = crate::transfer::deadline(&self.limits.io)?;
        let mut query=connection.prepare("SELECT bytes FROM _darkbox_sync_pending ORDER BY replica,length(sequence),sequence").map_err(sql)?;
        let rows = query
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(sql)?;
        let mut result = Vec::new();
        for row in rows {
            crate::container::check_deadline(end)?;
            let transaction: SyncTransaction = decode(&row.map_err(sql)?, MAX_TRANSACTION_BYTES)?;
            let missing_dependencies = history.missing_dependencies(&transaction)?;
            let mut missing_objects = Vec::new();
            for blob in transaction.blobs()? {
                if !self.objects.contains(&blob)? {
                    missing_objects.push(blob);
                }
            }
            let ready = missing_dependencies.is_empty() && missing_objects.is_empty();
            result.push(PendingStatus {
                replica_id: transaction.replica_id,
                sequence: transaction.sequence,
                missing_dependencies,
                missing_objects,
                ready_to_validate: ready,
            });
        }
        Ok(result)
    }
    pub fn pending_count(&self, connection: &Connection) -> Result<usize> {
        self.check(connection)?;
        let n: i64 = connection
            .query_row("SELECT count(*) FROM _darkbox_sync_pending", [], |r| {
                r.get(0)
            })
            .map_err(sql)?;
        Ok(n as usize)
    }
    pub fn queued_count(&self, connection: &Connection) -> Result<usize> {
        self.check(connection)?;
        let n: i64 = connection
            .query_row(
                "SELECT count(*) FROM _darkbox_sync_outbox WHERE published=0",
                [],
                |r| r.get(0),
            )
            .map_err(sql)?;
        Ok(n as usize)
    }
    /// Export a complete old-generation package plus exact outgoing and pending input.
    /// The application must hold its write barrier through checking the returned revision
    /// and switching libraries. The old working library is never removed here.
    pub fn export_recovery(
        &self,
        connection: &Connection,
        destination: impl AsRef<Path>,
        adapter: &dyn SyncProjection,
        options: &crate::VerificationOptions<'_>,
    ) -> Result<RecoveryJournal> {
        self.check(connection)?;
        let read = connection.unchecked_transaction().map_err(sql)?;
        let history = self.history(&read)?;
        let source_revision = cache_revision(&read)?;
        let transactions = |query: &str| -> Result<Vec<SyncTransaction>> {
            let mut statement = read.prepare(query).map_err(sql)?;
            let mut rows = statement.query([]).map_err(sql)?;
            let mut result = Vec::new();
            while let Some(row) = rows.next().map_err(sql)? {
                let bytes: Vec<u8> = row.get(0).map_err(sql)?;
                result.push(decode(&bytes, MAX_TRANSACTION_BYTES)?);
            }
            Ok(result)
        };
        check_budget(&read, &self.limits)?;
        let outgoing = transactions(
            "SELECT bytes FROM _darkbox_sync_outbox WHERE published=0 ORDER BY replica,length(sequence),sequence",
        )?;
        let incoming = transactions(
            "SELECT bytes FROM _darkbox_sync_pending ORDER BY replica,length(sequence),sequence",
        )?;
        read.commit().map_err(sql)?;
        let mut requested = BTreeSet::new();
        for transaction in &incoming {
            requested.extend(transaction.blobs()?);
        }
        let historical = history.blobs()?;
        let mut available = Vec::new();
        let mut missing_objects = Vec::new();
        for blob in requested.difference(&historical) {
            if self.objects.contains(blob)? {
                available.push(blob.clone());
            } else {
                missing_objects.push(blob.clone());
            }
        }
        let recovery = RecoveryJournal {
            kind: "darkbox-sync-recovery".into(),
            protocol_version: VERSION.into(),
            sync_id: self.domain.root().sync_id.clone(),
            root_sha256: self.domain.root_hash().into(),
            source_revision,
            frontier: history.frontier(),
            outgoing,
            incoming,
            missing_objects,
        };
        let metadata_path = format!("{PREFIX}/recovery/journal.json");
        let object_paths: Vec<_> = available
            .iter()
            .map(|blob| Ok(format!("{PREFIX}/recovery/{}", blob.relative_path()?)))
            .collect::<Result<_>>()?;
        let mut paths = object_paths.clone();
        paths.push(metadata_path.clone());
        let mut manifest = crate::json::parse(&super::exchange::read_regular(
            self.library.path(),
            "manifest.json",
            self.limits.io.max_metadata_bytes as usize,
        )?)?;
        super::snapshot::ensure_folders(&mut manifest, &paths)?;
        let mut builder = SnapshotBuilder::from_local(
            destination,
            manifest.clone(),
            &history,
            &self.objects,
            LocalProjection {
                adapter,
                source: connection,
            },
            self.limits.io.clone(),
            options,
        )?;
        add_recovery_resources(
            &mut builder,
            self.library.path(),
            &manifest,
            &self.domain,
            &self.limits.io,
        )?;
        builder.add_reader(&metadata_path, canonical(&recovery)?.as_slice())?;
        for (blob, path) in available.iter().zip(object_paths) {
            self.objects
                .with_blob(blob, |reader| builder.add_reader(&path, reader))?;
        }
        builder.finish()?;
        Ok(recovery)
    }
    pub fn check_rebase_revision(&self, connection: &Connection, expected: Counter) -> Result<()> {
        self.check(connection)?;
        if meta(connection, "forked")?.is_some() {
            return Err(fork("Source was forked during rebase"));
        }
        if cache_revision(connection)? != expected {
            return Err(crate::Error::new(
                crate::Status::OperationalError,
                "sync.revision_changed",
                "Source changed while preparing rebase; preserve the current library and prepare again",
            ));
        }
        Ok(())
    }
    pub fn revision(&self, connection: &Connection) -> Result<Counter> {
        self.check(connection)?;
        cache_revision(connection)
    }
    /// Merge verified checkpoint history without dropping local unpublished operations.
    pub fn receive_history(
        &self,
        connection: &mut Connection,
        history: &History,
        objects: &ObjectStore,
    ) -> Result<()> {
        self.check(connection)?;
        self.domain.bind(
            &history.domain().root().sync_id,
            history.domain().root_hash(),
        )?;
        for blob in history.blobs()? {
            objects.with_blob(&blob, |reader| {
                self.objects.put_expected(reader, &blob).map(|_| ())
            })?;
        }
        for bytes in history.transaction_bytes() {
            self.receive(connection, bytes)?;
        }
        Ok(())
    }
}
fn check_connection(root: &Path, domain: &Domain, connection: &Connection) -> Result<()> {
    let synchronous: i64 = connection
        .query_row("PRAGMA main.synchronous", [], |row| row.get(0))
        .map_err(sql)?;
    let mode: String = connection
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(sql)?;
    if synchronous < 2 || !matches!(mode.as_str(), "wal" | "delete" | "truncate" | "persist") {
        return Err(unsupported(
            "Sync journal requires persistent SQLite journaling and synchronous FULL or EXTRA",
        ));
    }

    let path: String = connection
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let expected =
        super::exchange::safe_path(root, &domain.mapping().storage.database_path, false)?;
    if path.is_empty()
        || fs::canonicalize(&path).map_err(crate::io_failure)?
            != fs::canonicalize(expected).map_err(crate::io_failure)?
    {
        return Err(invalid(
            "Journal must use the working library's authoritative main database",
        ));
    }
    Ok(())
}

/// Validate advisory receipt coverage against an independently verified history.
/// Unknown tips remain pending; receipts never authorize deletion.
pub fn verified_receipts(
    scan: &ExchangeScan,
    history: &History,
) -> Result<BTreeMap<String, Receipt>> {
    let mut result: BTreeMap<String, Receipt> = BTreeMap::new();
    let mut receipts = scan.receipts.clone();
    receipts.sort_by(|a, b| (&a.replica_id, a.serial).cmp(&(&b.replica_id, b.serial)));
    let entries: BTreeMap<_, _> = history
        .transactions()
        .map(|t| Ok(((t.replica_id.clone(), t.sequence), t.hash()?)))
        .collect::<Result<_>>()?;
    let mut seen = BTreeMap::new();
    for receipt in receipts {
        receipt.validate(history.domain())?;
        if !scan.replicas.contains_key(&receipt.replica_id) {
            continue;
        }
        let key = (receipt.replica_id.clone(), receipt.serial);
        let bytes = canonical(&receipt)?;
        if seen
            .insert(key, bytes.clone())
            .is_some_and(|old| old != bytes)
        {
            return Err(fork("Receipt serial has different content"));
        }
        if !receipt
            .frontier
            .iter()
            .all(|tip| entries.get(&(tip.replica_id.clone(), tip.sequence)) == Some(&tip.sha256))
        {
            continue;
        }
        for tip in &receipt.frontier {
            let tx = history
                .transactions()
                .find(|t| t.replica_id == tip.replica_id && t.sequence == tip.sequence)
                .unwrap();
            if !tx.dependencies.iter().all(|d| {
                receipt
                    .frontier
                    .iter()
                    .any(|tip| tip.replica_id == d.replica_id && tip.sequence >= d.sequence)
            }) {
                return Err(invalid("Receipt frontier is not closed"));
            }
        }
        if result.get(&receipt.replica_id).is_some_and(|old| {
            !old.frontier.iter().all(|d| {
                receipt
                    .frontier
                    .iter()
                    .any(|tip| tip.replica_id == d.replica_id && tip.sequence >= d.sequence)
            })
        }) {
            return Err(invalid("Receipt frontier regressed"));
        }
        result.insert(receipt.replica_id.clone(), receipt);
    }
    Ok(result)
}

fn add_recovery_resources(
    builder: &mut SnapshotBuilder<'_>,
    root: &Path,
    manifest: &serde_json::Value,
    domain: &Domain,
    limits: &crate::Limits,
) -> Result<()> {
    let spec = crate::creation::specification(manifest)?;
    let canonical: BTreeSet<_> = spec
        .files
        .iter()
        .map(|file| file.path)
        .chain(std::iter::once(crate::versions::CATALOG_PATH))
        .collect();
    let databases: BTreeSet<_> = manifest["databases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|db| db["path"].as_str().unwrap().to_owned())
        .collect();
    let profile = manifest["application"]["profilePath"].as_str().unwrap();
    let end = crate::transfer::deadline(limits)?;
    let mut stack = vec![root.to_owned()];
    let mut count = 0;
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(directory).map_err(crate::io_failure)? {
            crate::container::check_deadline(end)?;
            count += 1;
            if count > limits.max_entries {
                return Err(super::limit("Recovery resources"));
            }
            let entry = entry.map_err(crate::io_failure)?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .ok_or_else(|| invalid("Recovery resource path"))?;
            if relative == PREFIX || relative.starts_with(&format!("{PREFIX}/")) {
                continue;
            }
            let kind = entry.file_type().map_err(crate::io_failure)?;
            if kind.is_symlink() {
                return Err(invalid("Recovery refuses linked resources").at(relative));
            }
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            if relative == "manifest.json"
                || relative == profile
                || canonical.contains(relative)
                || relative == domain.mapping().storage.database_path
            {
                continue;
            }
            if databases.iter().any(|database| {
                ["-wal", "-shm", "-journal"]
                    .iter()
                    .any(|suffix| relative == format!("{database}{suffix}"))
            }) {
                continue;
            }
            let checked = super::exchange::safe_path(root, relative, false)?;
            if databases.contains(relative) {
                let connection = Connection::open_with_flags(
                    checked,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                )
                .map_err(sql)?;
                let snapshot = crate::package::database_snapshot(&connection, limits, end)?;
                builder.add_path(relative, snapshot.path())?;
            } else {
                builder.add_path(relative, checked)?;
            }
        }
    }
    Ok(())
}
