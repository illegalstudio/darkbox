use darkbox::{
    DirectoryLibrary, Error, ManifestBuilder, Status, VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    sync::*,
};
use rusqlite::{Connection, Transaction};
use serde_json::{Value, json};
use std::{fs, path::Path};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../archive/1.5.0/docs/darkbox/sync/1.0.0.vectors.json"
    ))
    .unwrap()
}
fn domain() -> Domain {
    let data = vectors();
    Domain::from_parts(
        &canonical(&data["root"]).unwrap(),
        &canonical(&data["mapping"]).unwrap(),
        &notes::profile(),
    )
    .unwrap()
}
fn transactions(name: &str) -> Vec<SyncTransaction> {
    let v = vectors();
    serde_json::from_value(
        v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()["transactions"]
            .clone(),
    )
    .unwrap()
}
fn limits() -> SyncLimits {
    SyncLimits::default()
}
fn history(name: &str) -> History {
    History::replay(domain(), transactions(name), limits()).unwrap()
}
fn blob() -> (Blob, Vec<u8>) {
    let v = vectors();
    let b = &v["objects"][0];
    let hex = b["hex"].as_str().unwrap();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    (
        Blob {
            sha256: b["sha256"].as_str().unwrap().into(),
            size: Counter(b["size"].as_str().unwrap().parse().unwrap()),
        },
        bytes,
    )
}
fn bad(message: &str) -> Error {
    Error::invalid("test.projection", message)
}

#[test]
fn independent_schema_and_python_replay_vectors() {
    let v = vectors();
    let schema: Value = serde_json::from_str(include_str!(
        "../archive/1.5.0/docs/darkbox/sync/1.0.0.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    for data in [&v["root"], &v["mapping"]] {
        assert!(
            validator.is_valid(data),
            "{}",
            validator
                .iter_errors(data)
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(";")
        );
    }
    for vector in v["vectors"].as_array().unwrap() {
        assert!(
            validator.is_valid(&vector["state"]),
            "state schema {}",
            vector["name"]
        );
        let mut txs: Vec<SyncTransaction> =
            serde_json::from_value(vector["transactions"].clone()).unwrap();
        for tx in &txs {
            let value = serde_json::to_value(tx).unwrap();
            assert!(
                validator.is_valid(&value),
                "tx schema {}",
                validator
                    .iter_errors(&value)
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(";")
            );
        }
        txs.reverse();
        let h = History::replay(domain(), txs, limits()).unwrap();
        let bytes = canonical(&h.state()).unwrap();
        assert_eq!(
            bytes,
            canonical(&vector["state"]).unwrap(),
            "{}",
            vector["name"]
        );
        assert_eq!(sha256(&bytes), vector["stateSha256"]);
        let order: Vec<Dot> = serde_json::from_value(vector["order"].clone()).unwrap();
        assert_eq!(
            h.state()
                .ordered_records("position", "items", None)
                .unwrap(),
            order
        );
    }
    for rejection in v["rejections"].as_array().unwrap() {
        let txs = serde_json::from_value(rejection["transactions"].clone()).unwrap();
        assert!(
            History::replay(domain(), txs, limits()).is_err(),
            "{}",
            rejection["name"]
        );
    }
    let example = &v["canonicalExample"];
    let tx: SyncTransaction = serde_json::from_value(example["transaction"].clone()).unwrap();
    assert_eq!(
        tx.bytes().unwrap(),
        example["utf8"].as_str().unwrap().as_bytes()
    );
    assert_eq!(tx.hash().unwrap(), example["sha256"]);
}
#[test]
fn wire_refuses_rounding_duplicate_keys_and_noncanonical_values() {
    for bytes in [
        br#"{"x":1}"#.as_slice(),
        br#"{"x":"1","x":"2"}"#,
        b"{\"x\":\"1\"}\n",
        br#"{"x":"\u0061"}"#,
        br#"{"x":"\ud800"}"#,
    ] {
        assert!(decode::<Value>(bytes, 1000).is_err());
    }
    for value in [
        json!("01"),
        json!("+1"),
        json!("18446744073709551616"),
        json!(1),
    ] {
        assert!(serde_json::from_value::<Counter>(value).is_err());
    }
    let mut tx = transactions("exact-values").pop().unwrap();
    tx.operations.push(Operation::Assign {
        record: tx.operations[0].clone().record_for_test(),
        field: "data".into(),
        present: true,
        value: Some(SyncValue::Decimal {
            coefficient: "10".into(),
            exponent: "0".into(),
        }),
    });
    assert!(
        History::replay(
            domain(),
            vec![transactions("exact-values")[0].clone(), tx],
            limits()
        )
        .is_err()
    );
    assert!(
        Blob {
            sha256: "".into(),
            size: Counter(0)
        }
        .relative_path()
        .is_err()
    );
}
trait OperationTest {
    fn record_for_test(&self) -> Dot;
}
impl OperationTest for Operation {
    fn record_for_test(&self) -> Dot {
        match self {
            Operation::Assign { record, .. } => record.clone(),
            _ => panic!(),
        }
    }
}
#[test]
fn all_delivery_permutations_converge_and_duplicate_replay_is_idempotent() {
    let txs = transactions("explicit-new-id-restore");
    let expected = canonical(&history("explicit-new-id-restore").state()).unwrap();
    let mut order: (Vec<usize>, usize) = ((0..txs.len()).collect(), 0);
    fn permute(
        position: usize,
        order: &mut [usize],
        txs: &[SyncTransaction],
        expected: &[u8],
        count: &mut usize,
        domain: &Domain,
    ) {
        if position == order.len() {
            let mut h = History::new(domain.clone(), limits());
            let mut pending = Vec::new();
            for index in order.iter() {
                pending.push(txs[*index].clone());
                loop {
                    let before = pending.len();
                    pending.retain(|tx| {
                        matches!(h.accept(tx.clone()).unwrap(), ApplyStatus::Pending(_))
                    });
                    if before == pending.len() {
                        break;
                    }
                }
            }
            assert!(pending.is_empty());
            assert_eq!(canonical(&h.state()).unwrap(), expected);
            for tx in txs {
                assert_eq!(h.accept(tx.clone()).unwrap(), ApplyStatus::Duplicate);
            }
            *count += 1;
            return;
        }
        for i in position..order.len() {
            order.swap(i, position);
            permute(position + 1, order, txs, expected, count, domain);
            order.swap(i, position);
        }
    }
    permute(0, &mut order.0, &txs, &expected, &mut order.1, &domain());
    assert_eq!(order.1, 5040);
}

#[path = "../examples/support/sync_notes.rs"]
mod notes;
use notes::Notes;

fn manifest() -> Value {
    ManifestBuilder::new("1.5.0", "org.example.sync-notes", "1")
        .unwrap()
        .package_id(&domain().root().package_id)
        .folder("data", "Authoritative state")
        .database(DatabaseDeclaration {
            path: "data/project.sqlite".into(),
            description: "Synchronized notes".into(),
            user_version: None,
            tables: ["items", "item_conflicts"]
                .into_iter()
                .map(|name| TableDeclaration {
                    name: name.into(),
                    description: "Profile state".into(),
                })
                .collect(),
        })
        .build()
        .unwrap()
}
fn new_library(root: &Path, name: &str, source: &History) -> (DirectoryLibrary, ObjectStore) {
    let objects = ObjectStore::open(root.join(format!("objects-{name}")), limits()).unwrap();
    let (_, bytes) = blob();
    objects.put(&mut bytes.as_slice()).unwrap();
    let package = root.join(format!("{name}.zip"));
    let options = VerificationOptions::default();
    SnapshotBuilder::new(
        &package,
        manifest(),
        source,
        &objects,
        &Notes,
        limits().io,
        &options,
    )
    .unwrap()
    .finish()
    .unwrap();
    let snapshot = SyncSnapshot::open(&package, limits(), &options).unwrap();
    snapshot.verify_projection(&Notes).unwrap();
    let library = snapshot
        .bootstrap(root.join(name), &objects, &Notes)
        .unwrap();
    (library, objects)
}
fn db(library: &DirectoryLibrary) -> Connection {
    Connection::open(library.path().join("data/project.sqlite")).unwrap()
}
#[test]
fn complete_checkpoint_bootstraps_without_segments_and_retains_deleted_resource() {
    let root = tempfile::tempdir().unwrap();
    let h = history("delete-wins");
    let (mut library, objects) = new_library(root.path(), "restored", &h);
    let mut connection = db(&library);
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("7".repeat(32), "third PC"),
        &Notes,
    )
    .unwrap();
    assert_eq!(
        canonical(&session.history(&connection).unwrap().state()).unwrap(),
        canonical(&h.state()).unwrap()
    );
    assert!(session.objects().contains(&blob().0).unwrap());
    let descriptor = fs::read(
        session
            .objects()
            .path()
            .join(blob().0.relative_path().unwrap()),
    )
    .unwrap();
    assert_eq!(descriptor, blob().1);
}
#[test]
fn two_offline_peers_exchange_conflicts_and_a_third_replays_a_checkpoint() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut a, oa) = new_library(root.path(), "a", &initial);
    let (mut b, ob) = new_library(root.path(), "b", &initial);
    let (mut ca, mut cb) = (db(&a), db(&b));
    let record = initial.state().records[0].id.clone();
    let sa = SyncSession::open(
        &mut a,
        &mut ca,
        domain(),
        oa,
        SessionOptions::new("a".repeat(32), "A"),
        &Notes,
    )
    .unwrap();
    let sb = SyncSession::open(
        &mut b,
        &mut cb,
        domain(),
        ob,
        SessionOptions::new("b".repeat(32), "B"),
        &Notes,
    )
    .unwrap();
    let assign = |value: &str| Operation::Assign {
        record: record.clone(),
        field: "title".into(),
        present: true,
        value: Some(SyncValue::text(value)),
    };
    sa.edit(&mut ca, vec![assign("from A")], &Notes).unwrap();
    sb.edit(&mut cb, vec![assign("from B")], &Notes).unwrap();
    ca.execute(
        "UPDATE items SET local_note='only A' WHERE id=?1",
        [record.to_string()],
    )
    .unwrap();
    let exchange = Exchange::create(root.path().join("cloud"), domain(), limits()).unwrap();
    sa.publish_pending(&ca, &exchange).unwrap();
    sb.publish_pending(&cb, &exchange).unwrap();
    sa.receive_exchange(&mut ca, &exchange).unwrap();
    sb.receive_exchange(&mut cb, &exchange).unwrap();
    sa.apply_ready(&mut ca, &Notes).unwrap();
    sb.apply_ready(&mut cb, &Notes).unwrap();
    assert_eq!(
        sa.history(&ca).unwrap().state(),
        sb.history(&cb).unwrap().state()
    );
    let state = sa.history(&ca).unwrap().state();
    assert!(
        state
            .record(&record)
            .unwrap()
            .register("title")
            .unwrap()
            .conflicted()
    );
    assert_eq!(
        ca.query_row(
            "SELECT local_note FROM items WHERE id=?1",
            [record.to_string()],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "only A"
    );
    sa.edit(&mut ca, vec![assign("resolved")], &Notes).unwrap();
    sa.publish_pending(&ca, &exchange).unwrap();
    sb.receive_exchange(&mut cb, &exchange).unwrap();
    sb.apply_ready(&mut cb, &Notes).unwrap();
    assert_eq!(
        sa.history(&ca).unwrap().state(),
        sb.history(&cb).unwrap().state()
    );
    assert!(
        !sa.history(&ca)
            .unwrap()
            .state()
            .record(&record)
            .unwrap()
            .register("title")
            .unwrap()
            .conflicted()
    );
    let checkpoint = root.path().join("checkpoint.zip");
    let options = VerificationOptions::default();
    SnapshotBuilder::new(
        &checkpoint,
        manifest(),
        &sa.history(&ca).unwrap(),
        sa.objects(),
        &Notes,
        limits().io,
        &options,
    )
    .unwrap()
    .finish()
    .unwrap();
    let snapshot = SyncSnapshot::open(&checkpoint, limits(), &options).unwrap();
    let descriptor = snapshot.publish(&exchange, sa.replica()).unwrap();
    assert!(exchange.path().join(descriptor.package.path).is_file());
    let third_objects = ObjectStore::open(root.path().join("objects-third"), limits()).unwrap();
    let third = snapshot
        .bootstrap(root.path().join("third"), &third_objects, &Notes)
        .unwrap();
    let cc = db(&third);
    Notes
        .verify(&cc, &domain(), &sa.history(&ca).unwrap().state())
        .unwrap();
    sa.publish_receipt(&mut ca, &exchange).unwrap();
    let scan = exchange.scan().unwrap();
    assert_eq!(
        verified_receipts(&scan, &sa.history(&ca).unwrap())
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn projection_failure_rolls_back_rows_history_and_outbox_and_restart_uses_new_identity() {
    struct Failing;
    impl SyncProjection for Failing {
        fn id(&self) -> &str {
            Notes.id()
        }
        fn version(&self) -> &str {
            Notes.version()
        }
        fn validate_mapping(&self, d: &Domain, c: &Connection) -> Result<(), Error> {
            Notes.validate_mapping(d, c)
        }
        fn verify(&self, c: &Connection, d: &Domain, s: &LogicalState) -> Result<(), Error> {
            Notes.verify(c, d, s)
        }
        fn project(
            &self,
            t: &Transaction<'_>,
            _: &Domain,
            _: &LogicalState,
            _: &LogicalState,
        ) -> Result<(), Error> {
            t.execute("UPDATE items SET title='partial'", []).unwrap();
            Err(bad("injected failure"))
        }
    }
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "local", &initial);
    let mut connection = db(&library);
    let identity;
    {
        let session = SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects.clone(),
            SessionOptions::new("f".repeat(32), "first"),
            &Notes,
        )
        .unwrap();
        identity = session.replica().replica_id.clone();
        let before = session.history(&connection).unwrap().state();
        let record = before.records[0].id.clone();
        assert!(
            session
                .edit(
                    &mut connection,
                    vec![Operation::Assign {
                        record,
                        field: "title".into(),
                        present: true,
                        value: Some(SyncValue::text("new"))
                    }],
                    &Failing
                )
                .is_err()
        );
        assert_eq!(before, session.history(&connection).unwrap().state());
        assert_eq!(session.queued_count(&connection).unwrap(), 0);
        Notes.verify(&connection, &domain(), &before).unwrap();
    }
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("f".repeat(32), "reopened"),
        &Notes,
    )
    .unwrap();
    assert_ne!(identity, session.replica().replica_id);
    let tx = session
        .edit_with(&mut connection, &Notes, |batch| {
            let id = batch.dot(0)?;
            Ok(vec![
                Operation::Create {
                    collection: "items".into(),
                },
                Operation::Assign {
                    record: id,
                    field: "title".into(),
                    present: true,
                    value: Some(SyncValue::text("atomic create")),
                },
            ])
        })
        .unwrap();
    assert_eq!(tx.sequence, Counter(1));
    assert_eq!(session.queued_count(&connection).unwrap(), 1);
}

#[test]
fn missing_objects_and_causal_descendants_wait_while_other_replicas_progress() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, _) = new_library(root.path(), "missing", &initial);
    let objects = ObjectStore::open(root.path().join("empty-objects"), limits()).unwrap();
    let mut connection = db(&library);
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("8".repeat(32), "missing"),
        &Notes,
    )
    .unwrap();
    let txs = transactions("observed-remove-concurrent-add");
    for tx in txs[1..].iter().rev() {
        session
            .receive(&mut connection, &tx.bytes().unwrap())
            .unwrap();
    }
    assert_eq!(session.apply_ready(&mut connection, &Notes).unwrap(), 1);
    assert_eq!(session.pending_count(&connection).unwrap(), 2);
    let expected = History::replay(
        domain(),
        [
            initial.transactions().cloned().collect::<Vec<_>>(),
            vec![txs[2].clone()],
        ]
        .concat(),
        limits(),
    )
    .unwrap();
    assert_eq!(
        session.history(&connection).unwrap().state(),
        expected.state()
    );
    let (_, bytes) = blob();
    session.objects().put(&mut bytes.as_slice()).unwrap();
    assert_eq!(session.apply_ready(&mut connection, &Notes).unwrap(), 2);
    assert_eq!(session.pending_count(&connection).unwrap(), 0);
    let expected = History::replay(
        domain(),
        [initial.transactions().cloned().collect::<Vec<_>>(), txs].concat(),
        limits(),
    )
    .unwrap();
    assert_eq!(
        session.history(&connection).unwrap().state(),
        expected.state()
    );
}
#[test]
fn fork_evidence_survives_reopen_and_blocks_writes() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "fork", &initial);
    let mut connection = db(&library);
    {
        let session = SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects.clone(),
            SessionOptions::new("9".repeat(32), "fork"),
            &Notes,
        )
        .unwrap();
        let original = transactions("concurrent-values-and-moves")[1].clone();
        session
            .receive(&mut connection, &original.bytes().unwrap())
            .unwrap();
        let mut fork = original;
        fork.operations[0] = Operation::Assign {
            record: initial.state().records[0].id.clone(),
            field: "title".into(),
            present: true,
            value: Some(SyncValue::text("different branch")),
        };
        assert_eq!(
            session
                .receive(&mut connection, &fork.bytes().unwrap())
                .unwrap_err()
                .code,
            "sync.fork"
        );
        assert!(session.history(&connection).is_err());
    }
    assert!(
        SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects,
            SessionOptions::new("9".repeat(32), "reopened"),
            &Notes
        )
        .is_err()
    );
    let evidence: i64 = connection
        .query_row("SELECT count(*) FROM _darkbox_sync_forks", [], |r| r.get(0))
        .unwrap();
    assert_eq!(evidence, 2);
    Notes
        .verify(&connection, &domain(), &initial.state())
        .unwrap();
}
#[test]
fn scanner_waits_for_complete_bytes_and_distinguishes_duplicates_from_forks() {
    let root = tempfile::tempdir().unwrap();
    let exchange = Exchange::create(root.path().join("cloud"), domain(), limits()).unwrap();
    let tx = transactions("concurrent-values-and-moves")[0].clone();
    let descriptor = ReplicaDescriptor {
        kind: "darkbox-sync-replica".into(),
        protocol_version: VERSION.into(),
        sync_id: domain().root().sync_id.clone(),
        root_sha256: domain().root_hash().into(),
        replica_id: tx.replica_id.clone(),
        device_id: "1".repeat(32),
        label: "origin".into(),
    };
    exchange.publish_replica(&descriptor).unwrap();
    let segment = Segment::new(&domain(), vec![tx.clone()]).unwrap();
    let path = exchange.path().join(segment.relative_path().unwrap());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = canonical(&segment).unwrap();
    fs::create_dir_all(exchange.path().join("replicas/unrelated/a/b/c/d/e/f/g")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        fs::write(
            path.parent()
                .unwrap()
                .join(std::ffi::OsString::from_vec(vec![0xff])),
            b"foreign metadata",
        )
        .unwrap();
    }
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert_eq!(
        exchange.publish_segment(&segment).unwrap_err().code,
        "sync.pending_bytes"
    );
    let scan = exchange.scan().unwrap();
    assert!(scan.transactions.is_empty());
    assert!(
        scan.diagnostics
            .iter()
            .any(|d| d.code == "sync.pending_bytes")
    );
    fs::write(&path, &bytes).unwrap();
    assert_eq!(exchange.scan().unwrap().transactions, vec![tx.clone()]);
    let copy = path.with_file_name(format!(
        "{} (conflicted copy).json",
        path.file_stem().unwrap().to_str().unwrap()
    ));
    fs::write(copy, &bytes).unwrap();
    assert_eq!(exchange.scan().unwrap().transactions.len(), 1);
    let mut other = tx;
    other.operations.push(Operation::Create {
        collection: "items".into(),
    });
    let fork = Segment::new(&domain(), vec![other]).unwrap();
    let fork_bytes = canonical(&fork).unwrap();
    let copy = path.parent().unwrap().join(format!(
        "{} (conflicted copy).json",
        Path::new(&fork.relative_path().unwrap())
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap()
    ));
    fs::write(copy, &fork_bytes).unwrap();
    assert_eq!(exchange.scan().unwrap_err().code, "sync.fork");
}
#[test]
fn checkpoint_union_preserves_local_outbox_and_local_only_values() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "union", &initial);
    let mut connection = db(&library);
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects.clone(),
        SessionOptions::new("e".repeat(32), "union"),
        &Notes,
    )
    .unwrap();
    let id = initial.state().records[0].id.clone();
    let local = session
        .edit(
            &mut connection,
            vec![Operation::Assign {
                record: id.clone(),
                field: "title".into(),
                present: true,
                value: Some(SyncValue::text("unpublished local edit")),
            }],
            &Notes,
        )
        .unwrap();
    connection
        .execute(
            "UPDATE items SET local_note='keep me' WHERE id=?1",
            [id.to_string()],
        )
        .unwrap();
    let remote = history("concurrent-values-and-moves");
    session
        .receive_history(&mut connection, &remote, &objects)
        .unwrap();
    session.apply_ready(&mut connection, &Notes).unwrap();
    let expected = History::replay(
        domain(),
        [
            initial.transactions().cloned().collect::<Vec<_>>(),
            remote.transactions().cloned().collect::<Vec<_>>(),
            vec![local],
        ]
        .concat(),
        limits(),
    )
    .unwrap();
    assert_eq!(
        session.history(&connection).unwrap().state(),
        expected.state()
    );
    assert_eq!(session.queued_count(&connection).unwrap(), 1);
    assert_eq!(
        connection
            .query_row(
                "SELECT local_note FROM items WHERE id=?1",
                [id.to_string()],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "keep me"
    );
}

#[test]
#[ignore = "subprocess crash probe, invoked by sqlite_process_crashes_preserve_atomicity"]
fn child_crash_probe() {
    let root = std::path::PathBuf::from(std::env::var_os("DARKBOX_SYNC_CRASH_ROOT").unwrap());
    let stage = std::env::var("DARKBOX_SYNC_CRASH_STAGE").unwrap();
    let mut library = DirectoryLibrary::open(root.join("crash")).unwrap();
    let mut connection = db(&library);
    connection
        .execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")
        .unwrap();
    let objects = ObjectStore::open(root.join("objects-crash"), limits()).unwrap();
    struct Crash;
    impl SyncProjection for Crash {
        fn id(&self) -> &str {
            Notes.id()
        }
        fn version(&self) -> &str {
            Notes.version()
        }
        fn validate_mapping(&self, d: &Domain, c: &Connection) -> Result<(), Error> {
            Notes.validate_mapping(d, c)
        }
        fn verify(&self, c: &Connection, d: &Domain, s: &LogicalState) -> Result<(), Error> {
            Notes.verify(c, d, s)
        }
        fn project(
            &self,
            t: &Transaction<'_>,
            d: &Domain,
            a: &LogicalState,
            b: &LogicalState,
        ) -> Result<(), Error> {
            Notes.project(t, d, a, b)?;
            std::process::exit(77)
        }
    }
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("c".repeat(32), "child"),
        &Notes,
    )
    .unwrap();
    let id = session.history(&connection).unwrap().state().records[0]
        .id
        .clone();
    let operation = Operation::Assign {
        record: id,
        field: "title".into(),
        present: true,
        value: Some(SyncValue::text("committed by child")),
    };
    session
        .edit(
            &mut connection,
            vec![operation],
            if stage == "before_commit" {
                &Crash
            } else {
                &Notes
            },
        )
        .unwrap();
    if stage == "after_publish" {
        let exchange = Exchange::create(root.join("cloud"), domain(), limits()).unwrap();
        session.publish_pending(&connection, &exchange).unwrap();
    }
    std::process::exit(77)
}
#[test]
fn sqlite_process_crashes_preserve_atomicity() {
    for stage in ["before_commit", "after_commit", "after_publish"] {
        let root = tempfile::tempdir().unwrap();
        let initial = history("exact-values");
        let (library, objects) = new_library(root.path(), "crash", &initial);
        drop(library);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_crash_probe", "--ignored", "--nocapture"])
            .env("DARKBOX_SYNC_CRASH_ROOT", root.path())
            .env("DARKBOX_SYNC_CRASH_STAGE", stage)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let mut library = DirectoryLibrary::open(root.path().join("crash")).unwrap();
        let mut connection = db(&library);
        let session = SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects,
            SessionOptions::new("d".repeat(32), "recovery"),
            &Notes,
        )
        .unwrap();
        let history = session.history(&connection).unwrap();
        Notes
            .verify(&connection, &domain(), &history.state())
            .unwrap();
        assert_eq!(
            history.len(),
            initial.len() + usize::from(stage != "before_commit")
        );
        assert_eq!(
            session.queued_count(&connection).unwrap(),
            usize::from(stage == "after_commit")
        );
        if stage == "after_publish" {
            let exchange =
                Exchange::open(root.path().join("cloud"), domain().root_hash(), limits()).unwrap();
            let before = exchange.scan().unwrap().transactions;
            session.publish_pending(&connection, &exchange).unwrap();
            assert_eq!(exchange.scan().unwrap().transactions, before);
        }
    }
}

#[test]
fn typed_wire_rejects_missing_nullable_members_and_explicit_null_aliases() {
    let original = serde_json::to_value(&transactions("exact-values")[0]).unwrap();
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("previous");
    assert!(
        decode::<SyncTransaction>(&canonical(&missing).unwrap(), MAX_TRANSACTION_BYTES).is_err()
    );
    let mut missing = original.clone();
    missing["operations"][4]
        .as_object_mut()
        .unwrap()
        .remove("owner");
    assert!(
        decode::<SyncTransaction>(&canonical(&missing).unwrap(), MAX_TRANSACTION_BYTES).is_err()
    );
    let mut alias = original;
    alias["operations"] = json!([{"op":"assign","record":format!("{}:1:0",alias["replicaId"].as_str().unwrap()),"field":"title","present":false,"value":null}]);
    assert!(decode::<SyncTransaction>(&canonical(&alias).unwrap(), MAX_TRANSACTION_BYTES).is_err());
}
#[test]
fn changed_causal_revision_never_commits_a_stale_create_group() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "revision", &initial);
    let mut connection = db(&library);
    connection
        .execute_batch("PRAGMA journal_mode=WAL;")
        .unwrap();
    let mut other = Connection::open(library.path().join("data/project.sqlite")).unwrap();
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("3".repeat(32), "revision"),
        &Notes,
    )
    .unwrap();
    let result = session.edit_with(&mut connection, &Notes, |batch| {
        let stale = batch.dot(0)?;
        session.edit_with(&mut other, &Notes, |inner| {
            Ok(vec![
                Operation::Create {
                    collection: "items".into(),
                },
                Operation::Assign {
                    record: inner.dot(0)?,
                    field: "title".into(),
                    present: true,
                    value: Some(SyncValue::text("inner committed")),
                },
            ])
        })?;
        Ok(vec![
            Operation::Create {
                collection: "items".into(),
            },
            Operation::Assign {
                record: stale,
                field: "title".into(),
                present: true,
                value: Some(SyncValue::text("outer stale")),
            },
        ])
    });
    assert!(result.is_err());
    assert_eq!(
        session.history(&connection).unwrap().len(),
        initial.len() + 1
    );
    assert_eq!(session.queued_count(&connection).unwrap(), 1);
    Notes
        .verify(
            &connection,
            &domain(),
            &session.history(&connection).unwrap().state(),
        )
        .unwrap();
}
#[test]
fn durable_sqlite_policy_and_reader_limits_fail_without_losing_state() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "policy", &initial);
    let mut connection = db(&library);
    connection.execute_batch("PRAGMA synchronous=OFF;").unwrap();
    assert!(
        SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects.clone(),
            SessionOptions::new("2".repeat(32), "unsafe"),
            &Notes
        )
        .is_err()
    );
    connection
        .execute_batch("PRAGMA synchronous=FULL;")
        .unwrap();
    let mut policy = limits();
    policy.max_transactions = 1;
    assert!(History::replay(domain(), transactions("exact-values"), policy).is_err());
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("2".repeat(32), "safe"),
        &Notes,
    )
    .unwrap();
    assert_eq!(
        session.history(&connection).unwrap().state(),
        initial.state()
    );
}
#[test]
fn sealed_checkpoint_rejects_a_forged_state_even_with_updated_resource_digest() {
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
    };
    let root = tempfile::tempdir().unwrap();
    let source = history("concurrent-values-and-moves");
    let _ = new_library(root.path(), "source", &source);
    let original = root.path().join("source.zip");
    let mut archive = zip::ZipArchive::new(fs::File::open(&original).unwrap()).unwrap();
    let mut files = BTreeMap::new();
    let mut directories = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let name = entry.name().to_owned();
        if entry.is_dir() {
            directories.push(name);
        } else {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            files.insert(name, bytes);
        }
    }
    let state_path = format!("{PREFIX}/state.json");
    let mut state: Value = serde_json::from_slice(&files[&state_path]).unwrap();
    state["records"][0]["collection"] = json!("forged");
    let state = canonical(&state).unwrap();
    files.insert(state_path, state.clone());
    let checkpoint_path = format!("{PREFIX}/checkpoint.json");
    let mut checkpoint: Checkpoint = decode(&files[&checkpoint_path], MAX_SEGMENT_BYTES).unwrap();
    checkpoint.state.sha256 = sha256(&state);
    checkpoint.state.size = Counter(state.len() as u64);
    files.insert(checkpoint_path, canonical(&checkpoint).unwrap());
    let path = root.path().join("forged.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    for dir in directories {
        zip.add_directory(dir, options).unwrap();
    }
    for (name, bytes) in files {
        zip.start_file(name, options).unwrap();
        zip.write_all(&bytes).unwrap();
    }
    zip.finish().unwrap();
    let report = darkbox::verify(&path);
    assert_eq!(report.status, Status::Invalid);
    assert!(report.diagnostics.iter().any(|d| d.code == "sync.invalid"));
}

#[test]
fn background_publication_and_local_edits_share_a_coherent_outbox_snapshot() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SyncSession<'_>>();
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "concurrent", &initial);
    let path = library.path().join("data/project.sqlite");
    let mut connection = db(&library);
    connection
        .execute_batch("PRAGMA journal_mode=WAL;")
        .unwrap();
    let session = SyncSession::open(
        &mut library,
        &mut connection,
        domain(),
        objects,
        SessionOptions::new("5".repeat(32), "concurrent"),
        &Notes,
    )
    .unwrap();
    let exchange = Exchange::create(root.path().join("cloud"), domain(), limits()).unwrap();
    let id = initial.state().records[0].id.clone();
    std::thread::scope(|scope| {
        let publisher = scope.spawn(|| {
            let db = Connection::open(&path).unwrap();
            db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
            for _ in 0..25 {
                session.publish_pending(&db, &exchange).unwrap();
            }
        });
        for i in 0..25 {
            session
                .edit(
                    &mut connection,
                    vec![Operation::Assign {
                        record: id.clone(),
                        field: "title".into(),
                        present: true,
                        value: Some(SyncValue::text(format!("edit {i}"))),
                    }],
                    &Notes,
                )
                .unwrap();
        }
        publisher.join().unwrap();
    });
    session.publish_pending(&connection, &exchange).unwrap();
    assert_eq!(exchange.scan().unwrap().transactions.len(), 25);
    assert_eq!(session.queued_count(&connection).unwrap(), 0);
    assert_eq!(
        session.history(&connection).unwrap().len(),
        initial.len() + 25
    );
    let segment = exchange.scan().unwrap().transactions[0].clone();
    let segment = Segment::new(&domain(), vec![segment]).unwrap();
    let path = exchange.path().join(segment.relative_path().unwrap());
    fs::remove_file(&path).unwrap();
    assert_eq!(session.publish_pending(&connection, &exchange).unwrap(), 0);
    assert!(!path.exists());
    assert_eq!(
        session.repair_publications(&connection, &exchange).unwrap(),
        25
    );
    assert!(path.is_file());
}

#[test]
fn future_required_sync_version_is_unsupported_instead_of_corrupt() {
    let schema: Value =
        serde_json::from_str(include_str!("../schema/1.5.0/manifest.schema.json")).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let mut metadata = manifest();
    metadata["extensions"] = json!({NAMESPACE:{"version":"2.0.0","required":true,"data":{}}});
    assert!(validator.is_valid(&metadata));
    let options = VerificationOptions::default();
    assert!(options.extensions.get(NAMESPACE, "2.0.0").is_none());
    let root = tempfile::tempdir().unwrap();
    let source = history("exact-values");
    let _ = new_library(root.path(), "future-source", &source);
    let mut archive =
        zip::ZipArchive::new(fs::File::open(root.path().join("future-source.zip")).unwrap())
            .unwrap();
    let output = root.path().join("future.zip");
    let mut writer = zip::ZipWriter::new(fs::File::create(&output).unwrap());
    let entry_options = zip::write::SimpleFileOptions::default();
    use std::io::{Read, Write};
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let path = entry.name().to_owned();
        if entry.is_dir() {
            writer.add_directory(path, entry_options).unwrap();
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        if path == "manifest.json" {
            let mut metadata: Value = serde_json::from_slice(&bytes).unwrap();
            metadata["extensions"][NAMESPACE]["version"] = json!("2.0.0");
            bytes = serde_json::to_vec(&metadata).unwrap();
        }
        writer.start_file(path, entry_options).unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.finish().unwrap();
    assert_eq!(darkbox::verify(output).status, Status::Unsupported);
}

#[test]
fn working_mutators_refuse_unowned_required_extensions_without_changes() {
    let root = tempfile::tempdir().unwrap();
    let initial = history("exact-values");
    let (mut library, objects) = new_library(root.path(), "required", &initial);
    let mut connection = db(&library);
    let path = library.path().join("manifest.json");
    let mut metadata: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata["extensions"]["org.example.required"] =
        json!({"version":"1.0.0","required":true,"data":{"preserve":"exact"}});
    let original = serde_json::to_vec(&metadata).unwrap();
    fs::write(&path, &original).unwrap();
    assert_eq!(
        attach_working(&library, &domain(), &limits().io)
            .unwrap_err()
            .status,
        Status::Unsupported
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(
        SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects,
            SessionOptions::new("4".repeat(32), "unsupported extension"),
            &Notes
        )
        .is_err()
    );
    let incarnations: i64 = connection
        .query_row(
            "SELECT count(*) FROM _darkbox_sync_meta WHERE key LIKE 'replica:%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(incarnations, 0);
    Notes
        .verify(&connection, &domain(), &initial.state())
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    metadata["extensions"]
        .as_object_mut()
        .unwrap()
        .remove("org.example.required");
    let clean = serde_json::to_vec(&metadata).unwrap();
    fs::write(&path, &clean).unwrap();
    let profile = library.path().join("docs/profile.md");
    let profile_bytes = fs::read(&profile).unwrap();
    fs::write(&profile, b"changed without a new domain").unwrap();
    let objects = ObjectStore::open(root.path().join("wrong-profile-objects"), limits()).unwrap();
    assert!(
        SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects.clone(),
            SessionOptions::new("4".repeat(32), "wrong profile"),
            &Notes
        )
        .is_err()
    );
    fs::write(profile, profile_bytes).unwrap();
    metadata["darkbox"]["id"] = json!("wrong");
    fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    assert!(
        SyncSession::open(
            &mut library,
            &mut connection,
            domain(),
            objects,
            SessionOptions::new("4".repeat(32), "wrong manifest"),
            &Notes
        )
        .is_err()
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM _darkbox_sync_meta WHERE key LIKE 'replica:%'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}
