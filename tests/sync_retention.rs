use darkbox::{
    DirectoryLibrary, ManifestBuilder, VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    sync::*,
};
use rusqlite::Connection;
use serde_json::Value;
use std::{collections::BTreeMap, fs, io::Read, path::Path};
#[path = "../examples/support/sync_notes.rs"]
mod notes;
use notes::Notes;
fn assert_wire_schema(bytes: &[u8]) {
    let schema: Value = serde_json::from_str(include_str!(
        "../archive/1.5.0/docs/darkbox/sync/1.0.0.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let value: Value = serde_json::from_slice(bytes).unwrap();
    assert!(
        validator.is_valid(&value),
        "{}",
        validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    );
}
fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../archive/1.5.0/docs/darkbox/sync/1.0.0.vectors.json"
    ))
    .unwrap()
}
fn history(name: &str) -> History {
    let v = vectors();
    let domain = Domain::from_parts(
        &canonical(&v["root"]).unwrap(),
        &canonical(&v["mapping"]).unwrap(),
        &notes::profile(),
    )
    .unwrap();
    let tx = v["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["transactions"]
        .clone();
    History::replay(
        domain,
        serde_json::from_value(tx).unwrap(),
        SyncLimits::default(),
    )
    .unwrap()
}
fn manifest(domain: &Domain) -> Value {
    ManifestBuilder::new("1.5.0", "org.example.sync-notes", "1")
        .unwrap()
        .package_id(&domain.root().package_id)
        .folder("data", "Application state")
        .database(DatabaseDeclaration {
            path: "data/project.sqlite".into(),
            description: "Notes".into(),
            user_version: None,
            tables: ["items", "item_conflicts"]
                .into_iter()
                .map(|name| TableDeclaration {
                    name: name.into(),
                    description: "Notes state".into(),
                })
                .collect(),
        })
        .build()
        .unwrap()
}
fn store(root: &Path, name: &str) -> ObjectStore {
    let store = ObjectStore::open(root.join(name), SyncLimits::default()).unwrap();
    let v = vectors();
    for object in v["objects"].as_array().unwrap() {
        let hex = object["hex"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        store.put(&mut bytes.as_slice()).unwrap();
    }
    store
}
fn snapshot(root: &Path, name: &str, history: &History, objects: &ObjectStore) -> SyncSnapshot {
    let path = root.join(format!("{name}.darkbox"));
    SnapshotBuilder::new(
        &path,
        manifest(history.domain()),
        history,
        objects,
        &Notes,
        SyncLimits::default().io,
        &VerificationOptions::default(),
    )
    .unwrap()
    .finish()
    .unwrap();
    SyncSnapshot::open(path, SyncLimits::default(), &VerificationOptions::default()).unwrap()
}
fn live(
    snapshot: &SyncSnapshot,
    path: &Path,
    objects: &ObjectStore,
) -> (DirectoryLibrary, Connection) {
    let library = snapshot.bootstrap(path, objects, &Notes).unwrap();
    let connection = Connection::open(library.path().join("data/project.sqlite")).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")
        .unwrap();
    (library, connection)
}
fn policy() -> RetentionPolicy {
    RetentionPolicy {
        retention_seconds: Counter(10),
        checkpoint_interval_seconds: Counter(5),
        checkpoint_transactions: Counter(2),
        checkpoint_history_bytes: Counter(1024),
        ..Default::default()
    }
}

#[test]
fn compact_seeds_match_independent_python_vectors() {
    let vectors = vectors();
    let schema: Value = serde_json::from_str(include_str!(
        "../archive/1.5.0/docs/darkbox/sync/1.0.0.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    for vector in vectors["compactVectors"].as_array().unwrap() {
        let compact = history(vector["name"].as_str().unwrap()).compact().unwrap();
        let base = compact.domain().baseline().unwrap();
        assert_eq!(
            canonical(base).unwrap(),
            canonical(&vector["baseline"]).unwrap()
        );
        assert_eq!(sha256(&canonical(base).unwrap()), vector["baselineSha256"]);
        assert!(validator.is_valid(&serde_json::to_value(base).unwrap()));
        assert!(validator.is_valid(&serde_json::to_value(compact.domain().root()).unwrap()));
    }
}

#[test]
fn compact_baselines_preserve_live_identity_conflicts_and_order_and_allow_new_edits() {
    for fixture in vectors()["vectors"].as_array().unwrap() {
        let original = history(fixture["name"].as_str().unwrap());
        let compact = original.compact().unwrap();
        assert_eq!(compact.len(), 0);
        assert!(compact.domain().baseline().is_some());
        let original_state = original.state();
        let state = compact.state();
        let original_live: BTreeMap<_, _> = original_state
            .records
            .iter()
            .filter(|r| r.live())
            .map(|r| (&r.id, r))
            .collect();
        let compact_live: BTreeMap<_, _> = state
            .records
            .iter()
            .filter(|r| r.live())
            .map(|r| (&r.id, r))
            .collect();
        assert_eq!(
            original_live.keys().collect::<Vec<_>>(),
            compact_live.keys().collect::<Vec<_>>()
        );
        for (id, row) in &compact_live {
            for field in &row.registers {
                let before = original_live[id].register(&field.field).unwrap();
                assert_eq!(
                    field
                        .candidates
                        .iter()
                        .map(|candidate| (&candidate.dot, candidate.present, &candidate.value))
                        .collect::<Vec<_>>(),
                    before
                        .candidates
                        .iter()
                        .map(|candidate| (&candidate.dot, candidate.present, &candidate.value))
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    field.selected().map(|candidate| &candidate.value),
                    before.selected().map(|candidate| &candidate.value)
                );
            }
            for field in &row.positions {
                let before = original_live[id].position(&field.field).unwrap();
                assert_eq!(
                    field.selected().map(|candidate| &candidate.node),
                    before.selected().map(|candidate| &candidate.node)
                );
            }
            for set in &row.sets {
                assert_eq!(
                    set.values().unwrap(),
                    original_live[id].set(&set.field).unwrap().values().unwrap()
                );
            }
        }
        assert_eq!(
            state.ordered_records("position", "items", None).unwrap(),
            original_state
                .ordered_records("position", "items", None)
                .unwrap()
        );
        assert!(state.nodes.len() <= original_state.nodes.len());
        let compact_twice = compact.compact().unwrap();
        assert_eq!(
            compact.domain().baseline().unwrap().records,
            compact_twice.domain().baseline().unwrap().records
        );
        assert_eq!(
            compact.domain().baseline().unwrap().nodes,
            compact_twice.domain().baseline().unwrap().nodes
        );
        if let Some(record) = state.records.iter().find(|r| r.live()) {
            let mut edited = compact.clone();
            let tx = edited
                .prepare(
                    &"d".repeat(32),
                    vec![Operation::Assign {
                        record: record.id.clone(),
                        field: "title".into(),
                        present: true,
                        value: Some(SyncValue::text("after compaction")),
                    }],
                )
                .unwrap();
            edited.accept(tx).unwrap();
            assert_eq!(
                edited
                    .state()
                    .record(&record.id)
                    .unwrap()
                    .register("title")
                    .unwrap()
                    .candidates
                    .len(),
                1
            );
            assert_eq!(
                edited
                    .state()
                    .record(&record.id)
                    .unwrap()
                    .register("title")
                    .unwrap()
                    .selected()
                    .unwrap()
                    .value,
                Some(SyncValue::text("after compaction"))
            );
        }
    }
    assert!(
        history("delete-wins")
            .compact()
            .unwrap()
            .blobs()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn generations_prune_after_grace_and_stale_peer_preserves_local_edits_before_rebase() {
    let root = tempfile::tempdir().unwrap();
    let options = VerificationOptions::default();
    let original = history("exact-values");
    let objects = store(root.path(), "private-objects");
    let initial = snapshot(root.path(), "initial", &original, &objects);
    let repository = SyncRepository::create(
        root.path().join("cloud"),
        original.domain(),
        policy(),
        SyncLimits::default(),
    )
    .unwrap();
    let first = repository.publish_initial(&initial, &Notes, 100).unwrap();
    assert_wire_schema(&fs::read(repository.path().join("repository.json")).unwrap());
    assert_wire_schema(&canonical(&first).unwrap());
    let old_exchange = repository.exchange(&first).unwrap();
    let reopened = SyncRepository::open(
        repository.path(),
        repository.root_hash(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(reopened.current().unwrap(), first);
    let old_objects = store(root.path(), "old-objects");
    let (mut library, mut connection) =
        live(&initial, &root.path().join("old-library"), &old_objects);
    let old = repository
        .open_session(
            &mut library,
            &mut connection,
            old_objects,
            SessionOptions::new("7".repeat(32), "old peer"),
            &Notes,
        )
        .unwrap();
    let id = original
        .state()
        .records
        .iter()
        .find(|r| r.live())
        .unwrap()
        .id
        .clone();
    old.edit(
        &mut connection,
        vec![Operation::Assign {
            record: id.clone(),
            field: "title".into(),
            present: true,
            value: Some(SyncValue::text("months-old unpublished edit")),
        }],
        &Notes,
    )
    .unwrap();
    connection
        .execute(
            "UPDATE items SET local_note='private installation note' WHERE id=?1",
            [id.to_string()],
        )
        .unwrap();
    let second = repository
        .compact(&initial, &objects, &Notes, 101, &options)
        .unwrap();
    assert_eq!(
        repository.base_status(original.domain(), 105).unwrap(),
        BaseStatus::Superseded {
            retire_at: Counter(111)
        }
    );
    assert_eq!(
        old.publish_pending(&connection, &old_exchange)
            .unwrap_err()
            .code,
        "sync.generation_changed"
    );
    let checkpoint = repository.checkpoint(&second, &options).unwrap();
    assert_eq!(checkpoint.history().len(), 0);
    checkpoint.verify_projection(&Notes).unwrap();
    let third = repository
        .compact(&checkpoint, &objects, &Notes, 102, &options)
        .unwrap();
    assert!(
        repository
            .prune(109, &Notes, &options)
            .unwrap()
            .generations
            .is_empty()
    );
    let old_namespace = root.path().join("old-cloud-files");
    copy_tree(
        &repository.path().join("domains/00000000000000000000"),
        &old_namespace,
    );
    let removed = repository.prune(112, &Notes, &options).unwrap();
    assert_eq!(removed.generations, vec![first.id().unwrap()]);
    assert_eq!(repository.generations().unwrap().len(), 2);
    copy_tree(
        &old_namespace,
        &repository.path().join("domains/00000000000000000000"),
    );
    fs::write(
        repository.path().join(first.relative_path().unwrap()),
        canonical(&first).unwrap(),
    )
    .unwrap();
    assert_eq!(
        repository.prune(113, &Notes, &options).unwrap().generations,
        vec![first.id().unwrap()]
    );
    assert_eq!(repository.retired_before().unwrap(), Counter(1));
    assert!(
        !repository
            .path()
            .join("domains/00000000000000000000")
            .exists()
    );

    assert_eq!(repository.current().unwrap(), third);
    assert_eq!(
        repository.base_status(original.domain(), 112).unwrap(),
        BaseStatus::Expired
    );
    assert!(
        repository
            .prune(1000, &Notes, &options)
            .unwrap()
            .generations
            .is_empty()
    );
    let fresh_objects = store(root.path(), "fresh-objects");
    let destination = root.path().join("rebased-library");
    assert_eq!(
        repository
            .prepare_rebase(
                &old,
                &connection,
                RebaseTarget {
                    destination: &destination,
                    objects: &fresh_objects,
                    recovery_path: None
                },
                &Notes,
                &options
            )
            .err()
            .unwrap()
            .code,
        "sync.recovery_required"
    );
    assert!(!destination.exists());
    let recovery_path = root.path().join("recover-old.darkbox");
    let prepared = repository
        .prepare_rebase(
            &old,
            &connection,
            RebaseTarget {
                destination: &destination,
                objects: &fresh_objects,
                recovery_path: Some(&recovery_path),
            },
            &Notes,
            &options,
        )
        .unwrap();
    repository
        .check_prepared_rebase(&old, &connection, &prepared)
        .unwrap();
    assert_eq!(prepared.recovery, Some(recovery_path.clone()));
    let backup = SyncSnapshot::open(&recovery_path, SyncLimits::default(), &options).unwrap();
    backup.verify_projection(&Notes).unwrap();
    let mut bytes = Vec::new();
    backup
        .package()
        .resource(&format!("{PREFIX}/recovery/journal.json"))
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let journal: RecoveryJournal = decode(&bytes, MAX_BASELINE_BYTES).unwrap();
    assert_eq!(journal.outgoing.len(), 1);
    assert_wire_schema(&bytes);
    assert_eq!(
        backup
            .history()
            .state()
            .record(&id)
            .unwrap()
            .register("title")
            .unwrap()
            .selected()
            .unwrap()
            .value,
        Some(SyncValue::text("months-old unpublished edit"))
    );
    let current_connection =
        Connection::open(prepared.library.path().join("data/project.sqlite")).unwrap();
    let note: Option<String> = current_connection
        .query_row(
            "SELECT local_note FROM items WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(note.as_deref(), Some("private installation note"));
    let backup_note: Option<String> = backup
        .package()
        .database("data/project.sqlite")
        .unwrap()
        .connection()
        .query_row(
            "SELECT local_note FROM items WHERE id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(backup_note.as_deref(), Some("private installation note"));
    let current = repository.checkpoint(&third, &options).unwrap();
    Notes
        .verify(
            &current_connection,
            current.history().domain(),
            &current.history().state(),
        )
        .unwrap();
    assert!(old.working_path().exists());
    let incoming = old
        .history(&connection)
        .unwrap()
        .prepare(
            &"e".repeat(32),
            vec![Operation::Create {
                collection: "items".into(),
            }],
        )
        .unwrap();
    old.receive(&mut connection, &incoming.bytes().unwrap())
        .unwrap();
    assert_eq!(
        repository
            .check_prepared_rebase(&old, &connection, &prepared)
            .unwrap_err()
            .code,
        "sync.revision_changed"
    );

    old.edit(
        &mut connection,
        vec![Operation::Assign {
            record: id,
            field: "title".into(),
            present: true,
            value: Some(SyncValue::text("edited after preparation")),
        }],
        &Notes,
    )
    .unwrap();
    assert_eq!(
        repository
            .check_prepared_rebase(&old, &connection, &prepared)
            .unwrap_err()
            .code,
        "sync.revision_changed"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination.join(entry.file_name()));
        } else {
            fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
        }
    }
}
#[test]
fn concurrent_compactions_stop_pruning_and_require_archived_explicit_resolution() {
    let root = tempfile::tempdir().unwrap();
    let options = VerificationOptions::default();
    let original = history("concurrent-values-and-moves");
    let objects = store(root.path(), "objects");
    let initial = snapshot(root.path(), "initial", &original, &objects);
    let repository = SyncRepository::create(
        root.path().join("cloud-a"),
        original.domain(),
        policy(),
        SyncLimits::default(),
    )
    .unwrap();
    repository.publish_initial(&initial, &Notes, 1).unwrap();
    copy_tree(repository.path(), &root.path().join("cloud-b"));
    let other = SyncRepository::open(
        root.path().join("cloud-b"),
        repository.root_hash(),
        SyncLimits::default(),
    )
    .unwrap();
    let a = repository
        .compact(&initial, &objects, &Notes, 2, &options)
        .unwrap();
    let b = other
        .compact(&initial, &objects, &Notes, 3, &options)
        .unwrap();
    copy_tree(other.path(), repository.path());
    assert_eq!(
        repository.current().unwrap_err().code,
        "sync.generation_conflict"
    );
    assert_eq!(
        repository.prune(100, &Notes, &options).unwrap_err().code,
        "sync.generation_conflict"
    );
    assert_eq!(repository.generations().unwrap().len(), 3);
    let selected = repository.checkpoint(&a, &options).unwrap();
    let archive = root.path().join("branch-recovery");
    let resolved = repository
        .resolve_with_checkpoint(
            &a,
            &selected,
            ResolutionTarget {
                objects: &objects,
                recovery_directory: &archive,
                now: 4,
            },
            &Notes,
            &options,
        )
        .unwrap();
    assert_eq!(repository.current().unwrap(), resolved);
    assert_wire_schema(&canonical(&resolved).unwrap());
    assert!(
        archive
            .join(format!("{}.darkbox", a.id().unwrap()))
            .exists()
    );
    assert!(
        archive
            .join(format!("{}.darkbox", b.id().unwrap()))
            .exists()
    );
    let kept = repository.checkpoint(&resolved, &options).unwrap();
    kept.verify_projection(&Notes).unwrap();
    let next = repository
        .compact(&kept, &objects, &Notes, 5, &options)
        .unwrap();
    let pruned = repository.prune(100, &Notes, &options).unwrap();
    assert_eq!(pruned.generations.len(), 3);
    assert_eq!(repository.current().unwrap(), next);
    for entry in fs::read_dir(archive).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "darkbox") {
            SyncSnapshot::open(path, SyncLimits::default(), &options)
                .unwrap()
                .verify_projection(&Notes)
                .unwrap();
        }
    }
}

#[test]
fn compact_seed_rejects_reused_event_identity_and_missing_bytes() {
    let source = history("concurrent-values-and-moves").compact().unwrap();
    let domain = source.domain();
    let mut malformed = serde_json::to_value(domain.baseline().unwrap()).unwrap();
    malformed["records"][0]["registers"][0]["candidates"][0]["dot"] =
        malformed["records"][0]["id"].clone();
    let mut root = domain.root().clone();
    let bytes = canonical(&malformed).unwrap();
    root.baseline.as_mut().unwrap().sha256 = sha256(&bytes);
    root.baseline.as_mut().unwrap().size = Counter(bytes.len() as u64);
    assert!(
        Domain::from_parts_with_baseline(
            &canonical(&root).unwrap(),
            &canonical(domain.mapping()).unwrap(),
            domain.profile(),
            Some(&bytes)
        )
        .is_err()
    );
    assert!(
        Domain::from_parts(
            &canonical(domain.root()).unwrap(),
            &canonical(domain.mapping()).unwrap(),
            domain.profile()
        )
        .is_err()
    );
}

#[test]
fn repeated_pruning_bounds_control_records_and_blocks_transient_cloud_rollback() {
    let root = tempfile::tempdir().unwrap();
    let options = VerificationOptions::default();
    let initial = history("exact-values");
    let objects = store(root.path(), "objects");
    let first_package = snapshot(root.path(), "initial", &initial, &objects);
    let repository = SyncRepository::create(
        root.path().join("cloud"),
        initial.domain(),
        policy(),
        SyncLimits::default(),
    )
    .unwrap();
    repository
        .publish_initial(&first_package, &Notes, 1)
        .unwrap();
    let mut source = first_package;
    let mut head = repository.current().unwrap();
    for iteration in 1..=6 {
        head = repository
            .compact(&source, &objects, &Notes, 1 + iteration * 20, &options)
            .unwrap();
        source = repository.checkpoint(&head, &options).unwrap();
        repository
            .prune(12 + iteration * 20, &Notes, &options)
            .unwrap();
        assert_eq!(repository.generations().unwrap().len(), 2);
        if repository.path().join("retention").exists() {
            assert!(
                fs::read_dir(repository.path().join("retention"))
                    .unwrap()
                    .count()
                    <= 1
            );
        }
        if repository.path().join("retention").exists() {
            for entry in fs::read_dir(repository.path().join("retention")).unwrap() {
                assert_wire_schema(&fs::read(entry.unwrap().path()).unwrap());
            }
        }
        assert_eq!(
            fs::read_dir(repository.path().join("domains"))
                .unwrap()
                .count(),
            2
        );
    }
    let missing = root.path().join("temporarily-missing.json");
    let control = repository.path().join(head.relative_path().unwrap());
    fs::rename(&control, &missing).unwrap();
    assert_eq!(repository.current().unwrap_err().code, "sync.pending_bytes");
    let reopened = SyncRepository::open(
        repository.path(),
        repository.root_hash(),
        SyncLimits::default(),
    )
    .unwrap();
    assert_eq!(reopened.current().unwrap_err().code, "sync.pending_bytes");
    fs::rename(missing, control).unwrap();
    assert_eq!(reopened.current().unwrap(), head);
    assert_eq!(
        repository.prune(1, &Notes, &options).unwrap_err().code,
        "sync.retention_clock"
    );
}

#[test]
fn deletion_does_not_follow_links_and_opening_missing_repositories_is_read_only() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing");
    assert!(SyncRepository::open(&missing, &"0".repeat(64), SyncLimits::default()).is_err());
    assert!(!missing.exists());
    #[cfg(unix)]
    {
        let options = VerificationOptions::default();
        let initial = history("exact-values");
        let objects = store(root.path(), "objects");
        let original = snapshot(root.path(), "initial", &initial, &objects);
        let repository = SyncRepository::create(
            root.path().join("cloud"),
            initial.domain(),
            policy(),
            SyncLimits::default(),
        )
        .unwrap();
        repository.publish_initial(&original, &Notes, 1).unwrap();
        let middle = repository
            .compact(&original, &objects, &Notes, 2, &options)
            .unwrap();
        let source = repository.checkpoint(&middle, &options).unwrap();
        repository
            .compact(&source, &objects, &Notes, 3, &options)
            .unwrap();
        let external = root.path().join("precious.bin");
        fs::write(&external, b"keep this data").unwrap();
        std::os::unix::fs::symlink(
            &external,
            repository.path().join("domains/00000000000000000000/link"),
        )
        .unwrap();
        assert!(repository.prune(100, &Notes, &options).is_err());
        assert_eq!(fs::read(external).unwrap(), b"keep this data");
    }
}

#[test]
fn partial_generation_packages_wait_without_authorizing_pruning() {
    let root = tempfile::tempdir().unwrap();
    let options = VerificationOptions::default();
    let history = history("exact-values");
    let objects = store(root.path(), "objects");
    let source = snapshot(root.path(), "initial", &history, &objects);
    let repository = SyncRepository::create(
        root.path().join("cloud"),
        history.domain(),
        policy(),
        SyncLimits::default(),
    )
    .unwrap();
    let generation = repository.publish_initial(&source, &Notes, 1).unwrap();
    let path = repository.path().join(format!(
        "domains/{:020}/{}/{}",
        generation.ordinal.0, generation.checkpoint.sync_id, generation.checkpoint.package.path
    ));
    let bytes = fs::read(&path).unwrap();
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert_eq!(
        repository
            .checkpoint(&generation, &options)
            .err()
            .unwrap()
            .code,
        "sync.pending_bytes"
    );
    assert_eq!(
        repository.prune(100, &Notes, &options).unwrap_err().code,
        "sync.pending_bytes"
    );
    fs::write(&path, bytes).unwrap();
    repository.checkpoint(&generation, &options).unwrap();
}

#[test]
fn insertion_between_compacted_nodes_uses_a_clock_above_the_seed() {
    let original = history("concurrent-values-and-moves");
    let mut compact = original.compact().unwrap();
    let state = compact.state();
    let before = state.ordered_records("position", "items", None).unwrap();
    assert!(before.len() >= 2);
    let anchor = state
        .record(&before[0])
        .unwrap()
        .position("position")
        .unwrap()
        .selected()
        .unwrap()
        .node
        .clone();
    let record = Dot {
        replica_id: "f".repeat(32),
        sequence: Counter(1),
        index: Counter(0),
    };
    let transaction = compact
        .prepare(
            &record.replica_id,
            vec![
                Operation::Create {
                    collection: "items".into(),
                },
                Operation::Place {
                    record: record.clone(),
                    field: "position".into(),
                    sequence: "items".into(),
                    owner: None,
                    after: anchor,
                },
            ],
        )
        .unwrap();
    compact.accept(transaction).unwrap();
    let after = compact
        .state()
        .ordered_records("position", "items", None)
        .unwrap();
    assert_eq!(&after[..2], &[before[0].clone(), record]);
    assert_eq!(&after[2..], &before[1..]);
}
