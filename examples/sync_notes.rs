//! Two offline peers, retained conflicts and a third peer bootstrapped from a checkpoint.
#[path = "support/sync_notes.rs"]
mod notes;
use darkbox::{
    ManifestBuilder, VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    sync::*,
};
use notes::Notes;
use rusqlite::Connection;
use std::{fs, path::PathBuf};

fn manifest(domain: &Domain) -> Result<serde_json::Value, darkbox::Error> {
    ManifestBuilder::new("1.5.0", "org.example.sync-notes", "1")?
        .package_id(&domain.root().package_id)
        .folder("data", "Authoritative application state")
        .database(DatabaseDeclaration {
            path: "data/project.sqlite".into(),
            description: "Notes and retained conflict records".into(),
            user_version: None,
            tables: ["items", "item_conflicts"]
                .into_iter()
                .map(|name| TableDeclaration {
                    name: name.into(),
                    description: "Documented application state".into(),
                })
                .collect(),
        })
        .build()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args_os().nth(1) else {
        println!("Usage: cargo run --example sync_notes -- /absolute/new-demo-directory");
        return Ok(());
    };
    let root = PathBuf::from(path);
    fs::create_dir(&root)?;
    let mut limits = SyncLimits::default();
    let staging = root.join("staging");
    fs::create_dir(&staging)?;
    limits.io.staging_directory = Some(staging);
    let domain = Domain::generate(notes::mapping(), notes::profile())?;
    let origin = random_id()?;
    let record = Dot {
        replica_id: origin.clone(),
        sequence: Counter(1),
        index: Counter(0),
    };
    let mut initial = History::new(domain.clone(), limits.clone());
    let seed = initial.prepare(
        &origin,
        vec![
            Operation::Create {
                collection: "items".into(),
            },
            Operation::Assign {
                record: record.clone(),
                field: "title".into(),
                present: true,
                value: Some(SyncValue::text("initial title")),
            },
        ],
    )?;
    initial.accept(seed)?;
    let options = VerificationOptions::default();
    let initial_path = root.join("initial.darkbox");
    let objects_a = ObjectStore::open(root.join("objects-a"), limits.clone())?;
    SnapshotBuilder::new(
        &initial_path,
        manifest(&domain)?,
        &initial,
        &objects_a,
        &Notes,
        limits.io.clone(),
        &options,
    )?
    .finish()?;
    let checkpoint = SyncSnapshot::open(&initial_path, limits.clone(), &options)?;
    let objects_b = ObjectStore::open(root.join("objects-b"), limits.clone())?;
    let mut a = checkpoint.bootstrap(root.join("library-a"), &objects_a, &Notes)?;
    let mut b = checkpoint.bootstrap(root.join("library-b"), &objects_b, &Notes)?;
    let mut ca = Connection::open(a.path().join("data/project.sqlite"))?;
    let mut cb = Connection::open(b.path().join("data/project.sqlite"))?;
    ca.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")?;
    cb.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;")?;
    let repository = SyncRepository::create(
        root.join("exchange"),
        &domain,
        RetentionPolicy::default(),
        limits.clone(),
    )?;
    let generation = repository.publish_initial(&checkpoint, &Notes, 100)?;
    let session_options = |label: &str| -> Result<SessionOptions, darkbox::Error> {
        Ok(SessionOptions {
            device_id: random_id()?,
            label: label.into(),
            limits: limits.clone(),
        })
    };
    let sa =
        repository.open_session(&mut a, &mut ca, objects_a, session_options("PC A")?, &Notes)?;
    let sb =
        repository.open_session(&mut b, &mut cb, objects_b, session_options("PC B")?, &Notes)?;
    let change = |title: &str| Operation::Assign {
        record: record.clone(),
        field: "title".into(),
        present: true,
        value: Some(SyncValue::text(title)),
    };
    sa.edit(&mut ca, vec![change("offline edit from A")], &Notes)?;
    sb.edit(&mut cb, vec![change("offline edit from B")], &Notes)?;
    let exchange = repository.exchange(&generation)?;
    sa.publish_pending(&ca, &exchange)?;
    sb.publish_pending(&cb, &exchange)?;
    sa.receive_exchange(&mut ca, &exchange)?;
    sb.receive_exchange(&mut cb, &exchange)?;
    sa.apply_ready(&mut ca, &Notes)?;
    sb.apply_ready(&mut cb, &Notes)?;
    let state = sa.history(&ca)?.state();
    assert_eq!(state, sb.history(&cb)?.state());
    let competing = state
        .record(&record)
        .and_then(|r| r.register("title"))
        .expect("Created title");
    assert!(competing.conflicted());
    let full_path = root.join("complete.darkbox");
    SnapshotBuilder::new(
        &full_path,
        manifest(&domain)?,
        &sa.history(&ca)?,
        sa.objects(),
        &Notes,
        limits.io.clone(),
        &options,
    )?
    .finish()?;
    let full = SyncSnapshot::open(&full_path, limits.clone(), &options)?;
    full.publish(&exchange, sa.replica())?;
    let compact = repository.compact(&full, sa.objects(), &Notes, 110, &options)?;
    let compact_snapshot = repository.checkpoint(&compact, &options)?;
    let next = repository.compact(&compact_snapshot, sa.objects(), &Notes, 120, &options)?;
    repository.prune(3_000_000, &Notes, &options)?;
    sb.edit(
        &mut cb,
        vec![change("late offline edit retained for recovery")],
        &Notes,
    )?;
    let rebased_objects = ObjectStore::open(root.join("objects-b-rebased"), limits.clone())?;
    let rebased_path = root.join("library-b-rebased");
    let recovery_path = root.join("old-b-recovery.darkbox");
    let prepared = repository.prepare_rebase(
        &sb,
        &cb,
        RebaseTarget {
            destination: &rebased_path,
            objects: &rebased_objects,
            recovery_path: Some(&recovery_path),
        },
        &Notes,
        &options,
    )?;
    repository.check_prepared_rebase(&sb, &cb, &prepared)?;
    let full = repository.checkpoint(&next, &options)?;
    let objects_c = ObjectStore::open(root.join("objects-c"), limits)?;
    let c = full.bootstrap(root.join("library-c"), &objects_c, &Notes)?;
    let cc = Connection::open(c.path().join("data/project.sqlite"))?;
    Notes.verify(&cc, full.history().domain(), &full.history().state())?;
    println!(
        "Two peers converged with both title alternatives retained. Compact generations were pruned, a stale peer produced a private recovery package, and a third peer bootstrapped from the compact checkpoint."
    );
    println!("Example files: {}", root.display());
    Ok(())
}
