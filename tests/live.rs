use darkbox::{
    DirectoryLibrary, Limits, ManifestBuilder, Status, TrustedDigests, VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    rusqlite::Connection,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Read, path::Path};

const DB: &str = "data/library.sqlite";
struct Fixture {
    dir: tempfile::TempDir,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let manifest = ManifestBuilder::new("1.3.0", "org.example.live", "1")
            .unwrap()
            .package_id("00112233445566778899aabbccddeeff")
            .resource_inventory()
            .folder("data", "Database")
            .folder("media", "Immutable objects")
            .database(DatabaseDeclaration {
                path: DB.into(),
                description: "Records".into(),
                user_version: Some(1),
                tables: vec![TableDeclaration {
                    name: "items".into(),
                    description: "Records".into(),
                }],
            })
            .build()
            .unwrap();
        Self {
            dir: tempfile::tempdir().unwrap(),
            manifest,
        }
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.dir.path().join(name)
    }
    fn initialize(&self) -> (DirectoryLibrary, Connection) {
        let library = DirectoryLibrary::initialize(self.path("library"), self.manifest.clone(), "# org.example.live format 1\nitems(id INTEGER PRIMARY KEY, text TEXT) stores records. media contains immutable objects.\n", Limits::default()).unwrap();
        let connection = Connection::open(library.path().join(DB)).unwrap();
        connection.execute_batch("PRAGMA user_version=1; CREATE TABLE items(id INTEGER PRIMARY KEY, text TEXT); INSERT INTO items VALUES(1,'first');").unwrap();
        fs::write(library.path().join("media/item.mp4"), b"immutable media").unwrap();
        (library, connection)
    }
    fn sealed(&self) {
        let (library, db) = self.initialize();
        drop(db);
        let report = library
            .seal(
                self.manifest.clone(),
                Limits::default(),
                &VerificationOptions::default(),
            )
            .unwrap();
        assert_eq!(report.status, Status::Passed);
        assert_eq!(report.scope, "common_machine_checks");
        assert!(report.trusted_resources.is_empty());
    }
}
struct Cache;
impl TrustedDigests for Cache {
    fn sha256(&self, path: &str, _: u64) -> Option<String> {
        (path == "media/item.mp4").then(|| format!("{:x}", Sha256::digest(b"immutable media")))
    }
}
fn assert_passed(path: &Path) {
    let report = darkbox::verify(path);
    assert_eq!(report.status, Status::Passed, "{:?}", report.diagnostics);
}

#[test]
fn initialize_lock_seal_and_reopen_without_intermediate_zip() {
    let f = Fixture::new();
    let (library, db) = f.initialize();
    let lock_path = library.lock_path().unwrap();
    assert!(lock_path.exists());
    assert_eq!(
        lock_path.parent(),
        Some(fs::canonicalize(f.dir.path()).unwrap().as_path())
    );
    assert_eq!(darkbox::verify(library.path()).status, Status::NotQuiescent);
    assert!(DirectoryLibrary::open(library.path()).is_err());
    let error = darkbox::pack(
        library.path(),
        f.path("busy.zip"),
        Limits::default(),
        &VerificationOptions::default(),
    )
    .unwrap_err();
    assert_eq!(error.status, Status::NotQuiescent);
    assert!(!f.path("busy.zip").exists());
    drop(db);
    library
        .seal(
            f.manifest.clone(),
            Limits::default(),
            &VerificationOptions::default(),
        )
        .unwrap();
    assert_passed(&f.path("library"));
    assert!(lock_path.exists());
    let library = DirectoryLibrary::open(f.path("library")).unwrap();
    drop(library);
    darkbox::pack(
        f.path("library"),
        f.path("sealed.zip"),
        Limits::default(),
        &VerificationOptions::default(),
    )
    .unwrap();
    let mut zip = zip::ZipArchive::new(fs::File::open(f.path("sealed.zip")).unwrap()).unwrap();
    for i in 0..zip.len() {
        assert!(!zip.by_index(i).unwrap().name().ends_with(".lock"));
    }
}

#[test]
fn sidecars_and_wal_headers_are_not_corruption_and_are_never_recovered() {
    let f = Fixture::new();
    f.sealed();
    for suffix in ["-wal", "-shm", "-journal", "-mj123"] {
        let path = f.path("library").join(format!("{DB}{suffix}"));
        fs::write(&path, b"interrupted").unwrap();
        let report = darkbox::verify(f.path("library"));
        assert_eq!(report.status, Status::NotQuiescent);
        assert_eq!(report.status.exit_code(), 6);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.code == "directory.not_quiescent")
        );
        assert_eq!(fs::read(&path).unwrap(), b"interrupted");
        fs::remove_file(path).unwrap();
    }
    let path = f.path("library").join(DB);
    let mut bytes = fs::read(&path).unwrap();
    bytes[18] = 2;
    bytes[19] = 2;
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        darkbox::verify(f.path("library")).status,
        Status::NotQuiescent
    );
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn hot_wal_backup_and_direct_delta_capture_committed_state() {
    let f = Fixture::new();
    f.sealed();
    let options = VerificationOptions::default();
    darkbox::pack(
        f.path("library"),
        f.path("base.zip"),
        Limits::default(),
        &options,
    )
    .unwrap();
    let mut library = DirectoryLibrary::open(f.path("library")).unwrap();
    let db = Connection::open(library.path().join(DB)).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; INSERT INTO items VALUES(2,'hot');")
        .unwrap();
    assert!(library.path().join(format!("{DB}-wal")).exists());
    let connections = BTreeMap::from([(DB.to_owned(), &db)]);
    let before = fs::read(library.path().join("manifest.json")).unwrap();
    library
        .hot_backup(
            f.path("hot.zip"),
            f.manifest.clone(),
            &connections,
            Limits::default(),
            &options,
        )
        .unwrap();
    assert_passed(&f.path("hot.zip"));
    let report = library
        .create_delta(
            f.path("base.zip"),
            f.path("hot.delta"),
            f.manifest.clone(),
            &connections,
            Limits::default(),
            &VerificationOptions {
                trusted_digests: Some(&Cache),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(report.trusted_resources.len(), 1);
    assert!(library.path().join(format!("{DB}-wal")).exists());
    assert_eq!(
        fs::read(library.path().join("manifest.json")).unwrap(),
        before
    );
    darkbox::merge(
        f.path("base.zip"),
        f.path("hot.delta"),
        f.path("merged.zip"),
        Limits::default(),
        &options,
    )
    .unwrap();
    assert_passed(&f.path("merged.zip"));
    let mut delta = zip::ZipArchive::new(fs::File::open(f.path("hot.delta")).unwrap()).unwrap();
    let mut descriptor = String::new();
    delta
        .by_name("delta.json")
        .unwrap()
        .read_to_string(&mut descriptor)
        .unwrap();
    let descriptor: Value = serde_json::from_str(&descriptor).unwrap();
    assert!(
        !descriptor["changed"]
            .as_array()
            .unwrap()
            .contains(&json!("media/item.mp4"))
    );
    assert!(
        descriptor["changed"]
            .as_array()
            .unwrap()
            .contains(&json!(DB))
    );
    darkbox::unpack(
        f.path("merged.zip"),
        f.path("restored"),
        Limits::default(),
        &options,
    )
    .unwrap();
    let restored = Connection::open(f.path("restored").join(DB)).unwrap();
    assert_eq!(
        restored
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        restored
            .query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "delete"
    );
}

#[test]
fn cached_checks_are_explicit_and_full_verification_remains_available() {
    let f = Fixture::new();
    f.sealed();
    let report = darkbox::analyze_with(
        f.path("library"),
        darkbox::Mode::Verify,
        Limits::default(),
        &VerificationOptions {
            trusted_digests: Some(&Cache),
            ..Default::default()
        },
    );
    assert_eq!(report.status, Status::Passed);
    assert_eq!(report.scope, "common_checks_with_trusted_resources");
    assert_eq!(report.trusted_resources.len(), 1);
    fs::write(f.path("library/media/item.mp4"), b"corrupted media").unwrap();
    assert_eq!(darkbox::verify(f.path("library")).status, Status::Invalid);
    let mut library = DirectoryLibrary::open(f.path("library")).unwrap();
    // Even an incorrect trusted hash cannot publish changed bytes into a ZIP.
    let db = Connection::open(library.path().join(DB)).unwrap();
    let error = library
        .hot_backup(
            f.path("bad.zip"),
            f.manifest.clone(),
            &BTreeMap::from([(DB.to_owned(), &db)]),
            Limits::default(),
            &VerificationOptions {
                trusted_digests: Some(&Cache),
                ..Default::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "transfer.changed");
    assert!(!f.path("bad.zip").exists());
}

#[test]
fn failed_seal_is_transactional_and_requires_complete_connection_set() {
    let f = Fixture::new();
    f.sealed();
    let mut library = DirectoryLibrary::open(f.path("library")).unwrap();
    let before = fs::read(library.path().join("manifest.json")).unwrap();
    let error = library
        .hot_backup(
            f.path("bad.zip"),
            f.manifest.clone(),
            &BTreeMap::new(),
            Limits::default(),
            &VerificationOptions::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, "directory.databases");
    fs::write(library.path().join(DB), b"broken").unwrap();
    assert!(
        library
            .seal(
                f.manifest.clone(),
                Limits::default(),
                &VerificationOptions::default()
            )
            .is_err()
    );
    assert_eq!(fs::read(f.path("library/manifest.json")).unwrap(), before);
    assert!(!f.path("bad.zip").exists());
}

#[cfg(feature = "cli")]
#[test]
fn cli_reports_busy_with_separate_exit_code() {
    let f = Fixture::new();
    f.sealed();
    let _library = DirectoryLibrary::open(f.path("library")).unwrap();
    for command in ["verify", "inspect"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_darkbox"))
            .args([command, f.path("library").to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(6));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], "not_quiescent");
    }
}

#[test]
fn shared_readers_block_writers_and_aliases_share_one_lock() {
    let f = Fixture::new();
    f.sealed();
    let library = DirectoryLibrary::open(f.path("library")).unwrap();
    let path = library.lock_path().unwrap();
    drop(library);
    let first = fs::File::open(&path).unwrap();
    let second = fs::File::open(&path).unwrap();
    fs2::FileExt::try_lock_shared(&first).unwrap();
    fs2::FileExt::try_lock_shared(&second).unwrap();
    assert_passed(&f.path("library"));
    assert!(DirectoryLibrary::open(f.path("library")).is_err());
    drop(first);
    drop(second);
    let library = DirectoryLibrary::open(f.path("library")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(f.dir.path(), f.path("alias")).unwrap();
        assert_eq!(
            darkbox::verify(f.path("alias/library")).status,
            Status::NotQuiescent
        );
    }
    drop(library);
    assert_passed(&f.path("library"));
}

#[test]
fn metadata_cannot_use_cached_hashes_and_staging_stays_outside_library() {
    struct All;
    impl TrustedDigests for All {
        fn sha256(&self, _: &str, _: u64) -> Option<String> {
            Some("0".repeat(64))
        }
    }
    let f = Fixture::new();
    f.sealed();
    fs::write(f.path("library/README.md"), b"broken canonical bytes").unwrap();
    let options = VerificationOptions {
        trusted_digests: Some(&All),
        ..Default::default()
    };
    let report = darkbox::analyze_with(
        f.path("library"),
        darkbox::Mode::Verify,
        Limits::default(),
        &options,
    );
    assert_eq!(report.status, Status::Invalid);
    assert!(report.diagnostics.iter().any(|d| d.code == "bundle.file"));
    let library = DirectoryLibrary::open(f.path("library")).unwrap();
    let error = library
        .seal(
            f.manifest.clone(),
            Limits {
                staging_directory: Some(f.path("library")),
                ..Default::default()
            },
            &VerificationOptions::default(),
        )
        .unwrap_err();
    assert_eq!(error.code, "directory.staging");
}

#[test]
fn cached_seal_can_handle_a_sparse_four_gib_resource_without_reading_it_all() {
    struct Sparse;
    impl TrustedDigests for Sparse {
        fn sha256(&self, path: &str, _: u64) -> Option<String> {
            (path == "media/item.mp4").then(|| "0".repeat(64))
        }
    }
    let f = Fixture::new();
    let (library, db) = f.initialize();
    drop(db);
    fs::OpenOptions::new()
        .write(true)
        .open(library.path().join("media/item.mp4"))
        .unwrap()
        .set_len(4 * 1024 * 1024 * 1024)
        .unwrap();
    // Artificial cache value exercises the trust boundary, never a full-byte claim.
    let report = library
        .seal(
            f.manifest.clone(),
            Limits {
                timeout_seconds: 10,
                ..Limits::large()
            },
            &VerificationOptions {
                trusted_digests: Some(&Sparse),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(report.scope, "common_checks_with_trusted_resources");
    assert_eq!(report.trusted_resources[0].size, 4 * 1024 * 1024 * 1024);
    assert!(!report.checks.contains(&"directory.bytes"));
}

#[test]
fn delta_base_directory_is_fully_read_even_when_target_cache_is_enabled() {
    let f = Fixture::new();
    f.sealed();
    let options = VerificationOptions::default();
    darkbox::pack(
        f.path("library"),
        f.path("base.zip"),
        Limits::default(),
        &options,
    )
    .unwrap();
    darkbox::unpack(
        f.path("base.zip"),
        f.path("target"),
        Limits::default(),
        &options,
    )
    .unwrap();
    fs::write(f.path("library/media/item.mp4"), b"corrupted media").unwrap();
    let error = darkbox::create_delta(
        f.path("library"),
        f.path("target"),
        f.path("bad.delta"),
        Limits::default(),
        &VerificationOptions {
            trusted_digests: Some(&Cache),
            ..Default::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.status, Status::Invalid);
    assert!(!f.path("bad.delta").exists());
}
