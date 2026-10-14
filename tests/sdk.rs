use darkbox::rusqlite::{Connection, params};
use darkbox::serde_json::{Value, json};
use darkbox::zeroize::Zeroizing;
use darkbox::{
    ApplicationProfile, DiagnosticPackage, Limits, ManifestBuilder, Package, PackageEditor,
    PackageWriter, ProfileContext, Status, VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    protection::{
        self, Ed25519Signer, KeyRing, ManifestSigner, NonceSequence, ProtectionData,
        SignatureDeclaration, SqliteProtection,
    },
};
use std::{
    fs,
    io::{self, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

const DATABASE: &str = "data/project.sqlite";
struct Nonces(u32);
impl NonceSequence for Nonces {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
        self.0 += 1;
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }
}
fn declaration() -> DatabaseDeclaration {
    DatabaseDeclaration {
        path: DATABASE.into(),
        description: "Application database".into(),
        user_version: Some(1),
        tables: vec![TableDeclaration {
            name: "notes".into(),
            description: "Public labels and optional protected values".into(),
        }],
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    keys: KeyRing,
    signer: Ed25519Signer,
}
impl Fixture {
    fn new() -> Self {
        let mut keys = KeyRing::default();
        keys.insert("test-key", Zeroizing::new([42; 32]));
        Self {
            directory: tempfile::Builder::new()
                .prefix("darkbox-sdk-tests-")
                .tempdir()
                .unwrap(),
            keys,
            signer: Ed25519Signer::from_seed("test-signer", Zeroizing::new([7; 32])),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
    fn options(&self, keyed: bool) -> VerificationOptions<'_> {
        let mut options = VerificationOptions::default();
        options
            .trusted_signers
            .insert("test-signer".into(), self.signer.public_key());
        if keyed {
            options.decryption_keys = Some(&self.keys);
        }
        options
    }
    fn editor(&self, protected: bool, version: &str) -> PackageEditor {
        let mut builder = ManifestBuilder::new(version, "org.example.sdk", "1")
            .unwrap()
            .folder("data", "SQLite snapshots")
            .folder("assets", "Attachments")
            .database(declaration());
        if protected {
            builder = builder.protection(ProtectionData {
                package_id: "00112233445566778899aabbccddeeff".into(),
                signature: SignatureDeclaration {
                    algorithm: "Ed25519".into(),
                    signer_id: "test-signer".into(),
                    path: protection::SIGNATURE_PATH.into(),
                },
                inventory: vec![],
                files: vec![],
                sqlite: vec![SqliteProtection {
                    database: DATABASE.into(),
                    table: "notes".into(),
                    column: "secret".into(),
                    record_id_column: "id".into(),
                    key_id: "test-key".into(),
                }],
            });
        }
        let mut editor = PackageEditor::new(builder.build().unwrap(), Limits::default()).unwrap();
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY,label TEXT NOT NULL,secret BLOB); INSERT INTO notes VALUES('r1','Public',NULL);").unwrap();
        editor.put_database(declaration(), &connection).unwrap();
        editor.put_reader("docs/profile.md",Cursor::new(b"# org.example.sdk, format 1\n\nnotes.id is stable unique TEXT, label is public TEXT and secret is NULL or a protected opaque byte string.\n")).unwrap();
        editor
            .put_reader("assets/public.bin", Cursor::new(b"Public attachment"))
            .unwrap();
        if protected {
            let mut nonces = Nonces(0);
            editor
                .put_encrypted(
                    "assets/private.bin",
                    b"Private file",
                    "test-key",
                    &self.keys,
                    &mut nonces,
                )
                .unwrap();
            editor
                .put_encrypted_value(
                    darkbox::ValueAddress::new(DATABASE, "notes", "secret", "r1"),
                    b"Private value",
                    &self.keys,
                    &mut nonces,
                )
                .unwrap();
        }
        editor
    }
    fn package(&self, protected: bool) -> Package {
        self.editor(protected, "1.1.0")
            .save_as(
                self.path("original.project"),
                &self.options(true),
                Some(&self.signer),
            )
            .unwrap()
    }
}
fn bytes(mut reader: impl Read) -> Vec<u8> {
    let mut result = Vec::new();
    reader.read_to_end(&mut result).unwrap();
    result
}
fn label(package: &Package) -> String {
    package
        .database(DATABASE)
        .unwrap()
        .connection()
        .query_row("SELECT label FROM notes WHERE id='r1'", [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn complete_public_lifecycle_supports_both_common_versions_and_reader_inputs() {
    for version in ["1.0.0", "1.1.0"] {
        let fixture = Fixture::new();
        let mut editor = fixture.editor(false, version);
        let original = editor
            .save_as(
                fixture.path("original.project"),
                &fixture.options(false),
                None,
            )
            .unwrap();
        assert!(!editor.is_dirty());
        assert_eq!(label(&original), "Public");
        editor.add_folder("assets/nested", "New folder").unwrap();
        editor
            .put_reader("assets/nested/new.txt", Cursor::new(b"New attachment"))
            .unwrap();
        editor
            .rename_resource("assets/public.bin", "assets/renamed.bin")
            .unwrap();
        editor
            .edit_database(DATABASE, |tx| {
                tx.execute("UPDATE notes SET label=?1 WHERE id='r1'", ["Edited"])
                    .map_err(|_| darkbox::Error::invalid("test.sql", "SQL failed"))?;
                Ok(())
            })
            .unwrap();
        let saved = editor.save(&fixture.options(false), None).unwrap();
        assert_eq!(label(&saved), "Edited");
        assert_eq!(label(&original), "Public");
        assert_eq!(
            bytes(saved.resource("assets/renamed.bin").unwrap()),
            b"Public attachment"
        );
        editor.remove_resource("assets/nested/new.txt").unwrap();
        editor.remove_folder("assets/nested").unwrap();
        let copy = editor
            .save_as(fixture.path("copy.project"), &fixture.options(false), None)
            .unwrap();
        let resolved_copy = fs::canonicalize(fixture.path("copy.project")).unwrap();
        assert_eq!(copy.path(), Some(resolved_copy.as_path()));
        assert!(copy.resource("assets/nested/new.txt").is_err());
        let mut archive = Vec::new();
        copy.copy_to(&mut archive).unwrap();
        assert_eq!(archive, fs::read(fixture.path("copy.project")).unwrap());
        let imported = Package::from_reader(
            Cursor::new(archive),
            Limits::default(),
            &fixture.options(false),
        )
        .unwrap();
        assert!(imported.path().is_none());
        let mut detached = imported.edit();
        assert_eq!(
            detached
                .save(&fixture.options(false), None)
                .err()
                .unwrap()
                .code,
            "package.destination"
        );
        assert_eq!(
            label(
                &detached
                    .save_as(
                        fixture.path("imported.project"),
                        &fixture.options(false),
                        None
                    )
                    .unwrap()
            ),
            "Edited"
        );
        assert_eq!(
            Package::open(
                fixture.path("imported.project"),
                Limits::default(),
                &fixture.options(false)
            )
            .unwrap()
            .manifest()["darkbox"]["version"],
            version
        );
    }
}

#[test]
fn streams_and_database_guards_own_their_snapshots_and_exports_never_clobber() {
    let fixture = Fixture::new();
    let package = fixture.package(false);
    let mut reader = package.resource("assets/public.bin").unwrap();
    let db = package.database(DATABASE).unwrap();
    assert!(
        db.connection()
            .execute_batch("PRAGMA query_only=OFF; UPDATE notes SET label='Forbidden'")
            .is_err()
    );
    let target = fixture.path("export.bin");
    package
        .export_resource("assets/public.bin", &target)
        .unwrap();
    assert!(
        package
            .export_resource("assets/public.bin", &target)
            .is_err()
    );
    assert_eq!(fs::read(&target).unwrap(), b"Public attachment");
    fs::write(fixture.path("original.project"), b"Changed source").unwrap();
    drop(package);
    reader.seek(SeekFrom::Start(7)).unwrap();
    assert_eq!(bytes(reader), b"attachment");
    assert_eq!(
        db.connection()
            .query_row("SELECT label FROM notes", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "Public"
    );
}

#[test]
fn protected_locked_editions_can_be_saved_and_copied_without_decryption_keys() {
    let fixture = Fixture::new();
    let package = fixture.package(true);
    let original = bytes(package.resource("assets/private.bin").unwrap());
    let locked = Package::open(
        fixture.path("original.project"),
        Limits::default(),
        &fixture.options(false),
    )
    .unwrap();
    assert!(
        locked
            .report()
            .protection
            .as_ref()
            .unwrap()
            .encrypted
            .iter()
            .all(|item| item.authentication == "key_absent")
    );
    let mut editor = locked.edit();
    editor
        .edit_database(DATABASE, |tx| {
            tx.execute("UPDATE notes SET label='New public label'", [])
                .map_err(|_| darkbox::Error::invalid("test.sql", "SQL failed"))?;
            Ok(())
        })
        .unwrap();
    let copy = editor
        .save_as(
            fixture.path("locked-copy.project"),
            &fixture.options(false),
            Some(&fixture.signer),
        )
        .unwrap();
    assert_eq!(
        bytes(copy.resource("assets/private.bin").unwrap()),
        original
    );
    assert_eq!(
        &*copy
            .decrypt_resource("assets/private.bin", &fixture.keys)
            .unwrap(),
        b"Private file"
    );
    assert_eq!(
        &*copy
            .decrypt_value(DATABASE, "notes", "secret", "r1", &fixture.keys)
            .unwrap()
            .unwrap(),
        b"Private value"
    );
    editor
        .save(&fixture.options(false), Some(&fixture.signer))
        .unwrap();
    assert!(editor.save(&fixture.options(false), None).is_err());
    assert_eq!(
        copy.decrypt_resource("assets/private.bin", &KeyRing::default())
            .err()
            .unwrap()
            .code,
        "protection.key_absent"
    );
}

#[test]
fn protected_edits_bind_new_paths_and_values_and_never_persist_plaintext() {
    let fixture = Fixture::new();
    let package = fixture.package(true);
    let mut editor = package.edit();
    let mut nonces = Nonces(100);
    assert_eq!(
        editor
            .rename_resource("assets/private.bin", "assets/moved.bin")
            .err()
            .unwrap()
            .code,
        "protection.context_changed"
    );
    editor
        .rename_encrypted(
            "assets/private.bin",
            "assets/moved.bin",
            &fixture.keys,
            &mut nonces,
        )
        .unwrap();
    editor
        .put_encrypted_value(
            darkbox::ValueAddress::new(DATABASE, "notes", "secret", "r1"),
            b"Updated secret value",
            &fixture.keys,
            &mut nonces,
        )
        .unwrap();
    assert_eq!(
        &*editor
            .decrypt_value(DATABASE, "notes", "secret", "r1", &fixture.keys)
            .unwrap()
            .unwrap(),
        b"Updated secret value"
    );
    assert!(
        !bytes(editor.resource(DATABASE).unwrap())
            .windows(b"Updated secret value".len())
            .any(|window| window == b"Updated secret value")
    );
    let before = fs::read(fixture.path("original.project")).unwrap();
    assert!(
        editor
            .save(&fixture.options(false), Some(&fixture.signer))
            .is_err()
    );
    assert_eq!(fs::read(fixture.path("original.project")).unwrap(), before);
    assert!(editor.is_dirty());
    let saved = editor
        .save(&fixture.options(true), Some(&fixture.signer))
        .unwrap();
    assert!(saved.resource("assets/private.bin").is_err());
    assert_eq!(
        &*saved
            .decrypt_resource("assets/moved.bin", &fixture.keys)
            .unwrap(),
        b"Private file"
    );
    assert_eq!(
        saved
            .report()
            .protection
            .as_ref()
            .unwrap()
            .encrypted
            .iter()
            .filter(|item| item.authentication == "verified")
            .count(),
        2
    );
    let mut wrong = KeyRing::default();
    wrong.insert("test-key", Zeroizing::new([99; 32]));
    assert_eq!(
        saved
            .decrypt_resource("assets/moved.bin", &wrong)
            .err()
            .unwrap()
            .code,
        "protection.authentication"
    );
    assert!(
        saved
            .decrypt_value(DATABASE, "notes", "secret", "missing", &fixture.keys)
            .is_err()
    );
}

#[test]
fn database_errors_reader_failures_metadata_errors_and_discard_preserve_staged_state() {
    let fixture = Fixture::new();
    let package = fixture.package(false);
    let mut editor = package.edit();
    let before = bytes(editor.resource(DATABASE).unwrap());
    let result = editor.edit_database(DATABASE, |tx| {
        tx.execute("UPDATE notes SET label='Temporary'", [])
            .unwrap();
        Err::<(), _>(darkbox::Error::invalid("test.abort", "Abort"))
    });
    assert!(result.is_err());
    assert_eq!(bytes(editor.resource(DATABASE).unwrap()), before);
    assert!(
        editor
            .edit_database(DATABASE, |tx| {
                tx.execute_batch("CREATE TABLE unexpected(id TEXT)")
                    .unwrap();
                Ok(())
            })
            .is_err()
    );
    assert_eq!(bytes(editor.resource(DATABASE).unwrap()), before);
    struct Broken(bool);
    impl Read for Broken {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("Reader failed"));
            }
            self.0 = true;
            output[..3].copy_from_slice(b"new");
            Ok(3)
        }
    }
    assert!(
        editor
            .put_reader("assets/public.bin", Broken(false))
            .is_err()
    );
    assert_eq!(
        bytes(editor.resource("assets/public.bin").unwrap()),
        b"Public attachment"
    );
    assert!(editor.remove_resource(DATABASE).is_err());
    assert!(editor.remove_resource("docs/profile.md").is_err());
    assert!(
        editor
            .put_reader("README.md", Cursor::new(b"Edited"))
            .is_err()
    );
    assert!(
        editor
            .put_reader("assets/PUBLIC.bin", Cursor::new(b"Collision"))
            .is_err()
    );
    assert!(
        editor
            .put_reader("undeclared/file", Cursor::new(b"File"))
            .is_err()
    );
    assert!(
        editor
            .update_manifest(|manifest| {
                manifest["application"]["id"] = json!("bad");
                Ok(())
            })
            .is_err()
    );
    assert_eq!(editor.manifest()["application"]["id"], "org.example.sdk");
    editor
        .put_reader("assets/public.bin", Cursor::new(b"Modified"))
        .unwrap();
    let fork = editor.clone();
    editor.discard_changes();
    assert!(!editor.is_dirty());
    assert_eq!(
        bytes(editor.resource("assets/public.bin").unwrap()),
        b"Public attachment"
    );
    assert_eq!(
        bytes(fork.resource("assets/public.bin").unwrap()),
        b"Modified"
    );
}

#[test]
fn coherent_snapshots_capture_committed_wal_data_and_schema_changes_are_explicit() {
    let fixture = Fixture::new();
    let mut editor = fixture.editor(false, "1.1.0");
    let source = fixture.path("live.sqlite");
    let db = Connection::open(&source).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY,label TEXT,secret BLOB); INSERT INTO notes VALUES('r1','WAL data',NULL);").unwrap();
    assert!(source.with_extension("sqlite-wal").exists());
    editor.put_database(declaration(), &db).unwrap();
    let saved = editor
        .save_as(
            fixture.path("snapshot.project"),
            &fixture.options(false),
            None,
        )
        .unwrap();
    assert_eq!(label(&saved), "WAL data");
    let mut editor = saved.edit();
    editor
        .update_manifest(|manifest| {
            manifest["databases"][0]["userVersion"] = json!(2);
            manifest["databases"][0]["tables"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"tags","description":"Tag records"}));
            Ok(())
        })
        .unwrap();
    editor
        .edit_database(DATABASE, |tx| {
            tx.execute_batch("PRAGMA user_version=2; CREATE TABLE tags(id TEXT PRIMARY KEY)")
                .map_err(|_| darkbox::Error::invalid("test.sql", "SQL failed"))?;
            Ok(())
        })
        .unwrap();
    let saved = editor.save(&fixture.options(false), None).unwrap();
    assert_eq!(saved.report().databases[0].user_version, 2);
    assert!(saved.report().databases[0].tables.contains(&"tags".into()));
}

#[test]
fn stale_editors_and_simultaneous_writers_cannot_overwrite_new_editions() {
    let fixture = Fixture::new();
    let package = fixture.package(false);
    let mut first = package.edit();
    let mut second = package.edit();
    first
        .put_reader("assets/public.bin", Cursor::new(b"First edition"))
        .unwrap();
    let saved = first.save(&fixture.options(false), None).unwrap();
    second
        .put_reader("assets/public.bin", Cursor::new(b"Stale edition"))
        .unwrap();
    assert_eq!(
        second
            .save(&fixture.options(false), None)
            .err()
            .unwrap()
            .code,
        "package.conflict"
    );
    assert!(second.is_dirty());
    assert_eq!(
        bytes(
            Package::open(
                fixture.path("original.project"),
                Limits::default(),
                &fixture.options(false)
            )
            .unwrap()
            .resource("assets/public.bin")
            .unwrap()
        ),
        b"First edition"
    );
    let options = fixture.options(false);
    let writer = PackageWriter::new(
        fixture.path("original.project"),
        saved.manifest().clone(),
        Limits::default(),
        &options,
        None,
    )
    .unwrap();
    assert_eq!(
        first.save(&options, None).err().unwrap().code,
        "package.busy"
    );
    assert_eq!(
        PackageWriter::new(
            fixture.path("original.project"),
            saved.manifest().clone(),
            Limits::default(),
            &options,
            None
        )
        .err()
        .unwrap()
        .code,
        "package.busy"
    );
    drop(writer);
    assert!(first.save(&options, None).is_ok());
    let existing = fixture.path("unrelated.bin");
    fs::write(&existing, b"Unrelated").unwrap();
    assert_eq!(
        second
            .save_as(&existing, &options, None)
            .err()
            .unwrap()
            .code,
        "package.destination_exists"
    );
    assert_eq!(fs::read(existing).unwrap(), b"Unrelated");
}

#[cfg(unix)]
#[test]
fn parent_directory_aliases_resolve_saved_paths_and_share_writer_locks() {
    let fixture = Fixture::new();
    let alias = fixture.path("parent-alias");
    std::os::unix::fs::symlink(fixture.directory.path(), &alias).unwrap();
    let aliased_path = alias.join("original.project");
    let options = fixture.options(false);
    let package = fixture
        .editor(false, "1.1.0")
        .save_as(&aliased_path, &options, None)
        .unwrap();
    let resolved_path = fs::canonicalize(&aliased_path).unwrap();
    assert_eq!(package.path(), Some(resolved_path.as_path()));

    let writer = PackageWriter::new(
        &aliased_path,
        package.manifest().clone(),
        Limits::default(),
        &options,
        None,
    )
    .unwrap();
    let mut editor = package.edit();
    assert_eq!(
        editor.save(&options, None).err().unwrap().code,
        "package.busy"
    );
    assert_eq!(
        darkbox::save(
            &resolved_path,
            &aliased_path,
            darkbox::PackageUpdate::default(),
            Limits::default(),
            &options,
            None
        )
        .err()
        .unwrap()
        .code,
        "package.busy"
    );
    drop(writer);

    editor
        .put_reader(
            "assets/public.bin",
            Cursor::new(b"Saved through a parent alias"),
        )
        .unwrap();
    let saved = editor.save(&options, None).unwrap();
    let reopened = Package::open(&aliased_path, Limits::default(), &options).unwrap();
    assert_eq!(saved.path(), reopened.path());
    assert_eq!(
        bytes(reopened.resource("assets/public.bin").unwrap()),
        b"Saved through a parent alias"
    );
}

struct Profile {
    reject: bool,
}
impl ApplicationProfile for Profile {
    fn id(&self) -> &str {
        "org.example.sdk"
    }
    fn supports(&self, version: &str) -> bool {
        version == "1"
    }
    fn validate(&self, context: &ProfileContext<'_>) -> Result<(), darkbox::Error> {
        context.with_resource("docs/profile.md", |reader| {
            assert!(bytes(reader).starts_with(b"# org.example.sdk"));
            Ok(())
        })?;
        context.with_database(DATABASE, |db| {
            let count: i64 = db
                .query_row("SELECT count(*) FROM notes", [], |row| row.get(0))
                .map_err(|_| darkbox::Error::invalid("profile.sql", "Profile SQL failed"))?;
            if self.reject || count != 1 {
                return Err(darkbox::Error::invalid(
                    "profile.semantic",
                    "Profile validation rejected the contents",
                ));
            }
            Ok(())
        })
    }
}
#[test]
fn profile_hooks_are_separate_and_gate_opening_and_atomic_publication() {
    let fixture = Fixture::new();
    let package = fixture.package(false);
    assert_eq!(package.report().application_validation, "not_performed");
    let mut options = fixture.options(false);
    options.require_profile = true;
    let error = Package::open(
        fixture.path("original.project"),
        Limits::default(),
        &options,
    )
    .err()
    .unwrap();
    assert!(
        error
            .report
            .as_ref()
            .unwrap()
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "profile.unsupported")
    );
    assert_eq!(
        darkbox::analyze_with(
            fixture.path("original.project"),
            darkbox::Mode::Verify,
            Limits::default(),
            &options
        )
        .application_validation,
        "unsupported"
    );
    options.profiles.register(Profile { reject: false });
    let verified = Package::open(
        fixture.path("original.project"),
        Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(verified.report().application_validation, "passed");
    let mut editor = verified.edit();
    editor
        .put_reader("assets/public.bin", Cursor::new(b"Changed"))
        .unwrap();
    let before = fs::read(fixture.path("original.project")).unwrap();
    options.profiles.register(Profile { reject: true });
    let error = editor.save(&options, None).err().unwrap();
    assert_eq!(error.report.unwrap().application_validation, "failed");
    assert_eq!(fs::read(fixture.path("original.project")).unwrap(), before);
    assert!(editor.is_dirty());
    let report = darkbox::analyze_with(
        fixture.path("original.project"),
        darkbox::Mode::Verify,
        Limits::default(),
        &options,
    );
    assert_eq!(report.application_validation, "failed");
    assert_eq!(report.status, Status::Invalid);
}

fn rewrite_manifest(source: &Path, target: &Path, change: impl FnOnce(&mut Value)) {
    use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};
    let mut input = ZipArchive::new(fs::File::open(source).unwrap()).unwrap();
    let mut writer = ZipWriter::new(fs::File::create(target).unwrap());
    let mut change = Some(change);
    for i in 0..input.len() {
        let mut entry = input.by_index(i).unwrap();
        let name = entry.name().to_owned();
        if entry.is_dir() {
            writer
                .add_directory(name, SimpleFileOptions::default())
                .unwrap();
            continue;
        }
        let data = if name == "manifest.json" {
            let mut manifest: Value = serde_json::from_slice(&bytes(&mut entry)).unwrap();
            change.take().unwrap()(&mut manifest);
            serde_json::to_vec(&manifest).unwrap()
        } else {
            bytes(entry)
        };
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut writer, &data).unwrap();
    }
    writer.finish().unwrap();
}

#[test]
fn unknown_required_extensions_and_future_versions_allow_only_diagnostic_access() {
    let fixture = Fixture::new();
    fixture.package(false);
    for future in [false, true] {
        let path = fixture.path(if future {
            "future.project"
        } else {
            "unknown.project"
        });
        rewrite_manifest(&fixture.path("original.project"), &path, |manifest| {
            if future {
                manifest["darkbox"]["version"] = json!("9.0.0");
            } else {
                manifest["extensions"]["org.example.unknown"] =
                    json!({"version":"1","required":true,"data":{}});
            }
        });
        assert!(Package::open(&path, Limits::default(), &fixture.options(false)).is_err());
        let diagnostic =
            DiagnosticPackage::open(&path, Limits::default(), &fixture.options(false)).unwrap();
        assert_eq!(diagnostic.report().status, Status::Unsupported);
        assert_eq!(
            bytes(diagnostic.resource("assets/public.bin").unwrap()),
            b"Public attachment"
        );
    }
    let invalid = DiagnosticPackage::from_reader(
        Cursor::new(b"Not a ZIP"),
        Limits::default(),
        &fixture.options(false),
    )
    .unwrap();
    assert_eq!(invalid.report().status, Status::Invalid);
    assert!(invalid.resource("manifest.json").is_err());
}

#[test]
fn unknown_optional_data_and_required_protection_cannot_be_silently_changed() {
    let fixture = Fixture::new();
    let mut editor = fixture.editor(false, "1.1.0");
    editor
        .add_folder("extensions", "Extension resources")
        .unwrap();
    editor
        .add_folder(
            "extensions/org.example.opaque",
            "Opaque application extension",
        )
        .unwrap();
    editor
        .update_manifest(|manifest| {
            manifest["extensions"]["org.example.opaque"] =
                json!({"version":"1","required":false,"data":{"public":42}});
            Ok(())
        })
        .unwrap();
    editor
        .put_reader(
            "extensions/org.example.opaque/resource",
            Cursor::new(b"Opaque"),
        )
        .unwrap();
    let package = editor
        .save_as(
            fixture.path("original.project"),
            &fixture.options(false),
            None,
        )
        .unwrap();
    let mut editor = package.edit();
    editor
        .put_reader(
            "extensions/org.example.opaque/resource",
            Cursor::new(b"Changed"),
        )
        .unwrap();
    assert!(editor.save(&fixture.options(false), None).is_err());
    editor.discard_changes();
    let copy = editor
        .save_as(fixture.path("copy.project"), &fixture.options(false), None)
        .unwrap();
    assert_eq!(
        bytes(
            copy.resource("extensions/org.example.opaque/resource")
                .unwrap()
        ),
        b"Opaque"
    );
    let fixture = Fixture::new();
    let package = fixture.package(true);
    let mut editor = package.edit();
    let before = fs::read(fixture.path("original.project")).unwrap();
    editor
        .update_manifest(|manifest| {
            manifest["extensions"]
                .as_object_mut()
                .unwrap()
                .remove(protection::NAMESPACE);
            Ok(())
        })
        .unwrap();
    assert!(editor.save(&fixture.options(false), None).is_err());
    assert_eq!(fs::read(fixture.path("original.project")).unwrap(), before);
}

#[test]
fn sdk_limits_and_key_lifecycle_are_enforced() {
    let fixture = Fixture::new();
    let package = fixture.package(false);
    let limits = Limits {
        max_archive_bytes: 10,
        ..Default::default()
    };
    assert!(
        Package::from_reader(
            Cursor::new(fs::read(fixture.path("original.project")).unwrap()),
            limits,
            &fixture.options(false)
        )
        .is_err()
    );
    let limits = Limits {
        max_entry_bytes: 8,
        ..Default::default()
    };
    let mut editor = PackageEditor::new(package.manifest().clone(), limits).unwrap();
    assert!(
        editor
            .put_reader("assets/large", io::repeat(b'x').take(9))
            .is_err()
    );
    assert_eq!(editor.resources().count(), 0);
    let mut keys = KeyRing::default();
    keys.insert("key", Zeroizing::new([1; 32]));
    assert!(keys.contains("key"));
    assert!(keys.remove("key"));
    assert!(!keys.contains("key"));
    assert!(ManifestBuilder::new("9.0.0", "org.example.sdk", "1").is_err());
    assert!(
        ManifestBuilder::new("1.1.0", "bad", "1")
            .unwrap()
            .database(declaration())
            .build()
            .is_err()
    );
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE notes(id TEXT,label TEXT,secret BLOB); INSERT INTO notes VALUES('r1','one',NULL)").unwrap();
    let tx = db.unchecked_transaction().unwrap();
    tx.execute("INSERT INTO notes VALUES(?1,'two',NULL)", params!["r2"])
        .unwrap();
    let mut editor = package.edit();
    assert!(editor.put_database(declaration(), &db).is_err());
    drop(tx);
}

#[test]
fn rekeying_rebinds_every_block_and_is_atomic_in_staging() {
    let fixture = Fixture::new();
    let package = fixture.package(true);
    let original_file = bytes(package.resource("assets/private.bin").unwrap());
    let original_database = bytes(package.resource(DATABASE).unwrap());
    let mut editor = package.edit();
    let id = "ffeeddccbbaa99887766554433221100";
    let mapping = std::collections::BTreeMap::from([("test-key".into(), "new-key".into())]);
    let mut nonces = Nonces(1000);
    assert!(
        editor
            .rekey(id, &mapping, &fixture.keys, &mut nonces)
            .is_err()
    );
    assert_eq!(
        bytes(editor.resource("assets/private.bin").unwrap()),
        original_file
    );
    assert_eq!(bytes(editor.resource(DATABASE).unwrap()), original_database);
    assert_eq!(editor.manifest(), package.manifest());
    let mut keys = KeyRing::default();
    keys.insert("test-key", Zeroizing::new([42; 32]));
    keys.insert("new-key", Zeroizing::new([43; 32]));
    editor.rekey(id, &mapping, &keys, &mut nonces).unwrap();
    assert_ne!(
        bytes(editor.resource("assets/private.bin").unwrap()),
        original_file
    );
    assert_ne!(bytes(editor.resource(DATABASE).unwrap()), original_database);
    assert_eq!(
        &*editor
            .decrypt_resource("assets/private.bin", &keys)
            .unwrap(),
        b"Private file"
    );
    assert_eq!(
        &*editor
            .decrypt_value(DATABASE, "notes", "secret", "r1", &keys)
            .unwrap()
            .unwrap(),
        b"Private value"
    );
    let mut options = fixture.options(false);
    options.decryption_keys = Some(&keys);
    let saved = editor
        .save_as(
            fixture.path("rekeyed.project"),
            &options,
            Some(&fixture.signer),
        )
        .unwrap();
    assert!(
        saved
            .report()
            .protection
            .as_ref()
            .unwrap()
            .encrypted
            .iter()
            .all(|block| block.context.package_id == id
                && block.context.key_id == "new-key"
                && block.authentication == "verified")
    );
    assert_eq!(
        saved
            .decrypt_resource("assets/private.bin", &fixture.keys)
            .err()
            .unwrap()
            .code,
        "protection.key_absent"
    );
    assert_eq!(
        bytes(package.resource("assets/private.bin").unwrap()),
        original_file
    );
}
