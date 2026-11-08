use darkbox::rusqlite::Connection;
use darkbox::{
    Limits, ManifestBuilder, Mode, Package, PackageEditor, Status, StoredResource,
    VerificationOptions,
    manifest::{DatabaseDeclaration, TableDeclaration},
    protection::{
        self, Ed25519Signer, KeyRing, ManifestSigner, NonceSequence, ProtectionData,
        SignatureDeclaration,
    },
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

const ID: &str = "00112233445566778899aabbccddeeff";
const DB: &str = "data/project.sqlite";
struct Fixture {
    dir: tempfile::TempDir,
    signer: Ed25519Signer,
    keys: KeyRing,
}
struct Nonces(u32);
impl NonceSequence for Nonces {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
        self.0 += 1;
        let mut bytes = [0; 12];
        bytes[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(bytes)
    }
}
fn declaration() -> DatabaseDeclaration {
    DatabaseDeclaration {
        path: DB.into(),
        description: "Library".into(),
        user_version: Some(1),
        tables: vec![TableDeclaration {
            name: "items".into(),
            description: "Item names".into(),
        }],
    }
}
impl Fixture {
    fn new() -> Self {
        let mut keys = KeyRing::default();
        keys.insert("key", Zeroizing::new([42; 32]));
        Self {
            dir: tempfile::Builder::new()
                .prefix("darkbox-library-tests-")
                .tempdir()
                .unwrap(),
            signer: Ed25519Signer::from_seed("signer", Zeroizing::new([7; 32])),
            keys,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn options(&self, keyed: bool) -> VerificationOptions<'_> {
        let mut options = VerificationOptions::default();
        options
            .trusted_signers
            .insert("signer".into(), self.signer.public_key());
        if keyed {
            options.decryption_keys = Some(&self.keys);
        }
        options
    }
    fn editor(&self, protected: bool) -> PackageEditor {
        let mut builder = ManifestBuilder::new("1.2.0", "org.example.library", "1")
            .unwrap()
            .package_id(ID)
            .resource_inventory()
            .folder("data", "Databases")
            .folder("media", "Media")
            .folder("empty", "Empty folder")
            .folder("extensions", "Extensions")
            .folder("extensions/org.example.opaque", "Opaque data")
            .extension("org.example.opaque", "1", false, json!({"preserve":true}))
            .database(declaration());
        if protected {
            builder = builder.protection(ProtectionData {
                package_id: ID.into(),
                signature: SignatureDeclaration {
                    algorithm: "Ed25519".into(),
                    signer_id: "signer".into(),
                    path: protection::SIGNATURE_PATH.into(),
                },
                inventory: vec![],
                files: vec![],
                sqlite: vec![],
            });
        }
        let manifest = builder.build().unwrap();
        let mut editor = PackageEditor::new(manifest, Limits::default()).unwrap();
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("PRAGMA user_version=1; CREATE TABLE items(id TEXT PRIMARY KEY, name TEXT); INSERT INTO items VALUES('1','one');").unwrap();
        editor.put_database(declaration(), &db).unwrap();
        editor.put_reader("docs/profile.md", Cursor::new(b"# org.example.library format 1\n\nitems.id identifies each item; name is its label. Media files are opaque attachments.\n")).unwrap();
        editor
            .put_reader("media/video.mp4", Cursor::new(b"seekable video test bytes"))
            .unwrap();
        editor
            .put_reader("media/remove.bin", Cursor::new(b"removed in next edition"))
            .unwrap();
        editor
            .put_reader(
                "extensions/org.example.opaque/data.bin",
                Cursor::new(b"opaque extension bytes"),
            )
            .unwrap();
        if protected {
            editor
                .put_encrypted(
                    "media/private.bin",
                    b"secret",
                    "key",
                    &self.keys,
                    &mut Nonces(0),
                )
                .unwrap();
        }
        editor
    }
    fn package(&self, protected: bool) -> Package {
        self.editor(protected)
            .save_as(
                self.path("base.project"),
                &self.options(true),
                protected.then_some(&self.signer as &dyn ManifestSigner),
            )
            .unwrap()
    }
    fn target(&self, package: &Package, protected: bool) -> Package {
        let mut editor = package.edit();
        editor.remove_resource("media/remove.bin").unwrap();
        editor
            .put_reader("media/new.bin", Cursor::new(b"added file"))
            .unwrap();
        editor
            .edit_database(DB, |tx| {
                tx.execute("UPDATE items SET name='two'", []).unwrap();
                Ok(())
            })
            .unwrap();
        editor
            .save_as(
                self.path("target.project"),
                &self.options(false),
                protected.then_some(&self.signer as &dyn ManifestSigner),
            )
            .unwrap()
    }
    fn assert_clean(&self) {
        for item in fs::read_dir(self.dir.path()).unwrap() {
            let name = item.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                !name.starts_with(".darkbox-transfer-") && !name.starts_with(".darkbox-unpack-"),
                "Leaked {name}"
            );
        }
    }
}
fn bytes(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = vec![];
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, result: &mut BTreeMap<String, Vec<u8>>) {
        for item in fs::read_dir(dir).unwrap() {
            let item = item.unwrap();
            if item.file_type().unwrap().is_dir() {
                visit(root, &item.path(), result);
            } else {
                result.insert(
                    item.path()
                        .strip_prefix(root)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('\\', "/"),
                    fs::read(item.path()).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}
fn rewrite_delta(path: &Path, mutate: impl FnOnce(&mut Value, &mut BTreeMap<String, Vec<u8>>)) {
    let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
    let mut files = BTreeMap::new();
    for i in 0..archive.len() {
        let entry = archive.by_index(i).unwrap();
        if !entry.is_dir() {
            files.insert(entry.name().to_owned(), bytes(entry));
        }
    }
    drop(archive);
    let mut descriptor: Value = serde_json::from_slice(&files["delta.json"]).unwrap();
    mutate(&mut descriptor, &mut files);
    files.insert(
        "delta.json".into(),
        serde_json::to_vec(&descriptor).unwrap(),
    );
    let mut writer = ZipWriter::new(File::create(path).unwrap());
    for (name, data) in files {
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&data).unwrap();
    }
    writer.finish().unwrap();
}

#[test]
fn directory_conversion_preserves_every_file_and_locked_signature() {
    for protected in [false, true] {
        let fixture = Fixture::new();
        let original = fixture.package(protected);
        let options = fixture.options(false);
        let folder = fixture.path("library");
        let report = darkbox::unpack(
            fixture.path("base.project"),
            &folder,
            Limits::default(),
            &options,
        )
        .unwrap();
        assert!(report.entries.iter().all(|e| !e.crc_verified));
        assert!(report.checks.contains(&"directory.bytes"));
        assert!(folder.join("empty").is_dir());
        let expected: BTreeMap<_, _> = original
            .resources()
            .map(|e| (e.path.clone(), bytes(original.resource(&e.path).unwrap())))
            .collect();
        assert_eq!(tree(&folder), expected);
        let packed = fixture.path("packed.project");
        darkbox::pack(&folder, &packed, Limits::default(), &options).unwrap();
        let roundtrip = Package::open(&packed, Limits::default(), &options).unwrap();
        for (name, data) in expected {
            assert_eq!(bytes(roundtrip.resource(&name).unwrap()), data, "{name}");
        }
        let snapshot = Package::open(&folder, Limits::default(), &options).unwrap();
        assert!(snapshot.path().is_none());
        assert_eq!(
            bytes(snapshot.resource("media/video.mp4").unwrap()),
            b"seekable video test bytes"
        );
        assert!(darkbox::unpack(&packed, &folder, Limits::default(), &options).is_err());
        assert!(
            darkbox::pack(
                &folder,
                fixture.path("library/inside.zip"),
                Limits::default(),
                &options
            )
            .is_err()
        );
        fixture.assert_clean();
    }
}

#[test]
fn delta_roundtrip_and_chain_preserve_exact_target_resources_without_private_keys() {
    for protected in [false, true] {
        let fixture = Fixture::new();
        let base = fixture.package(protected);
        let target = fixture.target(&base, protected);
        let options = fixture.options(false);
        let delta = fixture.path("week.delta");
        darkbox::create_delta(
            fixture.path("base.project"),
            fixture.path("target.project"),
            &delta,
            Limits::default(),
            &options,
        )
        .unwrap();
        let mut zip = ZipArchive::new(File::open(&delta).unwrap()).unwrap();
        let descriptor: Value =
            serde_json::from_slice(&bytes(zip.by_name("delta.json").unwrap())).unwrap();
        let schema: Value =
            serde_json::from_str(include_str!("../schema/1.2.0/delta.schema.json")).unwrap();
        jsonschema::meta::validate(&schema).unwrap();
        assert!(
            jsonschema::draft202012::options()
                .build(&schema)
                .unwrap()
                .is_valid(&descriptor)
        );
        assert!(
            !descriptor["changed"]
                .as_array()
                .unwrap()
                .contains(&json!("media/video.mp4"))
        );
        assert!(
            descriptor["changed"]
                .as_array()
                .unwrap()
                .contains(&json!(DB))
        );
        assert_eq!(descriptor["removed"], json!(["media/remove.bin"]));
        assert!(zip.by_name("README.md").is_err());
        drop(zip);
        let report = darkbox::verify_delta(
            fixture.path("base.project"),
            &delta,
            Limits::default(),
            &options,
        )
        .unwrap();
        assert_eq!(report.status, Status::Passed);
        assert_eq!(report.scope, "delta_against_base");
        let merged = fixture.path("merged.project");
        darkbox::merge(
            fixture.path("base.project"),
            &delta,
            &merged,
            Limits::default(),
            &options,
        )
        .unwrap();
        let result = Package::open(&merged, Limits::default(), &options).unwrap();
        assert_eq!(
            result.resources().collect::<Vec<_>>(),
            target.resources().collect::<Vec<_>>()
        );
        for digest in target.resources() {
            assert_eq!(
                bytes(result.resource(&digest.path).unwrap()),
                bytes(target.resource(&digest.path).unwrap())
            );
        }
        // A no-op link is still bound to its exact preceding edition.
        let next = fixture.path("next.delta");
        darkbox::create_delta(&merged, &merged, &next, Limits::default(), &options).unwrap();
        assert!(
            darkbox::verify_delta(
                fixture.path("base.project"),
                &next,
                Limits::default(),
                &options
            )
            .is_err()
        );
        darkbox::merge(
            &merged,
            &next,
            fixture.path("last.project"),
            Limits::default(),
            &options,
        )
        .unwrap();
        assert!(darkbox::merge(&merged, &next, &merged, Limits::default(), &options).is_err());
        fixture.assert_clean();
    }
}

#[test]
fn delta_rejects_wrong_base_tampered_payloads_and_ambiguous_descriptors() {
    for mutation in 0..9 {
        let fixture = Fixture::new();
        let base = fixture.package(false);
        fixture.target(&base, false);
        let options = fixture.options(false);
        let delta = fixture.path("bad.delta");
        darkbox::create_delta(
            fixture.path("base.project"),
            fixture.path("target.project"),
            &delta,
            Limits::default(),
            &options,
        )
        .unwrap();
        rewrite_delta(&delta, |descriptor, files| match mutation {
            0 => {
                descriptor["base"]["manifestSha256"] = json!("00".repeat(32));
            }
            1 => {
                descriptor["base"]["inventorySha256"] = json!("00".repeat(32));
            }
            2 => {
                descriptor["changed"][0] = json!("../escape");
            }
            3 => {
                descriptor["removed"] = json!([]);
            }
            4 => {
                files.insert("files/0".into(), b"tampered resource".to_vec());
            }
            5 => {
                files.insert("files/9999".into(), b"unexpected resource".to_vec());
            }
            6 => {
                descriptor["targetFiles"].as_array_mut().unwrap().reverse();
            }
            7 => {
                descriptor["target"]["packageId"] = json!("different");
            }
            8 => {
                descriptor["targetFiles"][0]["size"] = json!(u64::MAX);
            }
            _ => unreachable!(),
        });
        let original = fs::read(fixture.path("base.project")).unwrap();
        let result = darkbox::merge(
            fixture.path("base.project"),
            &delta,
            fixture.path("rejected.project"),
            Limits::default(),
            &options,
        );
        assert!(result.is_err(), "mutation {mutation}");
        assert!(!fixture.path("rejected.project").exists());
        assert_eq!(fs::read(fixture.path("base.project")).unwrap(), original);
        fixture.assert_clean();
    }
}

#[test]
fn unsigned_inventory_is_checked_but_quick_inspection_never_certifies_bytes() {
    let fixture = Fixture::new();
    fixture.package(false);
    let options = fixture.options(false);
    let folder = fixture.path("library");
    darkbox::unpack(
        fixture.path("base.project"),
        &folder,
        Limits::default(),
        &options,
    )
    .unwrap();
    fs::write(folder.join("media/video.mp4"), b"same length but different").unwrap();
    let quick = darkbox::inspect_inventory(&folder, Limits::default());
    assert_eq!(quick.status, Status::Inspected, "{:?}", quick.diagnostics);
    assert!(quick.databases.is_empty());
    assert!(!quick.checks.contains(&"inventory.sha256"));
    let full = darkbox::verify(&folder);
    assert_eq!(full.status, Status::Invalid);
    assert!(
        full.diagnostics
            .iter()
            .any(|d| d.code == "inventory.digest")
    );
    // No hash or CRC pass over this sparse 4 GiB media file is performed.
    let sparse = File::create(folder.join("media/large.mp4")).unwrap();
    sparse.set_len(4 * 1024 * 1024 * 1024).unwrap();
    let path = folder.join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["resourceInventory"].as_array_mut().unwrap().push(
        json!({"path":"media/large.mp4","size":4_u64*1024*1024*1024,"sha256":"00".repeat(32)}),
    );
    fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert_eq!(
        darkbox::inspect_inventory(&folder, Limits::default()).status,
        Status::ResourceLimit
    );
    assert_eq!(
        darkbox::inspect_inventory(&folder, Limits::large()).status,
        Status::Inspected
    );
}

#[test]
fn directories_reject_sidecars_links_case_collisions_and_old_common_versions() {
    for mutation in 0..5 {
        let fixture = Fixture::new();
        fixture.package(false);
        let folder = fixture.path("library");
        let options = fixture.options(false);
        darkbox::unpack(
            fixture.path("base.project"),
            &folder,
            Limits::default(),
            &options,
        )
        .unwrap();
        match mutation {
            0 => {
                fs::write(folder.join(format!("{DB}-wal")), b"sidecar").unwrap();
            }
            1 => {
                fs::write(folder.join("media/Video.mp4"), b"collision").unwrap();
            }
            2 => {
                let db = Connection::open(folder.join(DB)).unwrap();
                db.execute_batch("PRAGMA journal_mode=WAL").unwrap();
            }
            3 => {
                let path = folder.join("manifest.json");
                let mut manifest: Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                manifest["darkbox"]["version"] = json!("1.1.0");
                fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            }
            4 => {
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(
                        fixture.path("base.project"),
                        folder.join("media/link"),
                    )
                    .unwrap();
                }
            }
            _ => unreachable!(),
        }
        #[cfg(not(unix))]
        if mutation == 4 {
            continue;
        }
        let report = darkbox::verify(&folder);
        assert_ne!(report.status, Status::Passed, "mutation {mutation}");
        assert!(
            darkbox::pack(
                &folder,
                fixture.path("bad.project"),
                Limits::default(),
                &options
            )
            .is_err()
        );
        assert!(!fixture.path("bad.project").exists());
        fixture.assert_clean();
    }
}

#[test]
fn media_uses_aligned_store_and_bounded_seekable_direct_access() {
    let fixture = Fixture::new();
    let original = fixture.package(false);
    let options = fixture.options(false);
    let mut reader = StoredResource::open(
        fixture.path("base.project"),
        "media/video.mp4",
        Limits::default(),
        &options,
    )
    .unwrap();
    assert_eq!(reader.data_offset() % 4096, 0);
    assert_eq!(reader.len(), 25);
    assert_eq!(reader.report().status, Status::Passed);
    reader.seek(SeekFrom::Start(9)).unwrap();
    let mut part = [0; 5];
    reader.read_exact(&mut part).unwrap();
    assert_eq!(&part, b"video");
    reader.seek(SeekFrom::End(-5)).unwrap();
    assert_eq!(bytes(&mut reader), b"bytes");
    assert_eq!(reader.read(&mut part).unwrap(), 0);
    assert!(reader.seek(SeekFrom::End(-1000)).is_err());
    reader.seek(SeekFrom::Start(u64::MAX)).unwrap();
    assert_eq!(reader.read(&mut part).unwrap(), 0);
    let error = StoredResource::open(
        fixture.path("base.project"),
        DB,
        Limits::default(),
        &options,
    )
    .err()
    .unwrap();
    assert_eq!(error.code, "media.compression");
    assert_eq!(
        bytes(original.resource("media/video.mp4").unwrap()),
        b"seekable video test bytes"
    );
}

#[test]
fn explicit_staging_is_used_for_snapshots_edits_databases_and_transfer_verification() {
    let fixture = Fixture::new();
    fixture.package(false);
    let options = fixture.options(false);
    let storage = fixture.path("storage");
    fs::create_dir(&storage).unwrap();
    let limits = Limits {
        staging_directory: Some(storage.clone()),
        ..Default::default()
    };
    {
        let package =
            Package::open(fixture.path("base.project"), limits.clone(), &options).unwrap();
        assert!(fs::read_dir(&storage).unwrap().count() > 0);
        let mut editor = package.edit();
        editor
            .put_reader("media/added.bin", Cursor::new(b"staged"))
            .unwrap();
        editor
            .edit_database(DB, |tx| {
                tx.execute("UPDATE items SET name='edited'", []).unwrap();
                Ok(())
            })
            .unwrap();
        assert!(fs::read_dir(&storage).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("darkbox-edit-")
        }));
        editor
            .save_as(fixture.path("edited.project"), &options, None)
            .unwrap();
        darkbox::unpack(
            fixture.path("base.project"),
            fixture.path("directory"),
            limits.clone(),
            &options,
        )
        .unwrap();
    }
    assert_eq!(fs::read_dir(&storage).unwrap().count(), 0);
    let bad = Limits {
        staging_directory: Some(fixture.path("missing-storage")),
        ..Default::default()
    };
    assert!(Package::open(fixture.path("base.project"), bad, &options).is_err());
    let inside = Limits {
        staging_directory: Some(fixture.path("directory/media")),
        ..Default::default()
    };
    assert_eq!(
        darkbox::analyze_with(fixture.path("directory"), Mode::Verify, inside, &options).status,
        Status::Invalid
    );
    fixture.assert_clean();
}

#[test]
#[cfg(feature = "cli")]
fn cli_converts_and_verifies_deltas_and_preset_overrides() {
    use std::process::Command;
    let fixture = Fixture::new();
    let base = fixture.package(false);
    fixture.target(&base, false);
    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_darkbox"))
            .args(args)
            .current_dir(fixture.dir.path())
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
        (output.status.code().unwrap(), report)
    };
    for args in [
        vec!["unpack", "base.project", "library", "--json"],
        vec!["pack", "library", "packed.project", "--json"],
        vec![
            "delta",
            "base.project",
            "target.project",
            "week.delta",
            "--json",
        ],
        vec!["verify", "week.delta", "--base", "base.project", "--json"],
        vec![
            "merge",
            "base.project",
            "week.delta",
            "merged.project",
            "--json",
        ],
    ] {
        let (code, report) = run(&args);
        assert_eq!(code, 0, "{report}");
    }
    let (code, report) = run(&[
        "inspect",
        "library",
        "--inventory-only",
        "--limits",
        "large",
        "--json",
    ]);
    assert_eq!(code, 0);
    assert_eq!(report["status"], "inspected");
    assert_eq!(report["scope"], "inventory_claims");
    assert_eq!(
        report["limits"]["max_entry_bytes"],
        64_u64 * 1024 * 1024 * 1024
    );
    let (code, report) = run(&[
        "verify",
        "base.project",
        "--limits",
        "large",
        "--max-entry-bytes",
        "1",
        "--json",
    ]);
    assert_eq!(code, 4);
    assert_eq!(report["limits"]["max_entry_bytes"], 1);
    assert!(
        report["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains("--max-entry-bytes")
    );
}

#[test]
fn delta_binds_base_resources_even_without_an_unsigned_inventory() {
    let fixture = Fixture::new();
    let mut editor = fixture.editor(false);
    editor
        .update_manifest(|manifest| {
            manifest
                .as_object_mut()
                .unwrap()
                .remove("resourceInventory");
            Ok(())
        })
        .unwrap();
    let base = editor
        .save_as(fixture.path("base.project"), &fixture.options(false), None)
        .unwrap();
    fixture.target(&base, false);
    let options = fixture.options(false);
    let delta = fixture.path("week.delta");
    darkbox::create_delta(
        fixture.path("base.project"),
        fixture.path("target.project"),
        &delta,
        Limits::default(),
        &options,
    )
    .unwrap();
    let folder = fixture.path("altered-base");
    darkbox::unpack(
        fixture.path("base.project"),
        &folder,
        Limits::default(),
        &options,
    )
    .unwrap();
    let manifest_before = fs::read(folder.join("manifest.json")).unwrap();
    fs::write(folder.join("media/video.mp4"), b"same length but different").unwrap();
    assert_eq!(darkbox::verify(&folder).status, Status::Passed);
    assert_eq!(
        fs::read(folder.join("manifest.json")).unwrap(),
        manifest_before
    );
    let error = darkbox::merge(
        &folder,
        &delta,
        fixture.path("rejected.project"),
        Limits::default(),
        &options,
    )
    .unwrap_err();
    assert_eq!(error.code, "delta.invalid");
    assert!(!fixture.path("rejected.project").exists());
    fixture.assert_clean();
}

#[test]
fn delta_requires_matching_library_identity_and_preserves_required_protection() {
    let fixture = Fixture::new();
    fixture.package(true);
    let mut unprotected = fixture.editor(false);
    unprotected
        .save_as(
            fixture.path("unprotected.project"),
            &fixture.options(false),
            None,
        )
        .unwrap();
    let options = fixture.options(false);
    let error = darkbox::create_delta(
        fixture.path("base.project"),
        fixture.path("unprotected.project"),
        fixture.path("downgrade.delta"),
        Limits::default(),
        &options,
    )
    .unwrap_err();
    assert_eq!(error.code, "delta.invalid");
    assert!(!fixture.path("downgrade.delta").exists());
    unprotected
        .update_manifest(|manifest| {
            manifest["packageId"] = json!("another-library");
            Ok(())
        })
        .unwrap();
    unprotected
        .save_as(fixture.path("unrelated.project"), &options, None)
        .unwrap();
    assert!(
        darkbox::create_delta(
            fixture.path("unprotected.project"),
            fixture.path("unrelated.project"),
            fixture.path("unrelated.delta"),
            Limits::default(),
            &options
        )
        .is_err()
    );
    assert!(!fixture.path("unrelated.delta").exists());
    fixture.assert_clean();
}
