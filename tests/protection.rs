use darkbox::extensions::EntryDigest;
use darkbox::protection::{
    self, BlockContext, BlockLocation, DecryptionKeys, ManifestSigner, NAMESPACE, NonceSequence,
    SIGNATURE_PATH,
};
use darkbox::{Limits, Mode, PackageUpdate, Status, VerificationOptions};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zeroize::Zeroizing;
use zip::{ZipWriter, write::SimpleFileOptions};

const PACKAGE: &str = "00112233445566778899aabbccddeeff";
const KEY: [u8; 32] = [42; 32];
const DATABASE: &str = "data/project.sqlite";

struct Keys([u8; 32]);
impl DecryptionKeys for Keys {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        (id == "test-key").then(|| Zeroizing::new(self.0))
    }
}

struct Signing(SigningKey);
impl Signing {
    fn new() -> Self {
        Self(SigningKey::from_bytes(&[7; 32]))
    }
}
impl ManifestSigner for Signing {
    fn signer_id(&self) -> &str {
        "test-signer"
    }
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], darkbox::Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}

struct Counter(u32);
impl NonceSequence for Counter {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
        self.0 += 1;
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }
}

fn block_context(location: BlockLocation) -> BlockContext {
    BlockContext {
        package_id: PACKAGE.into(),
        key_id: "test-key".into(),
        location,
    }
}
fn file_context(path: &str) -> BlockContext {
    block_context(BlockLocation::File { path: path.into() })
}
fn row_context(id: &str) -> BlockContext {
    block_context(BlockLocation::Sqlite {
        database: DATABASE.into(),
        table: "notes".into(),
        column: "secret".into(),
        record_id: id.into(),
    })
}

fn collect(base: &Path, path: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect(base, &path, files);
        } else {
            files.insert(
                path.strip_prefix(base)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .replace('\\', "/"),
                fs::read(path).unwrap(),
            );
        }
    }
}

struct Fixture {
    dir: TempDir,
    files: BTreeMap<String, Vec<u8>>,
    manifest: Value,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::Builder::new()
            .prefix("darkbox-protection-tests-")
            .tempdir()
            .unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = BTreeMap::new();
        let base = root.join("archive/1.1.0");
        collect(&base, &base, &mut files);
        let mut manifest: Value = serde_json::from_slice(
            &fs::read(root.join("examples/notebook.manifest.json")).unwrap(),
        )
        .unwrap();
        manifest["application"] = json!({"id":"org.example.protected-notes","formatVersion":"1","profilePath":"docs/profile.md"});
        manifest["databases"][0]["userVersion"] = json!(1);
        manifest["databases"][0]["tables"] =
            json!([{"name":"notes","description":"Public labels and protected values"}]);
        manifest["folders"].as_array_mut().unwrap().extend([
            json!({"path":"assets","description":"Public and protected attachments"}),
            json!({"path":"extensions","description":"Extension resources"}),
            json!({"path":format!("extensions/{NAMESPACE}"),"description":"Detached manifest signature"}),
        ]);
        manifest["extensions"][NAMESPACE] = json!({"version":"1.0.0","required":true,"data":{
            "packageId":PACKAGE,"signature":{"algorithm":"Ed25519","signerId":"test-signer","path":SIGNATURE_PATH},
            "inventory":[],"files":[{"path":"assets/private.bin","keyId":"test-key"}],
            "sqlite":[{"database":DATABASE,"table":"notes","column":"secret","recordIdColumn":"id","keyId":"test-key"}]
        }});
        files.insert("docs/profile.md".into(), b"# org.example.protected-notes, format 1\n\nnotes.id is immutable unique UTF-8 TEXT; label is public TEXT; secret is NULL or a protected BLOB containing UTF-8 text. assets/private.bin contains protected bytes.\n".to_vec());
        files.insert("assets/public.txt".into(), b"Public attachment".to_vec());
        let mut nonces = Counter(0);
        files.insert(
            "assets/private.bin".into(),
            protection::encrypt_block(
                b"Private attachment",
                &KEY,
                &file_context("assets/private.bin"),
                &mut nonces,
            )
            .unwrap(),
        );
        let db_path = dir.path().join("source.sqlite");
        let db = Connection::open(&db_path).unwrap();
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY, label TEXT, secret BLOB);").unwrap();
        for id in ["r1", "r2"] {
            let encrypted = protection::encrypt_block(
                format!("Secret {id}").as_bytes(),
                &KEY,
                &row_context(id),
                &mut nonces,
            )
            .unwrap();
            db.execute(
                "INSERT INTO notes VALUES (?1,?2,?3)",
                params![id, format!("Public {id}"), encrypted],
            )
            .unwrap();
        }
        db.execute("INSERT INTO notes VALUES ('r3','Public r3',NULL)", [])
            .unwrap();
        drop(db);
        files.insert(DATABASE.into(), fs::read(&db_path).unwrap());
        let mut fixture = Self {
            dir,
            files,
            manifest,
        };
        fixture.seal();
        fixture
    }
    fn seal(&mut self) {
        let inventory: Vec<_> = self
            .files
            .iter()
            .filter(|(path, _)| path.as_str() != "manifest.json" && path.as_str() != SIGNATURE_PATH)
            .map(|(path, bytes)| EntryDigest {
                path: path.clone(),
                size: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            })
            .collect();
        self.manifest["extensions"][NAMESPACE]["data"]["inventory"] =
            serde_json::to_value(inventory).unwrap();
        self.sign();
    }
    fn sign(&mut self) {
        let bytes = serde_json::to_vec_pretty(&self.manifest).unwrap();
        self.files.insert(
            SIGNATURE_PATH.into(),
            Signing::new().sign(&bytes).unwrap().to_vec(),
        );
        self.files.insert("manifest.json".into(), bytes);
    }
    fn path(&self) -> PathBuf {
        let path = self.dir.path().join("protected.project");
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        for folder in self.manifest["folders"].as_array().unwrap() {
            zip.add_directory(
                format!("{}/", folder["path"].as_str().unwrap()),
                SimpleFileOptions::default(),
            )
            .unwrap();
        }
        for (name, bytes) in &self.files {
            zip.start_file(
                name,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated),
            )
            .unwrap();
            zip.write_all(bytes).unwrap();
        }
        fs::write(&path, zip.finish().unwrap().into_inner()).unwrap();
        path
    }
    fn options<'a>(&self, keys: Option<&'a dyn DecryptionKeys>) -> VerificationOptions<'a> {
        VerificationOptions {
            decryption_keys: keys,
            trusted_signers: BTreeMap::from([("test-signer".into(), Signing::new().public_key())]),
            require_protection: true,
            ..Default::default()
        }
    }
    fn verify(&self, keys: Option<&dyn DecryptionKeys>) -> darkbox::Report {
        darkbox::analyze_with(
            self.path(),
            Mode::Verify,
            Limits::default(),
            &self.options(keys),
        )
    }
    fn database(&mut self, edit: impl FnOnce(&Connection)) {
        let path = self.dir.path().join("edited.sqlite");
        fs::write(&path, &self.files[DATABASE]).unwrap();
        let db = Connection::open(&path).unwrap();
        edit(&db);
        drop(db);
        self.files.insert(DATABASE.into(), fs::read(path).unwrap());
    }
}

fn code(report: &darkbox::Report, code: &str) {
    assert!(
        report.diagnostics.iter().any(|d| d.code == code),
        "Expected {code}: {}",
        serde_json::to_string_pretty(report).unwrap()
    );
}
fn status(report: &darkbox::Report, status: Status) {
    assert_eq!(
        report.status,
        status,
        "{}",
        serde_json::to_string_pretty(report).unwrap()
    );
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn independent_aes_and_ed25519_vectors_are_exact() {
    let vectors: Value = serde_json::from_slice(include_bytes!(
        "../archive/1.1.0/docs/darkbox/protection/1.0.0.vectors.json"
    ))
    .unwrap();
    for vector in vectors["blocks"].as_array().unwrap() {
        let context: BlockContext = serde_json::from_value(vector["context"].clone()).unwrap();
        let bytes = unhex(vector["blockHex"].as_str().unwrap());
        let key: [u8; 32] = unhex(vector["keyHex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let plaintext = unhex(vector["plaintextHex"].as_str().unwrap());
        assert_eq!(
            context
                .aad(protection::block_header(&bytes).unwrap())
                .unwrap(),
            unhex(vector["aadHex"].as_str().unwrap())
        );
        assert_eq!(
            protection::decrypt_block(&bytes, &key, &context)
                .unwrap()
                .as_slice(),
            plaintext
        );
        struct Fixed([u8; 12]);
        impl NonceSequence for Fixed {
            fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
                Ok(self.0)
            }
        }
        let nonce = unhex(vector["nonceHex"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            protection::encrypt_block(&plaintext, &key, &context, &mut Fixed(nonce)).unwrap(),
            bytes
        );
        let mut moved = context.clone();
        moved.package_id = "ffeeddccbbaa99887766554433221100".into();
        assert_eq!(
            protection::decrypt_block(&bytes, &key, &moved)
                .unwrap_err()
                .code,
            "protection.authentication"
        );
    }
    let signature = &vectors["signature"];
    let manifest = unhex(signature["manifestHex"].as_str().unwrap());
    let public: [u8; 32] = unhex(signature["publicKeyHex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let signature =
        Signature::from_slice(&unhex(signature["signatureHex"].as_str().unwrap())).unwrap();
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(&manifest, &signature)
        .unwrap();
    assert_eq!(
        vectors["rfc8032EmptyMessageSignatureHex"],
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

#[test]
fn public_checks_work_without_keys_and_plaintext_never_enters_reports_or_sqlite() {
    let fixture = Fixture::new();
    let report = fixture.verify(None);
    status(&report, Status::Passed);
    code(&report, "protection.key_absent");
    let protection = report.protection.as_ref().unwrap();
    assert_eq!(protection.signature, "verified");
    assert!(protection.inventory_verified);
    assert_eq!(protection.encrypted.len(), 3);
    assert!(
        protection
            .encrypted
            .iter()
            .all(|b| b.authentication == "key_absent" && b.plaintext_validation == "not_performed")
    );
    assert!(report.databases[0].integrity_checked && report.databases[0].foreign_keys_checked);
    let report = fixture.verify(Some(&Keys(KEY)));
    status(&report, Status::Passed);
    assert!(
        report
            .protection
            .as_ref()
            .unwrap()
            .encrypted
            .iter()
            .all(|b| b.authentication == "verified")
    );
    let report = serde_json::to_string(&report).unwrap();
    assert!(!report.contains("Secret r1"));
    assert!(!report.contains(&"2a".repeat(32)));
    for secret in [b"Secret r1".as_slice(), b"Secret r2".as_slice()] {
        assert!(
            !fixture.files[DATABASE]
                .windows(secret.len())
                .any(|part| part == secret)
        );
    }
    assert!(fixture.files[DATABASE].starts_with(b"SQLite format 3\0"));
}

#[test]
fn unknown_signer_wrong_keys_removed_and_invalid_signatures_are_distinct() {
    let mut fixture = Fixture::new();
    let report = darkbox::verify(fixture.path());
    status(&report, Status::Unsupported);
    code(&report, "protection.signer_unknown");
    let report = fixture.verify(Some(&Keys([9; 32])));
    status(&report, Status::Invalid);
    code(&report, "protection.authentication");
    fixture.files.get_mut("manifest.json").unwrap().push(b' ');
    let report = fixture.verify(None);
    code(&report, "protection.signature_invalid");
    fixture.sign();
    fixture.files.get_mut(SIGNATURE_PATH).unwrap()[0] ^= 1;
    code(&fixture.verify(None), "protection.signature_invalid");
    fixture.files.remove(SIGNATURE_PATH);
    code(&fixture.verify(None), "protection.signature_missing");
}

#[test]
fn complete_inventory_detects_modified_added_missing_and_excluded_entries() {
    for path in [
        "assets/public.txt",
        DATABASE,
        "docs/profile.md",
        "docs/darkbox/protection/1.0.0.vectors.json",
    ] {
        let mut fixture = Fixture::new();
        fixture.files.get_mut(path).unwrap().push(b'x');
        code(&fixture.verify(None), "protection.inventory");
    }
    let mut fixture = Fixture::new();
    fixture
        .files
        .insert("assets/additional.txt".into(), b"Extra".to_vec());
    code(&fixture.verify(None), "protection.inventory");
    fixture = Fixture::new();
    fixture.files.remove("assets/public.txt");
    code(&fixture.verify(None), "protection.inventory");
    fixture = Fixture::new();
    fixture.manifest["extensions"][NAMESPACE]["data"]["inventory"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path":"manifest.json","size":0,"sha256":"0".repeat(64)}));
    fixture.sign();
    code(&fixture.verify(None), "protection.inventory");
    fixture = Fixture::new();
    let inventory = fixture.manifest["extensions"][NAMESPACE]["data"]["inventory"]
        .as_array_mut()
        .unwrap();
    inventory.swap(0, 1);
    fixture.sign();
    code(&fixture.verify(None), "protection.inventory");
    fixture = Fixture::new();
    fixture.files.insert(
        format!("extensions/{NAMESPACE}/extra.txt"),
        b"Extension resource".to_vec(),
    );
    fixture.seal();
    status(&fixture.verify(None), Status::Passed);
    fixture
        .files
        .get_mut(&format!("extensions/{NAMESPACE}/extra.txt"))
        .unwrap()
        .push(b'x');
    code(&fixture.verify(None), "protection.inventory");
}

#[test]
fn signed_database_and_attachment_edits_still_need_correct_aead_context() {
    let mut fixture = Fixture::new();
    fixture.files.get_mut("assets/private.bin").unwrap()[28] ^= 1;
    fixture.seal();
    status(&fixture.verify(None), Status::Passed);
    code(
        &fixture.verify(Some(&Keys(KEY))),
        "protection.authentication",
    );
    fixture = Fixture::new();
    fixture.database(|db| {
        db.execute(
            "UPDATE notes SET secret=(SELECT secret FROM notes WHERE id='r1') WHERE id='r2'",
            [],
        )
        .unwrap();
    });
    fixture.seal();
    let report = fixture.verify(Some(&Keys(KEY)));
    code(&report, "protection.authentication");
    code(&report, "protection.nonce_reuse");
    fixture = Fixture::new();
    fixture.database(|db| {
        db.execute("UPDATE notes SET id='renamed' WHERE id='r1'", [])
            .unwrap();
    });
    fixture.seal();
    code(
        &fixture.verify(Some(&Keys(KEY))),
        "protection.authentication",
    );
    fixture = Fixture::new();
    fixture.manifest["extensions"][NAMESPACE]["data"]["packageId"] =
        json!("ffeeddccbbaa99887766554433221100");
    fixture.seal();
    code(
        &fixture.verify(Some(&Keys(KEY))),
        "protection.authentication",
    );
    fixture = Fixture::new();
    let bytes = fixture.files.remove("assets/private.bin").unwrap();
    fixture.files.insert("assets/moved.bin".into(), bytes);
    fixture.manifest["extensions"][NAMESPACE]["data"]["files"][0]["path"] =
        json!("assets/moved.bin");
    fixture.seal();
    code(
        &fixture.verify(Some(&Keys(KEY))),
        "protection.authentication",
    );
}

#[test]
fn unknown_required_extensions_allow_only_diagnostics_and_never_save() {
    let mut fixture = Fixture::new();
    fixture.manifest["extensions"]["org.example.unknown"] =
        json!({"version":"1","required":true,"data":{}});
    fixture.seal();
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    let options = fixture.options(None);
    code(&fixture.verify(None), "extension.required");
    assert!(darkbox::open(&path, Limits::default(), &options).is_err());
    let report = darkbox::analyze_with(&path, Mode::Inspect, Limits::default(), &options);
    status(&report, Status::Inspected);
    assert!(!report.checks.contains(&"protection.signature"));
    assert!(
        darkbox::save(
            &path,
            &path,
            PackageUpdate::default(),
            Limits::default(),
            &options,
            Some(&Signing::new())
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    fixture = Fixture::new();
    fixture.manifest["extensions"][NAMESPACE]["version"] = json!("9.0.0");
    fixture.sign();
    code(&fixture.verify(None), "protection.version");
    fixture = Fixture::new();
    let mut options = fixture.options(None);
    options.extensions = darkbox::ExtensionRegistry::empty();
    let report = darkbox::analyze_with(fixture.path(), Mode::Verify, Limits::default(), &options);
    code(&report, "extension.required");
}

#[test]
fn malformed_blobs_ids_blocks_and_optional_protection_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.database(|db| {
        db.execute("UPDATE notes SET secret='plaintext' WHERE id='r1'", [])
            .unwrap();
    });
    fixture.seal();
    code(&fixture.verify(None), "protection.sqlite_blob");
    fixture = Fixture::new();
    fixture.database(|db| {
        db.execute("UPDATE notes SET id=NULL WHERE id='r1'", [])
            .unwrap();
    });
    fixture.seal();
    code(&fixture.verify(None), "protection.record_id");
    fixture = Fixture::new();
    fixture.files.get_mut("assets/private.bin").unwrap()[4] = 2;
    fixture.seal();
    code(&fixture.verify(None), "protection.block_version");
    fixture = Fixture::new();
    fixture.files.get_mut("assets/private.bin").unwrap()[6] = 1;
    fixture.seal();
    code(&fixture.verify(None), "protection.block");
    fixture = Fixture::new();
    fixture.manifest["extensions"][NAMESPACE]["required"] = json!(false);
    fixture.sign();
    code(&fixture.verify(None), "protection.required");
    fixture = Fixture::new();
    fixture.manifest["extensions"]
        .as_object_mut()
        .unwrap()
        .remove(NAMESPACE);
    fixture.files.remove(SIGNATURE_PATH);
    fixture.manifest["folders"]
        .as_array_mut()
        .unwrap()
        .retain(|folder| !folder["path"].as_str().unwrap().starts_with("extensions"));
    fixture.files.insert(
        "manifest.json".into(),
        serde_json::to_vec_pretty(&fixture.manifest).unwrap(),
    );
    code(&fixture.verify(None), "protection.missing");
}

#[test]
fn writer_retains_ciphertext_for_public_edits_and_requires_signing_and_keys_for_changes() {
    let fixture = Fixture::new();
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    let options = fixture.options(None);
    let edit = || PackageUpdate {
        files: BTreeMap::from([("assets/public.txt".into(), Some(b"Public edit".to_vec()))]),
        ..Default::default()
    };
    assert!(darkbox::save(&path, &path, edit(), Limits::default(), &options, None).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    let destination = fixture.dir.path().join("saved.project");
    let report = darkbox::save(
        &path,
        &destination,
        edit(),
        Limits::default(),
        &options,
        Some(&Signing::new()),
    )
    .unwrap();
    status(&report, Status::Passed);
    assert_eq!(fs::read(&path).unwrap(), original);
    let old = fixture.verify(None).protection.unwrap().encrypted;
    let new = report.protection.unwrap().encrypted;
    assert_eq!(
        old.iter().map(|b| &b.block_sha256).collect::<Vec<_>>(),
        new.iter().map(|b| &b.block_sha256).collect::<Vec<_>>()
    );
    let mut nonces = Counter(20);
    let encrypted = protection::encrypt_block(
        b"Changed secret",
        &KEY,
        &file_context("assets/private.bin"),
        &mut nonces,
    )
    .unwrap();
    let update = || PackageUpdate {
        files: BTreeMap::from([("assets/private.bin".into(), Some(encrypted.clone()))]),
        ..Default::default()
    };
    assert!(
        darkbox::save(
            &path,
            &path,
            update(),
            Limits::default(),
            &options,
            Some(&Signing::new())
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    let keys = Keys(KEY);
    let options = fixture.options(Some(&keys));
    let report = darkbox::save(
        &path,
        &path,
        update(),
        Limits::default(),
        &options,
        Some(&Signing::new()),
    )
    .unwrap();
    status(&report, Status::Passed);
    assert_ne!(fs::read(&path).unwrap(), original);
    assert_eq!(
        fs::read_dir(fixture.dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with(".darkbox-save-"))
            .count(),
        0
    );
}

#[test]
fn writer_refuses_downgrade_moved_blocks_and_invalid_candidates_without_replacing_original() {
    let mut fixture = Fixture::new();
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    let mut manifest = fixture.manifest.clone();
    manifest["extensions"][NAMESPACE]["required"] = json!(false);
    assert!(
        darkbox::save(
            &path,
            &path,
            PackageUpdate {
                manifest: Some(manifest),
                ..Default::default()
            },
            Limits::default(),
            &fixture.options(None),
            Some(&Signing::new())
        )
        .is_err()
    );
    fixture.database(|db| {
        db.execute("UPDATE notes SET id='moved' WHERE id='r1'", [])
            .unwrap();
    });
    let update = PackageUpdate {
        files: BTreeMap::from([(DATABASE.into(), Some(fixture.files[DATABASE].clone()))]),
        ..Default::default()
    };
    assert!(
        darkbox::save(
            &path,
            &path,
            update,
            Limits::default(),
            &fixture.options(None),
            Some(&Signing::new())
        )
        .is_err()
    );
    let update = PackageUpdate {
        files: BTreeMap::from([(
            "README.md".into(),
            Some(b"Changed canonical bytes".to_vec()),
        )]),
        ..Default::default()
    };
    assert!(
        darkbox::save(
            &path,
            &path,
            update,
            Limits::default(),
            &fixture.options(None),
            Some(&Signing::new())
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
#[cfg(feature = "cli")]
fn cli_uses_external_key_files_and_never_reports_secret_keys() {
    let fixture = Fixture::new();
    let path = fixture.path();
    let trust = fixture.dir.path().join("trust.json");
    let keys = fixture.dir.path().join("keys.json");
    fs::write(&trust,json!({"test-signer":Signing::new().public_key().iter().map(|b|format!("{b:02x}")).collect::<String>()}).to_string()).unwrap();
    fs::write(&keys, json!({"test-key":"2a".repeat(32)}).to_string()).unwrap();
    for keyed in [false, true] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_darkbox"));
        command
            .arg("verify")
            .arg(&path)
            .arg("--json")
            .arg("--require-protection")
            .arg("--trust-store")
            .arg(&trust);
        if keyed {
            command.arg("--decryption-keys").arg(&keys);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["report_version"], 2);
        assert_eq!(report["protection"]["signature"], "verified");
        assert_eq!(
            report["protection"]["encrypted"][0]["authentication"],
            if keyed { "verified" } else { "key_absent" }
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&"2a".repeat(32)));
    }
    fs::write(&keys, "secret-invalid-json-key").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_darkbox"))
        .arg("verify")
        .arg(path)
        .arg("--decryption-keys")
        .arg(keys)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-invalid-json-key"));
}

#[test]
fn extension_registration_requires_explicit_writer_capability() {
    struct ReadOnly;
    impl darkbox::ExtensionVerifier for ReadOnly {
        fn namespace(&self) -> &str {
            "org.example.registered"
        }
        fn supports(&self, version: &str) -> bool {
            version == "1"
        }
        fn verify(
            &self,
            context: &darkbox::extensions::ExtensionContext<'_>,
            report: &mut darkbox::Report,
        ) -> Result<(), darkbox::Error> {
            assert!(!context.read("docs/profile.md")?.is_empty());
            report.note("example.checked", "Registered extension checked");
            Ok(())
        }
    }
    struct Writable;
    impl darkbox::ExtensionVerifier for Writable {
        fn namespace(&self) -> &str {
            "org.example.registered"
        }
        fn supports(&self, version: &str) -> bool {
            version == "1"
        }
        fn verify(
            &self,
            _: &darkbox::extensions::ExtensionContext<'_>,
            _: &mut darkbox::Report,
        ) -> Result<(), darkbox::Error> {
            Ok(())
        }
        fn prepare_save(
            &self,
            _: &Value,
            manifest: &mut Value,
            _: &mut BTreeMap<String, Vec<u8>>,
        ) -> Result<(), darkbox::Error> {
            manifest["extensions"]["org.example.registered"]["data"]["updated"] = json!(true);
            Ok(())
        }
    }
    let mut fixture = Fixture::new();
    fixture.manifest["extensions"]["org.example.registered"] =
        json!({"version":"1","required":true,"data":{}});
    fixture.seal();
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    let mut options = fixture.options(None);
    options.extensions.register(ReadOnly);
    let report = darkbox::analyze_with(&path, Mode::Verify, Limits::default(), &options);
    status(&report, Status::Passed);
    code(&report, "example.checked");
    let error = darkbox::save(
        &path,
        &path,
        PackageUpdate::default(),
        Limits::default(),
        &options,
        Some(&Signing::new()),
    )
    .unwrap_err();
    assert_eq!(error.code, "save.extension_capability");
    assert_eq!(fs::read(&path).unwrap(), original);
    options.extensions.register(Writable);
    let report = darkbox::save(
        &path,
        &path,
        PackageUpdate::default(),
        Limits::default(),
        &options,
        Some(&Signing::new()),
    )
    .unwrap();
    status(&report, Status::Passed);
    assert_eq!(
        report.manifest.unwrap()["extensions"]["org.example.registered"]["data"]["updated"],
        true
    );
    // Adding a recognized extension also invokes its writer gate.
    let fixture = Fixture::new();
    let path = fixture.path();
    let mut options = fixture.options(None);
    options.extensions.register(ReadOnly);
    let mut manifest = fixture.manifest.clone();
    manifest["extensions"]["org.example.registered"] =
        json!({"version":"1","required":true,"data":{}});
    assert_eq!(
        darkbox::save(
            &path,
            &path,
            PackageUpdate {
                manifest: Some(manifest),
                ..Default::default()
            },
            Limits::default(),
            &options,
            Some(&Signing::new())
        )
        .unwrap_err()
        .code,
        "save.extension_capability"
    );
}

#[test]
fn writer_preserves_unknown_optional_data_and_does_not_overwrite_separate_destinations() {
    let mut fixture = Fixture::new();
    fixture.manifest["extensions"]["org.example.opaque"] =
        json!({"version":"1","required":false,"data":{"opaque":["preserve",7]}});
    fixture.manifest["folders"].as_array_mut().unwrap().push(
        json!({"path":"extensions/org.example.opaque","description":"Opaque optional resources"}),
    );
    fixture.files.insert(
        "extensions/org.example.opaque/resource.bin".into(),
        vec![0, 255, 128],
    );
    fixture.seal();
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    let options = fixture.options(None);
    let update = PackageUpdate {
        files: BTreeMap::from([(
            "extensions/org.example.opaque/resource.bin".into(),
            Some(vec![1]),
        )]),
        ..Default::default()
    };
    assert!(
        darkbox::save(
            &path,
            &path,
            update,
            Limits::default(),
            &options,
            Some(&Signing::new())
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    let report = darkbox::save(
        &path,
        &path,
        PackageUpdate::default(),
        Limits::default(),
        &options,
        Some(&Signing::new()),
    )
    .unwrap();
    status(&report, Status::Passed);
    assert_eq!(
        report.manifest.unwrap()["extensions"]["org.example.opaque"],
        fixture.manifest["extensions"]["org.example.opaque"]
    );
    let destination = fixture.dir.path().join("existing.project");
    fs::write(&destination, b"Existing data").unwrap();
    assert!(
        darkbox::save(
            &path,
            &destination,
            PackageUpdate::default(),
            Limits::default(),
            &options,
            Some(&Signing::new())
        )
        .is_err()
    );
    assert_eq!(fs::read(destination).unwrap(), b"Existing data");
}

#[test]
fn aad_separates_every_context_field_and_binary_strings_unambiguously() {
    let context = row_context("r1");
    let bytes = protection::encrypt_block(b"private", &KEY, &context, &mut Counter(90)).unwrap();
    let mut contexts = Vec::new();
    let mut moved = context.clone();
    moved.key_id = "alias".into();
    contexts.push(moved);
    for index in 0..4 {
        let mut moved = context.clone();
        if let BlockLocation::Sqlite {
            database,
            table,
            column,
            record_id,
        } = &mut moved.location
        {
            match index {
                0 => *database = "data/other.sqlite".into(),
                1 => *table = "other".into(),
                2 => *column = "other".into(),
                _ => *record_id = "other".into(),
            }
        }
        contexts.push(moved);
    }
    for moved in contexts {
        assert_eq!(
            protection::decrypt_block(&bytes, &KEY, &moved)
                .unwrap_err()
                .code,
            "protection.authentication"
        );
    }
    let mut a = row_context("c");
    let mut b = row_context("bc");
    if let BlockLocation::Sqlite { table, column, .. } = &mut a.location {
        *table = "ab".into();
        *column = "x".into();
    }
    if let BlockLocation::Sqlite { table, column, .. } = &mut b.location {
        *table = "a".into();
        *column = "x".into();
    }
    let header = protection::block_header(&bytes).unwrap();
    assert_ne!(a.aad(header).unwrap(), b.aad(header).unwrap());
}

#[test]
fn schema_nonce_aliases_public_metadata_and_record_uniqueness_are_enforced() {
    let mut fixture = Fixture::new();
    fixture.manifest["extensions"][NAMESPACE]["data"]["files"][0]["path"] =
        json!("docs/profile.md");
    fixture.seal();
    code(&fixture.verify(None), "protection.file");
    fixture = Fixture::new();
    fixture.manifest["extensions"][NAMESPACE]["data"]["unexpectedKey"] = json!("forbidden");
    fixture.sign();
    code(&fixture.verify(None), "protection.schema");
    fixture = Fixture::new();
    fixture.database(|db| {db.execute_batch("ALTER TABLE notes RENAME TO original; CREATE TABLE notes(id TEXT,label TEXT,secret BLOB); INSERT INTO notes SELECT * FROM original; DROP TABLE original; UPDATE notes SET id='r1' WHERE id='r2';").unwrap();});
    fixture.seal();
    code(&fixture.verify(None), "protection.record_id");
    fixture = Fixture::new();
    let mut context = file_context("assets/alias.bin");
    context.key_id = "alias".into();
    let bytes =
        protection::encrypt_block(b"alias secret", &KEY, &context, &mut Counter(0)).unwrap();
    fixture.files.insert("assets/alias.bin".into(), bytes);
    fixture.manifest["extensions"][NAMESPACE]["data"]["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({"path":"assets/alias.bin","keyId":"alias"}));
    fixture.seal();
    struct Aliases;
    impl DecryptionKeys for Aliases {
        fn key(&self, _: &str) -> Option<Zeroizing<[u8; 32]>> {
            Some(Zeroizing::new(KEY))
        }
    }
    status(&fixture.verify(None), Status::Passed);
    code(&fixture.verify(Some(&Aliases)), "protection.nonce_reuse");
}

#[test]
fn writer_rejects_a_new_encryption_reusing_a_previous_revision_nonce() {
    let fixture = Fixture::new();
    let path = fixture.path();
    let original = fs::read(&path).unwrap();
    // The candidate itself has distinct nonces; nonce 1 replaces nonce 1 from the source.
    let encrypted = protection::encrypt_block(
        b"Changed private value",
        &KEY,
        &file_context("assets/private.bin"),
        &mut Counter(0),
    )
    .unwrap();
    let keys = Keys(KEY);
    let options = fixture.options(Some(&keys));
    let update = PackageUpdate {
        files: BTreeMap::from([("assets/private.bin".into(), Some(encrypted))]),
        ..Default::default()
    };
    let error = darkbox::save(
        &path,
        &path,
        update,
        Limits::default(),
        &options,
        Some(&Signing::new()),
    )
    .unwrap_err();
    assert_eq!(error.code, "protection.nonce_reuse");
    assert_eq!(fs::read(&path).unwrap(), original);
}
