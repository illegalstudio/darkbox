use darkbox::extensions::EntryDigest;
use darkbox::protection::{
    self, BlockContext, BlockLocation, DecryptionKeys, ManifestSigner, NAMESPACE, NonceSequence,
    SIGNATURE_PATH,
};
use darkbox::{Limits, PackageWriter, Status, VerificationOptions};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zeroize::Zeroizing;

const KEY: [u8; 32] = [42; 32];
const PACKAGE: &str = "00112233445566778899aabbccddeeff";
const DATABASE: &str = "data/project.sqlite";

struct Keys;
impl DecryptionKeys for Keys {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        (id == "test-key").then(|| Zeroizing::new(KEY))
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
fn context(location: BlockLocation) -> BlockContext {
    BlockContext {
        package_id: PACKAGE.into(),
        key_id: "test-key".into(),
        location,
    }
}
fn file_context(path: &str) -> BlockContext {
    context(BlockLocation::File { path: path.into() })
}

struct Fixture {
    dir: TempDir,
    manifest: Value,
    sources: BTreeMap<String, PathBuf>,
    signing: Signing,
    keys: Keys,
}
impl Fixture {
    fn new(protected: bool) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("darkbox-create-tests-")
            .tempdir()
            .unwrap();
        let mut manifest: Value =
            serde_json::from_slice(include_bytes!("../examples/notebook.manifest.json")).unwrap();
        manifest["application"] = json!({"id":"org.example.streaming","formatVersion":"1","profilePath":"docs/profile.md"});
        manifest["databases"][0]["userVersion"] = json!(1);
        manifest["databases"][0]["tables"] =
            json!([{"name":"notes","description":"Public labels and optional protected values"}]);
        manifest["folders"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path":"assets","description":"Attachments"}));
        let database = dir.path().join("snapshot.sqlite");
        let db = Connection::open(&database).unwrap();
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY NOT NULL,label TEXT,secret BLOB);").unwrap();
        let mut nonces = Counter(0);
        for id in ["r1", "r2"] {
            let block = protected.then(|| {
                protection::encrypt_block(
                    b"Private",
                    &KEY,
                    &context(BlockLocation::Sqlite {
                        database: DATABASE.into(),
                        table: "notes".into(),
                        column: "secret".into(),
                        record_id: id.into(),
                    }),
                    &mut nonces,
                )
                .unwrap()
            });
            db.execute(
                "INSERT INTO notes VALUES (?1,'Public',?2)",
                params![id, block],
            )
            .unwrap();
        }
        drop(db);
        let profile = dir.path().join("profile.md");
        fs::write(&profile,b"# org.example.streaming, format 1\n\nnotes.id is unique immutable TEXT; label is public TEXT. secret is NULL or one protected BLOB of opaque bytes. Extension file declarations identify required encrypted attachments.\n").unwrap();
        let public = dir.path().join("public.bin");
        fs::write(&public, b"Public attachment").unwrap();
        let mut sources = BTreeMap::from([
            (DATABASE.into(), database),
            ("docs/profile.md".into(), profile),
            ("assets/public.bin".into(), public),
        ]);
        if protected {
            manifest["folders"].as_array_mut().unwrap().extend([json!({"path":"extensions","description":"Extensions"}),json!({"path":format!("extensions/{NAMESPACE}"),"description":"Detached signature"})]);
            manifest["extensions"][NAMESPACE] = json!({"version":"1.0.0","required":true,"data":{"packageId":PACKAGE,"signature":{"algorithm":"Ed25519","signerId":"test-signer","path":SIGNATURE_PATH},"inventory":[],"files":[{"path":"assets/private.bin","keyId":"test-key"}],"sqlite":[{"database":DATABASE,"table":"notes","column":"secret","recordIdColumn":"id","keyId":"test-key"}]}});
            let private = dir.path().join("encrypted.bin");
            fs::write(
                &private,
                protection::encrypt_block(
                    b"Private file",
                    &KEY,
                    &file_context("assets/private.bin"),
                    &mut Counter(100),
                )
                .unwrap(),
            )
            .unwrap();
            sources.insert("assets/private.bin".into(), private);
        }
        Self {
            dir,
            manifest,
            sources,
            signing: Signing::new(),
            keys: Keys,
        }
    }
    fn options(&self, keyed: bool) -> VerificationOptions<'_> {
        VerificationOptions {
            decryption_keys: if keyed { Some(&self.keys) } else { None },
            trusted_signers: BTreeMap::from([("test-signer".into(), self.signing.public_key())]),
            ..Default::default()
        }
    }
    fn publish(
        &self,
        path: &Path,
        manifest: Value,
        sources: &BTreeMap<String, PathBuf>,
        keyed: bool,
    ) -> Result<darkbox::Report, darkbox::Error> {
        let options = self.options(keyed);
        let mut writer = PackageWriter::new(
            path,
            manifest,
            Limits::default(),
            &options,
            Some(&self.signing),
        )?;
        for (name, source) in sources {
            writer.add_path(name, source)?;
        }
        writer.finish()
    }
    fn output(&self) -> PathBuf {
        self.dir.path().join("output.project")
    }
    fn assert_clean(&self) {
        assert!(
            !fs::read_dir(self.dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".darkbox-create-"))
        );
    }
}

#[test]
fn streams_paths_and_lazy_readers_with_automatic_canonical_bundles() {
    for version in ["1.0.0", "1.1.0"] {
        let mut fixture = Fixture::new(false);
        fixture.manifest["darkbox"]["version"] = json!(version);
        if version == "1.0.0" {
            fixture.manifest["folders"]
                .as_array_mut()
                .unwrap()
                .retain(|folder| folder["path"] != "docs/darkbox/protection");
        }
        let options = fixture.options(false);
        let path = fixture.output();
        let mut writer = PackageWriter::new(
            &path,
            fixture.manifest.clone(),
            Limits::default(),
            &options,
            None,
        )
        .unwrap();
        for (name, source) in &fixture.sources {
            writer.add_path(name, source).unwrap();
        }
        struct Lazy<'a> {
            remaining: u64,
            largest: &'a Cell<usize>,
        }
        impl Read for Lazy<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                self.largest.set(self.largest.get().max(buffer.len()));
                let count = buffer.len().min(self.remaining as usize);
                buffer[..count].fill(0x5a);
                self.remaining -= count as u64;
                Ok(count)
            }
        }
        let largest = Cell::new(0);
        let size = 16 * 1024 * 1024;
        let entry = writer
            .add_reader(
                "assets/large.bin",
                Lazy {
                    remaining: size,
                    largest: &largest,
                },
            )
            .unwrap();
        assert_eq!(entry.size, size);
        assert_eq!(largest.get(), 65_536);
        let mut expected = Sha256::new();
        for _ in 0..512 {
            expected.update([0x5a; 32768]);
        }
        let expected_hash = format!("{:x}", expected.finalize());
        assert_eq!(entry.sha256, expected_hash);
        let report = writer.finish().unwrap();
        assert_eq!(report.status, Status::Passed);
        assert!(report.checks.contains(&"bundle.canonical"));
        let mut archive = zip::ZipArchive::new(fs::File::open(&path).unwrap()).unwrap();
        let mut entry = archive.by_name("assets/large.bin").unwrap();
        let mut hash = Sha256::new();
        io::copy(&mut entry, &mut HashWriter(&mut hash)).unwrap();
        assert_eq!(format!("{:x}", hash.finalize()), expected_hash);
        fixture.assert_clean();
    }
}
struct HashWriter<'a>(&'a mut Sha256);
impl io::Write for HashWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn protected_creation_signs_exact_final_manifest_and_inventories_every_file() {
    let fixture = Fixture::new(true);
    let path = fixture.output();
    let report = fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
        .unwrap();
    assert_eq!(report.status, Status::Passed);
    let protection = report.protection.unwrap();
    assert_eq!(protection.signature, "verified");
    assert!(protection.inventory_verified);
    assert!(
        protection
            .encrypted
            .iter()
            .all(|block| block.authentication == "verified")
    );
    let mut archive = zip::ZipArchive::new(fs::File::open(path).unwrap()).unwrap();
    let mut bytes = Vec::new();
    archive
        .by_name("manifest.json")
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    let mut signature = Vec::new();
    archive
        .by_name(SIGNATURE_PATH)
        .unwrap()
        .read_to_end(&mut signature)
        .unwrap();
    fixture
        .signing
        .0
        .verifying_key()
        .verify_strict(
            &bytes,
            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
        )
        .unwrap();
    let inventory: Vec<EntryDigest> =
        serde_json::from_value(manifest["extensions"][NAMESPACE]["data"]["inventory"].clone())
            .unwrap();
    assert!(inventory.windows(2).all(|pair| pair[0].path < pair[1].path));
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        if entry.is_dir() || entry.name() == "manifest.json" || entry.name() == SIGNATURE_PATH {
            continue;
        }
        let expected = inventory
            .iter()
            .find(|record| record.path == entry.name())
            .unwrap();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert_eq!(expected.size, bytes.len() as u64);
        assert_eq!(expected.sha256, format!("{:x}", Sha256::digest(bytes)));
    }
    fixture.assert_clean();
}

#[test]
fn replacement_editions_can_add_and_remove_encrypted_resources() {
    let fixture = Fixture::new(true);
    let path = fixture.output();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let mut manifest = fixture.manifest.clone();
    manifest["extensions"][NAMESPACE]["data"]["files"] =
        json!([{"path":"assets/new.bin","keyId":"test-key"}]);
    let new = fixture.dir.path().join("new.bin");
    fs::write(
        &new,
        protection::encrypt_block(
            b"New private content",
            &KEY,
            &file_context("assets/new.bin"),
            &mut Counter(200),
        )
        .unwrap(),
    )
    .unwrap();
    let mut sources = fixture.sources.clone();
    sources.remove("assets/private.bin");
    sources.insert("assets/new.bin".into(), new);
    let report = fixture.publish(&path, manifest, &sources, true).unwrap();
    assert_eq!(report.status, Status::Passed);
    assert_ne!(fs::read(&path).unwrap(), original);
    let mut archive = zip::ZipArchive::new(fs::File::open(&path).unwrap()).unwrap();
    assert!(archive.by_name("assets/private.bin").is_err());
    assert!(archive.by_name("assets/new.bin").is_ok());
    fixture.assert_clean();
}

#[test]
fn unchanged_ciphertext_is_retained_without_keys_but_new_or_moved_ciphertext_is_not() {
    let fixture = Fixture::new(true);
    let path = fixture.output();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
        .unwrap();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, false)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let fresh = fixture.dir.path().join("fresh.project");
    assert!(
        fixture
            .publish(&fresh, fixture.manifest.clone(), &fixture.sources, false)
            .is_err()
    );
    assert!(!fresh.exists());
    let mut manifest = fixture.manifest.clone();
    manifest["extensions"][NAMESPACE]["data"]["files"][0]["path"] = json!("assets/moved.bin");
    let mut sources = fixture.sources.clone();
    let private = sources.remove("assets/private.bin").unwrap();
    sources.insert("assets/moved.bin".into(), private);
    assert!(fixture.publish(&path, manifest, &sources, false).is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    fixture.assert_clean();
}

#[test]
fn malformed_candidate_reader_and_signing_errors_preserve_previous_destination() {
    let fixture = Fixture::new(true);
    let path = fixture.output();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let options = fixture.options(true);
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        Some(&fixture.signing),
    )
    .unwrap();
    for (name, source) in &fixture.sources {
        if name == DATABASE {
            writer.add_reader(name, Cursor::new(b"not SQLite")).unwrap();
        } else {
            writer.add_path(name, source).unwrap();
        }
    }
    assert!(writer.finish().is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("Source failed"))
        }
    }
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        Some(&fixture.signing),
    )
    .unwrap();
    assert_eq!(
        writer
            .add_reader("assets/broken.bin", Broken)
            .unwrap_err()
            .code,
        "create.read"
    );
    assert_eq!(writer.finish().unwrap_err().code, "create.failed");
    assert_eq!(fs::read(&path).unwrap(), original);
    struct BadSigning(Signing);
    impl ManifestSigner for BadSigning {
        fn signer_id(&self) -> &str {
            "test-signer"
        }
        fn public_key(&self) -> [u8; 32] {
            self.0.public_key()
        }
        fn sign(&self, _: &[u8]) -> Result<[u8; 64], darkbox::Error> {
            Err(darkbox::Error::new(
                Status::OperationalError,
                "test.signing",
                "Signer failed",
            ))
        }
    }
    let signing = BadSigning(Signing::new());
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        Some(&signing),
    )
    .unwrap();
    for (name, source) in &fixture.sources {
        writer.add_path(name, source).unwrap();
    }
    assert_eq!(writer.finish().unwrap_err().code, "test.signing");
    assert_eq!(fs::read(&path).unwrap(), original);
    fixture.assert_clean();
}

#[test]
fn limits_reserved_names_collisions_and_ignored_errors_never_publish() {
    let fixture = Fixture::new(false);
    let options = fixture.options(false);
    for resource in [
        "manifest.json",
        "README.md",
        "docs/darkbox/extra.txt",
        "docs/sqlite/extra.txt",
        SIGNATURE_PATH,
        "../escape",
    ] {
        let path = fixture.output();
        let mut writer = PackageWriter::new(
            &path,
            fixture.manifest.clone(),
            Limits::default(),
            &options,
            None,
        )
        .unwrap();
        assert!(
            writer
                .add_reader(resource, Cursor::new(b"invalid"))
                .is_err()
        );
        assert!(writer.finish().is_err());
        assert!(!path.exists());
        fixture.assert_clean();
    }
    let limits = Limits {
        max_entry_bytes: 256 * 1024,
        ..Limits::default()
    };
    let path = fixture.output();
    let mut writer =
        PackageWriter::new(&path, fixture.manifest.clone(), limits, &options, None).unwrap();
    assert_eq!(
        writer
            .add_reader("assets/large.bin", io::repeat(0).take(300 * 1024))
            .unwrap_err()
            .status,
        Status::ResourceLimit
    );
    assert!(writer.finish().is_err());
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        None,
    )
    .unwrap();
    writer
        .add_reader("assets/one.bin", Cursor::new(b"one"))
        .unwrap();
    assert!(
        writer
            .add_reader("assets/ONE.bin", Cursor::new(b"collision"))
            .is_err()
    );
    assert!(writer.finish().is_err());
    fixture.assert_clean();
}

#[test]
fn changed_destinations_and_required_protection_downgrades_are_refused() {
    let fixture = Fixture::new(true);
    let path = fixture.output();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let options = fixture.options(true);
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        Some(&fixture.signing),
    )
    .unwrap();
    for (name, source) in &fixture.sources {
        writer.add_path(name, source).unwrap();
    }
    fs::write(&path, b"External modification").unwrap();
    assert_eq!(
        writer.finish().unwrap_err().code,
        "create.destination_changed"
    );
    assert_eq!(fs::read(&path).unwrap(), b"External modification");
    fs::write(&path, &original).unwrap();
    let mut manifest = fixture.manifest.clone();
    manifest["extensions"]
        .as_object_mut()
        .unwrap()
        .remove(NAMESPACE);
    assert!(
        fixture
            .publish(&path, manifest, &fixture.sources, true)
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut manifest = fixture.manifest.clone();
    manifest["extensions"][NAMESPACE]["data"]["files"] = json!([]);
    assert_eq!(
        fixture
            .publish(&path, manifest, &fixture.sources, true)
            .unwrap_err()
            .code,
        "create.protection_downgrade"
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    fixture.assert_clean();
}

#[test]
fn unknown_required_extensions_and_streaming_capabilities_are_distinct() {
    struct Registered;
    impl darkbox::ExtensionVerifier for Registered {
        fn namespace(&self) -> &str {
            "org.example.registered"
        }
        fn supports(&self, v: &str) -> bool {
            v == "1"
        }
        fn verify(
            &self,
            _: &darkbox::extensions::ExtensionContext<'_>,
            _: &mut darkbox::Report,
        ) -> Result<(), darkbox::Error> {
            Ok(())
        }
    }
    let mut fixture = Fixture::new(false);
    fixture.manifest["extensions"]["org.example.registered"] =
        json!({"version":"1","required":true,"data":{}});
    let path = fixture.output();
    assert_eq!(
        fixture
            .publish(&path, fixture.manifest.clone(), &fixture.sources, false)
            .unwrap_err()
            .code,
        "extension.required"
    );
    assert!(!path.exists());
    let mut options = fixture.options(false);
    options.extensions.register(Registered);
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        None,
    )
    .unwrap();
    for (name, source) in &fixture.sources {
        writer.add_path(name, source).unwrap();
    }
    assert_eq!(
        writer.finish().unwrap_err().code,
        "create.extension_capability"
    );
    fixture.assert_clean();
}

#[test]
fn streamed_optional_extension_resources_must_survive_new_editions() {
    let mut fixture = Fixture::new(false);
    fixture.manifest["extensions"]["org.example.opaque"] =
        json!({"version":"9","required":false,"data":{"meaning":"opaque"}});
    fixture.manifest["folders"].as_array_mut().unwrap().extend([
        json!({"path":"extensions","description":"Extensions"}),
        json!({"path":"extensions/org.example.opaque","description":"Opaque resources"}),
    ]);
    let resource = fixture.dir.path().join("opaque.bin");
    fs::write(&resource, [0, 255, 128]).unwrap();
    fixture.sources.insert(
        "extensions/org.example.opaque/resource.bin".into(),
        resource,
    );
    let path = fixture.output();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, false)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let mut sources = fixture.sources.clone();
    sources.remove("extensions/org.example.opaque/resource.bin");
    assert_eq!(
        fixture
            .publish(&path, fixture.manifest.clone(), &sources, false)
            .unwrap_err()
            .code,
        "create.optional_preservation"
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    fixture.assert_clean();
}

#[test]
fn replacement_rejects_nonce_reuse_and_bad_context_even_with_valid_signing() {
    let fixture = Fixture::new(true);
    let path = fixture.output();
    fixture
        .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
        .unwrap();
    let original = fs::read(&path).unwrap();
    let private = fixture.sources.get("assets/private.bin").unwrap();
    fs::write(
        private,
        protection::encrypt_block(
            b"Changed secret",
            &KEY,
            &file_context("assets/private.bin"),
            &mut Counter(100),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
            .unwrap_err()
            .code,
        "protection.nonce_reuse"
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut bad = file_context("assets/private.bin");
    bad.package_id = "ffeeddccbbaa99887766554433221100".into();
    fs::write(
        private,
        protection::encrypt_block(b"Wrong package", &KEY, &bad, &mut Counter(300)).unwrap(),
    )
    .unwrap();
    assert!(
        fixture
            .publish(&path, fixture.manifest.clone(), &fixture.sources, true)
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    fixture.assert_clean();
}

#[test]
fn archive_metadata_total_entry_and_time_budgets_are_enforced() {
    let fixture = Fixture::new(false);
    let options = fixture.options(false);
    let path = fixture.output();
    for limits in [
        Limits {
            max_archive_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_metadata_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_total_bytes: 1,
            ..Limits::default()
        },
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
        Limits {
            timeout_seconds: 0,
            ..Limits::default()
        },
    ] {
        let error = PackageWriter::new(&path, fixture.manifest.clone(), limits, &options, None)
            .err()
            .unwrap();
        assert_eq!(error.status, Status::ResourceLimit);
        assert!(!path.exists());
        fixture.assert_clean();
    }
    struct Noise(u64);
    impl Read for Noise {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            for byte in buffer.iter_mut() {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0 as u8;
            }
            Ok(buffer.len())
        }
    }
    let limits = Limits {
        max_archive_bytes: 512 * 1024,
        ..Limits::default()
    };
    let mut writer =
        PackageWriter::new(&path, fixture.manifest.clone(), limits, &options, None).unwrap();
    assert_eq!(
        writer
            .add_reader("assets/noise.bin", Noise(41).take(2 * 1024 * 1024))
            .unwrap_err()
            .status,
        Status::ResourceLimit
    );
    assert!(writer.finish().is_err());
    fixture.assert_clean();
    let limits = Limits {
        max_metadata_bytes: 20_000,
        ..Limits::default()
    };
    let protected = Fixture::new(true);
    let options = protected.options(true);
    let path = protected.output();
    let mut writer = PackageWriter::new(
        &path,
        protected.manifest.clone(),
        limits,
        &options,
        Some(&protected.signing),
    )
    .unwrap();
    for (name, source) in &protected.sources {
        writer.add_path(name, source).unwrap();
    }
    for index in 0..300 {
        writer
            .add_reader(&format!("assets/entry-{index}.bin"), io::empty())
            .unwrap();
    }
    assert_eq!(writer.finish().unwrap_err().status, Status::ResourceLimit);
    assert!(!path.exists());
    protected.assert_clean();
    struct Slow;
    impl Read for Slow {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            std::thread::sleep(std::time::Duration::from_millis(1100));
            buffer[0] = 1;
            Ok(1)
        }
    }
    let fixture = Fixture::new(false);
    let options = fixture.options(false);
    let path = fixture.output();
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits {
            timeout_seconds: 1,
            ..Limits::default()
        },
        &options,
        None,
    )
    .unwrap();
    assert_eq!(
        writer
            .add_reader("assets/slow.bin", Slow)
            .unwrap_err()
            .status,
        Status::ResourceLimit
    );
    assert!(writer.finish().is_err());
    assert!(!path.exists());
    fixture.assert_clean();
}

#[test]
fn registered_streaming_extension_receives_actual_inventory_before_signing() {
    struct Registered;
    impl darkbox::ExtensionVerifier for Registered {
        fn namespace(&self) -> &str {
            "org.example.registered"
        }
        fn supports(&self, version: &str) -> bool {
            version == "1"
        }
        fn prepare_streamed_package(
            &self,
            _: Option<&Value>,
            manifest: &mut Value,
            inventory: &BTreeMap<String, EntryDigest>,
        ) -> Result<(), darkbox::Error> {
            assert!(!inventory.contains_key("manifest.json"));
            assert!(!inventory.contains_key(SIGNATURE_PATH));
            manifest["extensions"]["org.example.registered"]["data"]["sha256"] =
                json!(inventory["assets/public.bin"].sha256);
            Ok(())
        }
        fn verify(
            &self,
            context: &darkbox::extensions::ExtensionContext<'_>,
            report: &mut darkbox::Report,
        ) -> Result<(), darkbox::Error> {
            assert_eq!(
                context.manifest["extensions"]["org.example.registered"]["data"]["sha256"],
                context.inventory["assets/public.bin"].sha256
            );
            report.note("registered.verified", "Complete resource digest matched");
            Ok(())
        }
    }
    let mut fixture = Fixture::new(true);
    fixture.manifest["extensions"]["org.example.registered"] =
        json!({"version":"1","required":true,"data":{}});
    let mut options = fixture.options(true);
    options.extensions.register(Registered);
    let path = fixture.output();
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        Some(&fixture.signing),
    )
    .unwrap();
    for (name, source) in &fixture.sources {
        writer.add_path(name, source).unwrap();
    }
    let report = writer.finish().unwrap();
    assert_eq!(report.status, Status::Passed);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "registered.verified")
    );
    assert_eq!(report.protection.unwrap().signature, "verified");
    fixture.assert_clean();
}

#[test]
fn abandoning_writer_and_missing_sources_remove_only_the_private_candidate() {
    let fixture = Fixture::new(false);
    let options = fixture.options(false);
    let path = fixture.output();
    {
        let mut writer = PackageWriter::new(
            &path,
            fixture.manifest.clone(),
            Limits::default(),
            &options,
            None,
        )
        .unwrap();
        writer
            .add_reader("assets/partial.bin", Cursor::new(b"Partial input"))
            .unwrap();
    }
    assert!(!path.exists());
    fixture.assert_clean();
    let mut writer = PackageWriter::new(
        &path,
        fixture.manifest.clone(),
        Limits::default(),
        &options,
        None,
    )
    .unwrap();
    assert!(
        writer
            .add_path("assets/missing.bin", fixture.dir.path().join("absent.file"))
            .is_err()
    );
    assert!(writer.finish().is_err());
    assert!(!path.exists());
    fixture.assert_clean();
}

#[test]
fn callbacks_cannot_introduce_unprepared_required_extensions_or_protection() {
    struct Mutation(bool);
    impl darkbox::ExtensionVerifier for Mutation {
        fn namespace(&self) -> &str {
            "org.example.mutation"
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
        fn prepare_streamed_package(
            &self,
            _: Option<&Value>,
            manifest: &mut Value,
            _: &BTreeMap<String, EntryDigest>,
        ) -> Result<(), darkbox::Error> {
            let namespace = if self.0 {
                NAMESPACE
            } else {
                "org.example.added"
            };
            manifest["extensions"][namespace] =
                json!({"version":"1.0.0","required":true,"data":{}});
            Ok(())
        }
    }
    for protected in [false, true] {
        let mut fixture = Fixture::new(false);
        fixture.manifest["extensions"]["org.example.mutation"] =
            json!({"version":"1","required":true,"data":{}});
        let mut options = fixture.options(false);
        options.extensions.register(Mutation(protected));
        let path = fixture.output();
        let mut writer = PackageWriter::new(
            &path,
            fixture.manifest.clone(),
            Limits::default(),
            &options,
            None,
        )
        .unwrap();
        for (name, source) in &fixture.sources {
            writer.add_path(name, source).unwrap();
        }
        assert_eq!(
            writer.finish().unwrap_err().code,
            "create.extension_mutation"
        );
        assert!(!path.exists());
        fixture.assert_clean();
    }
}
