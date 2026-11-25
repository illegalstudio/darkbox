//! The language-neutral conformance corpus in `conformance/`. Every committed
//! case must produce its documented outcome with this reference implementation.
//! `regenerate_corpus` rebuilds the cases; it is ignored by default because the
//! committed archives are the test vectors, not a build product.
use darkbox::protection::{self, BlockContext, BlockLocation, DecryptionKeys, NonceSequence};
use darkbox::zeroize::Zeroizing;
use darkbox::{Limits, Mode, Report, Status, VerificationOptions};
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

/// Lowercase hexadecimal digits of a digest.
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const VERSION: &str = "1.6.0";
const PROTECTION: &str = "studio.illegal.darkbox.protection";
const DATABASE: &str = "data/project.sqlite";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance")
}

/// The outcome classes an independent implementation must distinguish.
fn outcome(status: Status) -> String {
    match status {
        Status::Passed => "valid".into(),
        Status::Invalid => "invalid".into(),
        Status::Unsupported => "unsupported".into(),
        // The corpus has no case for any other status, so this never matches one.
        other => other.to_string(),
    }
}

#[test]
fn reference_implementation_agrees_with_the_corpus() {
    // The corpus is repository material and is not part of the published crate.
    if !root().is_dir() {
        return;
    }
    let mut versions = 0;
    for directory in fs::read_dir(root()).unwrap() {
        let directory = directory.unwrap().path();
        if !directory.is_dir() {
            continue;
        }
        let index: Value =
            serde_json::from_slice(&fs::read(directory.join("cases.json")).unwrap()).unwrap();
        assert_eq!(
            index["darkbox"],
            directory.file_name().unwrap().to_str().unwrap()
        );
        let cases = index["cases"].as_array().unwrap();
        let mut listed = Vec::new();
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let file = case["file"].as_str().unwrap();
            listed.push(file.to_owned());
            let path = directory.join(file);
            let bytes = fs::read(&path).unwrap_or_else(|_| panic!("Missing corpus file: {id}"));
            assert_eq!(case["sha256"], hex(Sha256::digest(&bytes)), "{id}");
            let report = run(&directory, case);
            assert_eq!(
                case["expected"],
                outcome(report.status),
                "{id}: {}",
                serde_json::to_string_pretty(&report.diagnostics).unwrap()
            );
            if let Some(code) = case["referenceDiagnostic"].as_str() {
                assert!(
                    report
                        .diagnostics
                        .iter()
                        .any(|diagnostic| diagnostic.code == code),
                    "{id}: expected {code}: {}",
                    serde_json::to_string_pretty(&report.diagnostics).unwrap()
                );
            }
        }
        // Every archive in the directory is a documented case.
        let mut present: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".zip"))
            .collect();
        present.sort();
        listed.sort();
        assert_eq!(present, listed);
        versions += 1;
    }
    assert!(versions >= 1);
}

/// Keys of one `inputs` member: identifiers mapped to 64 hexadecimal digits.
fn key_map(value: &Value) -> BTreeMap<String, [u8; 32]> {
    let mut keys = BTreeMap::new();
    for (id, text) in value.as_object().into_iter().flatten() {
        let text = text.as_str().unwrap();
        assert_eq!(text.len(), 64, "{id}");
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
        }
        keys.insert(id.clone(), key);
    }
    keys
}

struct Keys(BTreeMap<String, [u8; 32]>);
impl DecryptionKeys for Keys {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        self.0.get(id).map(|key| Zeroizing::new(*key))
    }
}

/// Verify one case as the corpus documents it: offline, with default limits and
/// only the inputs the case lists.
fn run(directory: &Path, case: &Value) -> Report {
    let path = directory.join(case["file"].as_str().unwrap());
    let inputs = &case["inputs"];
    let keys = Keys(key_map(&inputs["decryptionKeys"]));
    let mut options =
        VerificationOptions::default().with_trusted_signers(key_map(&inputs["trustedSigners"]));
    if !keys.0.is_empty() {
        options = options.with_decryption_keys(&keys);
    }
    match inputs["base"].as_str() {
        Some(base) => {
            darkbox::verify_delta(directory.join(base), &path, Limits::default(), &options)
                .unwrap_or_else(|failure| {
                    Report::from_failure(
                        Mode::Verify,
                        path.display().to_string(),
                        Limits::default(),
                        failure,
                    )
                })
        }
        None => darkbox::analyze_with(&path, Mode::Verify, Limits::default(), &options),
    }
}

type Files = BTreeMap<String, Vec<u8>>;

fn collect(base: &Path, directory: &Path, files: &mut Files) {
    for entry in fs::read_dir(directory).unwrap() {
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

fn database(statements: &str) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch(statements).unwrap();
    drop(connection);
    fs::read(path).unwrap()
}

const SCHEMA: &str = "PRAGMA journal_mode=DELETE; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY, title TEXT NOT NULL); INSERT INTO notes VALUES('n1','First note');";

const PROFILE: &str = "# org.example.conformance, format 1\n\nProfile identifier: org.example.conformance. Data-format version: 1.\n\nThe database data/project.sqlite has SQLite user_version 1 and one table.\n\n- notes.id: stable unique TEXT identifier.\n- notes.title: UTF-8 title, never NULL.\n\nThere are no attachments, external dependencies or derived caches.\n";

struct Sample {
    files: Files,
    manifest: Value,
    /// Declared folders deliberately left without any entry.
    absent_folders: Vec<&'static str>,
}

impl Sample {
    fn new() -> Self {
        let mut files = Files::new();
        let base = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("archive")
            .join(VERSION);
        collect(&base, &base, &mut files);
        files.insert(DATABASE.into(), database(SCHEMA));
        files.insert("docs/profile.md".into(), PROFILE.as_bytes().to_vec());
        let folder =
            |path: &str, description: &str| json!({"path": path, "description": description});
        let manifest = json!({
            "darkbox": {"id": "darkbox", "version": VERSION},
            "application": {"id": "org.example.conformance", "formatVersion": "1", "profilePath": "docs/profile.md"},
            "folders": [
                folder("data", "Application database"),
                folder("docs", "Documentation"),
                folder("docs/darkbox", "Canonical Darkbox documentation"),
                folder("docs/sqlite", "Canonical SQLite reference"),
                folder("docs/sqlite/images", "Images of the SQLite reference"),
            ],
            "databases": [{
                "path": DATABASE,
                "description": "Notes",
                "userVersion": 1,
                "tables": [{"name": "notes", "description": "One row per note"}],
            }],
        });
        Self {
            files,
            manifest,
            absent_folders: Vec::new(),
        }
    }
    fn folder(&mut self, path: &str) {
        self.manifest["folders"]
            .as_array_mut()
            .unwrap()
            .push(json!({"path": path, "description": "Declared for this case"}));
    }
    /// Entries in bytewise path order, with explicit entries for empty folders.
    fn zip(mut self, method: CompressionMethod, zip64: bool) -> Vec<u8> {
        if !self.files.contains_key("manifest.json") && !self.manifest.is_null() {
            let mut bytes = serde_json::to_vec_pretty(&self.manifest).unwrap();
            bytes.push(b'\n');
            self.files.insert("manifest.json".into(), bytes);
        }
        for folder in self.manifest["folders"].as_array().into_iter().flatten() {
            let path = folder["path"].as_str().unwrap();
            if !self.absent_folders.contains(&path)
                && !self
                    .files
                    .keys()
                    .any(|name| name.starts_with(&format!("{path}/")))
            {
                self.files.insert(format!("{path}/"), Vec::new());
            }
        }
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .compression_method(method)
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644)
            .large_file(zip64);
        for (name, bytes) in &self.files {
            if name.ends_with('/') {
                zip.add_directory(name.as_str(), options).unwrap();
            } else {
                zip.start_file(name.as_str(), options).unwrap();
                zip.write_all(bytes).unwrap();
            }
        }
        zip.finish().unwrap().into_inner()
    }
    fn deflated(self) -> Vec<u8> {
        self.zip(CompressionMethod::Deflated, false)
    }
    fn stored(self) -> Vec<u8> {
        self.zip(CompressionMethod::Stored, false)
    }
}

fn position(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|part| part == needle)
        .unwrap()
}

fn rename_entries(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let positions: Vec<_> = bytes
        .windows(from.len())
        .enumerate()
        .filter(|(_, part)| *part == from)
        .map(|(index, _)| index)
        .collect();
    assert!(!positions.is_empty());
    for index in positions {
        bytes[index..index + to.len()].copy_from_slice(to);
    }
}

fn extension_bundle(namespace: &str, version: &str) -> Files {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("extensions")
        .join(namespace)
        .join(version);
    let mut files = Files::new();
    collect(&base, &base, &mut files);
    files
}

/// One case: identifier, expected outcome, specification section, description,
/// inputs (null when the case needs none) and archive bytes.
type Case = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Value,
    Vec<u8>,
);

// Fixed public test material. These keys protect nothing.
const PACKAGE: &str = "00112233445566778899aabbccddeeff";
const SIGNER: &str = "corpus-signer";
const SIGNER_SEED: [u8; 32] = [7; 32];
const KEY_ID: &str = "corpus-key";
const KEY: [u8; 32] = [42; 32];
const SIGNATURE: &str = "extensions/studio.illegal.darkbox.protection/manifest.ed25519";

const PROTECTED_PROFILE: &str = "# org.example.conformance, format 1\n\nProfile identifier: org.example.conformance. Data-format version: 1.\n\nThe database data/project.sqlite has SQLite user_version 1 and one table.\n\n- notes.id: stable unique TEXT identifier, never changed after creation.\n- notes.title: public UTF-8 title, never NULL.\n- notes.secret: NULL, or a protected BLOB whose plaintext is UTF-8 text.\n\nassets/public.txt is public UTF-8 text. assets/private.bin is a protected file whose plaintext is UTF-8 text.\n";

struct Counter(u32);
impl NonceSequence for Counter {
    fn next_nonce(&mut self, _: &str) -> Result<[u8; 12], darkbox::Error> {
        self.0 += 1;
        let mut nonce = [0; 12];
        nonce[8..].copy_from_slice(&self.0.to_be_bytes());
        Ok(nonce)
    }
}

fn block(plaintext: &str, location: BlockLocation, nonces: &mut Counter) -> Vec<u8> {
    let context = BlockContext {
        package_id: PACKAGE.into(),
        key_id: KEY_ID.into(),
        location,
    };
    protection::encrypt_block(plaintext.as_bytes(), &KEY, &context, nonces).unwrap()
}

fn row(id: &str) -> BlockLocation {
    BlockLocation::Sqlite {
        database: DATABASE.into(),
        table: "notes".into(),
        column: "secret".into(),
        record_id: id.into(),
    }
}

/// Sign the exact manifest bytes and store both.
fn sign(sample: &mut Sample) {
    let mut bytes = serde_json::to_vec_pretty(&sample.manifest).unwrap();
    bytes.push(b'\n');
    let signature = SigningKey::from_bytes(&SIGNER_SEED).sign(&bytes).to_bytes();
    sample.files.insert(SIGNATURE.into(), signature.to_vec());
    sample.files.insert("manifest.json".into(), bytes);
}

/// Record the complete payload inventory, then sign.
fn seal(sample: &mut Sample) {
    let inventory: Vec<Value> = sample
        .files
        .iter()
        .filter(|(path, _)| path.as_str() != "manifest.json" && path.as_str() != SIGNATURE)
        .map(|(path, bytes)| json!({"path": path, "size": bytes.len(), "sha256": hex(Sha256::digest(bytes))}))
        .collect();
    sample.manifest["extensions"][PROTECTION]["data"]["inventory"] = json!(inventory);
    sign(sample);
}

/// A sealed protected package. `second` is the record whose context encrypts the
/// block stored in record n2; anything other than "n2" relocates a block.
fn protected(second: &str) -> Sample {
    let mut sample = Sample::new();
    sample.files.extend(extension_bundle(PROTECTION, "1.0.0"));
    for path in [
        "docs/darkbox/protection",
        "assets",
        "extensions",
        "extensions/studio.illegal.darkbox.protection",
    ] {
        sample.folder(path);
    }
    let mut nonces = Counter(0);
    sample.files.insert(
        "docs/profile.md".into(),
        PROTECTED_PROFILE.as_bytes().to_vec(),
    );
    sample
        .files
        .insert("assets/public.txt".into(), b"Public attachment\n".to_vec());
    sample.files.insert(
        "assets/private.bin".into(),
        block(
            "Private attachment",
            BlockLocation::File {
                path: "assets/private.bin".into(),
            },
            &mut nonces,
        ),
    );
    let first = block("Secret of n1", row("n1"), &mut nonces);
    let other = block("Secret of n2", row(second), &mut nonces);
    sample.files.insert(
        DATABASE.into(),
        database(&format!(
            "PRAGMA journal_mode=DELETE; PRAGMA user_version=1; CREATE TABLE notes(id TEXT PRIMARY KEY, title TEXT NOT NULL, secret BLOB); INSERT INTO notes VALUES('n1','First note',X'{}'); INSERT INTO notes VALUES('n2','Second note',X'{}'); INSERT INTO notes VALUES('n3','Public note',NULL);",
            hex(&first),
            hex(&other)
        )),
    );
    sample.manifest["packageId"] = json!(PACKAGE);
    sample.manifest["extensions"] = json!({PROTECTION: {"version": "1.0.0", "required": true, "data": {
        "packageId": PACKAGE,
        "signature": {"algorithm": "Ed25519", "signerId": SIGNER, "path": SIGNATURE},
        "inventory": [],
        "files": [{"path": "assets/private.bin", "keyId": KEY_ID}],
        "sqlite": [{"database": DATABASE, "table": "notes", "column": "secret", "recordIdColumn": "id", "keyId": KEY_ID}],
    }}});
    seal(&mut sample);
    sample
}

fn signer_input() -> Value {
    json!({SIGNER: hex(SigningKey::from_bytes(&SIGNER_SEED).verifying_key().to_bytes())})
}

/// A package that declares the library identity a delta needs.
fn identified(edit: impl FnOnce(&mut Sample)) -> Vec<u8> {
    edited(|sample| {
        sample.manifest["packageId"] = json!(PACKAGE);
        sample.folder("media");
        edit(sample);
    })
}

/// The delta that turns one complete edition into another.
fn delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);
    fs::write(path("base.zip"), base).unwrap();
    fs::write(path("target.zip"), target).unwrap();
    darkbox::create_delta(
        path("base.zip"),
        path("target.zip"),
        path("delta.zip"),
        Limits::default(),
        &VerificationOptions::default(),
    )
    .unwrap();
    fs::read(path("delta.zip")).unwrap()
}

/// Rewrite a ZIP with edited entries, keeping every checksum valid.
fn rewritten(bytes: &[u8], edit: impl FnOnce(&mut Files)) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut files = Files::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        let name = entry.name().unwrap().to_string();
        if entry.is_file() {
            let mut content = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut content).unwrap();
            files.insert(name, content);
        }
    }
    edit(&mut files);
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .unix_permissions(0o644);
    for (name, content) in &files {
        zip.start_file(name.as_str(), options).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn edited(edit: impl FnOnce(&mut Sample)) -> Vec<u8> {
    let mut sample = Sample::new();
    edit(&mut sample);
    sample.deflated()
}

fn cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut add = |id, expected, section, description, bytes| {
        cases.push((id, expected, section, description, Value::Null, bytes));
    };

    // Conforming packages.
    add(
        "valid-minimal",
        "valid",
        "2",
        "The smallest conforming package: manifest, canonical bundle, profile document and one database, using DEFLATE.",
        Sample::new().deflated(),
    );
    add(
        "valid-stored",
        "valid",
        "2",
        "The same package with every entry using STORE.",
        Sample::new().stored(),
    );
    add(
        "valid-zip64",
        "valid",
        "2",
        "Entries written with ZIP64 extended information.",
        Sample::new().zip(CompressionMethod::Deflated, true),
    );
    add(
        "valid-empty-folder",
        "valid",
        "2",
        "A declared empty folder represented by an explicit directory entry.",
        edited(|sample| sample.folder("media")),
    );
    add(
        "valid-root-database",
        "valid",
        "2",
        "A declared database at the package root.",
        edited(|sample| {
            let bytes = sample.files.remove(DATABASE).unwrap();
            sample.files.insert("project.sqlite".into(), bytes);
            sample.manifest["databases"][0]["path"] = json!("project.sqlite");
            sample.manifest["folders"]
                .as_array_mut()
                .unwrap()
                .retain(|folder| folder["path"] != "data");
        }),
    );
    add(
        "valid-optional-extension",
        "valid",
        "8",
        "An unknown optional third-party extension with its own resource: skipped, not an error.",
        edited(|sample| {
            sample.folder("extensions");
            sample.folder("extensions/org.example.analysis");
            sample.files.insert(
                "extensions/org.example.analysis/summary.json".into(),
                b"{\"notes\":1}\n".to_vec(),
            );
            sample.manifest["extensions"] = json!({"org.example.analysis": {"version": "1", "required": false, "data": {"summaryPath": "extensions/org.example.analysis/summary.json"}}});
        }),
    );
    add(
        "valid-crlf-manifest",
        "valid",
        "4",
        "A manifest with CRLF line endings, which readers accept.",
        edited(|sample| {
            let text = serde_json::to_string_pretty(&sample.manifest)
                .unwrap()
                .replace('\n', "\r\n");
            sample
                .files
                .insert("manifest.json".into(), text.into_bytes());
        }),
    );

    // Manifest.
    add(
        "invalid-missing-manifest",
        "invalid",
        "2",
        "No root manifest.json.",
        edited(|sample| sample.manifest = Value::Null),
    );
    add(
        "invalid-manifest-duplicate-key",
        "invalid",
        "3",
        "The manifest repeats an object key.",
        edited(|sample| {
            let text = serde_json::to_string_pretty(&sample.manifest).unwrap();
            let text = text.replacen(
                "\"application\"",
                "\"darkbox\": {\"id\": \"darkbox\", \"version\": \"1.6.0\"},\n  \"application\"",
                1,
            );
            sample
                .files
                .insert("manifest.json".into(), text.into_bytes());
        }),
    );
    add(
        "invalid-manifest-bom",
        "invalid",
        "3",
        "The manifest starts with a UTF-8 byte order mark.",
        edited(|sample| {
            let mut bytes = vec![0xef, 0xbb, 0xbf];
            bytes.extend(serde_json::to_vec_pretty(&sample.manifest).unwrap());
            sample.files.insert("manifest.json".into(), bytes);
        }),
    );
    add(
        "invalid-manifest-unknown-field",
        "invalid",
        "3",
        "An unknown property in a common manifest object.",
        edited(|sample| sample.manifest["darkbox"]["flavor"] = json!("custom")),
    );

    // Canonical documentation.
    add(
        "invalid-missing-readme",
        "invalid",
        "5",
        "The canonical root README.md is absent.",
        edited(|sample| {
            sample.files.remove("README.md");
        }),
    );
    add(
        "invalid-modified-readme",
        "invalid",
        "5",
        "The canonical README.md has one appended line.",
        edited(|sample| {
            sample
                .files
                .get_mut("README.md")
                .unwrap()
                .extend_from_slice(b"Producer note.\n")
        }),
    );
    add(
        "invalid-modified-catalog",
        "invalid",
        "5",
        "The bundle catalog has the same content with different whitespace: it must equal the trusted reference byte for byte.",
        edited(|sample| {
            let catalog: Value =
                serde_json::from_slice(&sample.files["docs/darkbox/bundle.json"]).unwrap();
            sample.files.insert(
                "docs/darkbox/bundle.json".into(),
                serde_json::to_vec(&catalog).unwrap(),
            );
        }),
    );
    add(
        "invalid-reserved-extra-file",
        "invalid",
        "4",
        "An application file inside the reserved docs/darkbox/ subtree.",
        edited(|sample| {
            sample
                .files
                .insert("docs/darkbox/notes.md".into(), b"# Notes\n".to_vec());
        }),
    );
    add(
        "invalid-undeclared-extension-bundle",
        "invalid",
        "9",
        "The protection extension bundle is present although the manifest does not declare protection.",
        edited(|sample| {
            sample.files.extend(extension_bundle(PROTECTION, "1.0.0"));
            sample.folder("docs/darkbox/protection");
        }),
    );
    add(
        "invalid-extension-without-bundle",
        "invalid",
        "9",
        "The manifest declares the protection extension but its canonical bundle is absent.",
        edited(|sample| {
            sample.manifest["extensions"] =
                json!({PROTECTION: {"version": "1.0.0", "required": true, "data": {}}});
        }),
    );
    add(
        "invalid-missing-profile",
        "invalid",
        "5",
        "The profile document named by application.profilePath is absent.",
        edited(|sample| {
            sample.files.remove("docs/profile.md");
        }),
    );
    add(
        "invalid-profile-bom",
        "invalid",
        "5",
        "The profile document starts with a UTF-8 byte order mark.",
        edited(|sample| {
            let mut bytes = vec![0xef, 0xbb, 0xbf];
            bytes.extend_from_slice(PROFILE.as_bytes());
            sample.files.insert("docs/profile.md".into(), bytes);
        }),
    );

    // Inventory and paths.
    add(
        "invalid-undeclared-folder",
        "invalid",
        "2",
        "A directory that the manifest does not declare.",
        edited(|sample| {
            sample
                .files
                .insert("media/image.bin".into(), b"image".to_vec());
        }),
    );
    add(
        "invalid-missing-folder",
        "invalid",
        "2",
        "A declared empty folder without its explicit directory entry.",
        edited(|sample| {
            sample.folder("media");
            sample.absent_folders.push("media");
        }),
    );
    add(
        "invalid-folder-is-file",
        "invalid",
        "2",
        "A declared folder that is a regular file in the package.",
        edited(|sample| {
            sample.folder("media");
            sample
                .files
                .insert("media".into(), b"not a directory".to_vec());
        }),
    );
    add(
        "invalid-unexpected-root-file",
        "invalid",
        "2",
        "A regular file at the root that is neither metadata nor a declared database.",
        edited(|sample| {
            sample.files.insert("notes.txt".into(), b"stray".to_vec());
        }),
    );
    add(
        "invalid-path-traversal",
        "invalid",
        "4",
        "An entry name containing a parent-directory component.",
        edited(|sample| {
            sample
                .files
                .insert("data/../escape.txt".into(), b"escape".to_vec());
        }),
    );
    add(
        "invalid-backslash-path",
        "invalid",
        "4",
        "An entry name containing a backslash.",
        edited(|sample| {
            sample
                .files
                .insert("data\\file.txt".into(), b"backslash".to_vec());
        }),
    );
    add(
        "invalid-device-name",
        "invalid",
        "4",
        "An entry named after a Windows device.",
        edited(|sample| {
            sample
                .files
                .insert("data/CON.txt".into(), b"device".to_vec());
        }),
    );
    add(
        "invalid-case-collision",
        "invalid",
        "4",
        "Two paths that differ only by ASCII case.",
        edited(|sample| {
            sample
                .files
                .insert("data/Note.txt".into(), b"upper".to_vec());
            sample
                .files
                .insert("data/note.txt".into(), b"lower".to_vec());
        }),
    );
    add(
        "invalid-file-directory-collision",
        "invalid",
        "4",
        "A path that is both a regular file and a parent directory.",
        edited(|sample| {
            sample
                .files
                .insert(format!("{DATABASE}/child"), b"child".to_vec());
        }),
    );
    add(
        "invalid-duplicate-entry",
        "invalid",
        "4",
        "Two ZIP entries with the same name.",
        {
            let mut sample = Sample::new();
            sample.files.insert("data/aa".into(), b"first".to_vec());
            sample.files.insert("data/bb".into(), b"second".to_vec());
            let mut bytes = sample.stored();
            rename_entries(&mut bytes, b"data/bb", b"data/aa");
            bytes
        },
    );

    // ZIP container.
    let marker = b"CRC-DAMAGE-MARKER";
    let with_marker = || {
        let mut sample = Sample::new();
        sample
            .files
            .insert("data/marker.txt".into(), marker.to_vec());
        sample.stored()
    };
    add(
        "invalid-crc",
        "invalid",
        "2",
        "One stored data byte differs from the recorded CRC.",
        {
            let mut bytes = with_marker();
            let index = position(&bytes, marker);
            bytes[index] ^= 1;
            bytes
        },
    );
    add(
        "invalid-truncated",
        "invalid",
        "2",
        "The archive is cut short inside its end record.",
        {
            let bytes = Sample::new().stored();
            bytes[..bytes.len() - 12].to_vec()
        },
    );
    add(
        "invalid-encrypted-entry",
        "invalid",
        "2",
        "An entry flagged as encrypted.",
        {
            let mut bytes = Sample::new().stored();
            let central = position(&bytes, b"PK\x01\x02");
            bytes[central + 8] |= 1;
            bytes
        },
    );
    add(
        "invalid-split-volume",
        "invalid",
        "2",
        "The end record names another disk.",
        {
            let mut bytes = Sample::new().stored();
            let end = bytes.len() - 22;
            bytes[end + 4] = 1;
            bytes
        },
    );
    add(
        "invalid-symlink-entry",
        "invalid",
        "4",
        "An entry whose Unix mode is a symbolic link.",
        {
            let mut bytes = Sample::new().stored();
            let central = position(&bytes, b"PK\x01\x02");
            bytes[central + 5] = 3;
            bytes[central + 38..central + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
            bytes
        },
    );
    add(
        "invalid-self-extracting-wrapper",
        "invalid",
        "2",
        "Bytes prepended to the archive, as in a self-extracting wrapper.",
        {
            let mut bytes = b"MZ wrapper".to_vec();
            bytes.extend(Sample::new().stored());
            bytes
        },
    );

    // SQLite snapshots.
    add(
        "invalid-undeclared-database",
        "invalid",
        "2",
        "A second SQLite database that the manifest does not inventory.",
        edited(|sample| {
            let bytes = sample.files[DATABASE].clone();
            sample.files.insert("data/unlisted.bin".into(), bytes);
        }),
    );
    add(
        "invalid-missing-database",
        "invalid",
        "7",
        "A declared database that is absent.",
        edited(|sample| {
            sample.files.remove(DATABASE);
        }),
    );
    add(
        "invalid-sqlite-sidecar",
        "invalid",
        "6",
        "A write-ahead log beside a declared database.",
        edited(|sample| {
            sample
                .files
                .insert(format!("{DATABASE}-wal"), b"sidecar".to_vec());
        }),
    );
    add(
        "invalid-wal-journal-mode",
        "invalid",
        "6",
        "A database whose header still selects WAL mode.",
        edited(|sample| sample.files.get_mut(DATABASE).unwrap()[18..20].copy_from_slice(&[2, 2])),
    );
    add(
        "invalid-table-inventory",
        "invalid",
        "3",
        "The manifest lists a table that the database does not contain.",
        edited(|sample| {
            sample.manifest["databases"][0]["tables"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name": "missing", "description": "Not in the database"}));
        }),
    );
    add(
        "invalid-unlisted-table",
        "invalid",
        "3",
        "The database contains an application table that the manifest does not list.",
        edited(|sample| {
            sample.files.insert(
                DATABASE.into(),
                database(&format!(
                    "{SCHEMA} CREATE TABLE extra(id INTEGER PRIMARY KEY);"
                )),
            );
        }),
    );
    add(
        "invalid-user-version",
        "invalid",
        "3",
        "The declared userVersion differs from the database.",
        edited(|sample| sample.manifest["databases"][0]["userVersion"] = json!(2)),
    );
    add(
        "invalid-foreign-keys",
        "invalid",
        "6",
        "The database fails PRAGMA foreign_key_check.",
        edited(|sample| {
            sample.files.insert(DATABASE.into(), database(&format!("{SCHEMA} PRAGMA foreign_keys=OFF; CREATE TABLE parents(id INTEGER PRIMARY KEY); CREATE TABLE children(parent_id INTEGER REFERENCES parents(id)); INSERT INTO children VALUES(99);")));
            let tables = sample.manifest["databases"][0]["tables"]
                .as_array_mut()
                .unwrap();
            tables.push(json!({"name": "parents", "description": "Parent keys"}));
            tables.push(json!({"name": "children", "description": "References"}));
        }),
    );
    add(
        "invalid-corrupt-database",
        "invalid",
        "6",
        "The database fails PRAGMA integrity_check.",
        edited(|sample| {
            let bytes = sample.files.get_mut(DATABASE).unwrap();
            // Damage the b-tree page type of the first page after the header.
            bytes[100] = 0xff;
        }),
    );

    // Versions and extensions.
    add(
        "invalid-sync-1.0.0",
        "invalid",
        "9",
        "Sync extension 1.0.0, which is bound to common version 1.5.0, declared under 1.6.0.",
        edited(|sample| {
            sample.manifest["packageId"] = json!("00112233445566778899aabbccddeeff");
            sample.manifest["extensions"] = json!({"studio.illegal.darkbox.sync": {"version": "1.0.0", "required": true, "data": {}}});
        }),
    );
    add(
        "unsupported-common-version",
        "unsupported",
        "8",
        "A common specification version that no reader implements.",
        edited(|sample| sample.manifest["darkbox"]["version"] = json!("9.0.0")),
    );
    add(
        "unsupported-required-extension",
        "unsupported",
        "8",
        "An unknown required third-party extension.",
        edited(|sample| {
            sample.manifest["extensions"] =
                json!({"org.example.required": {"version": "1", "required": true, "data": {}}});
        }),
    );
    add(
        "unsupported-official-extension-version",
        "unsupported",
        "9",
        "A required official extension version without a trusted reference bundle: unsupported, never corrupt.",
        edited(|sample| {
            sample.folder("docs/darkbox/future");
            sample.files.insert(
                "docs/darkbox/future/9.0.0.md".into(),
                b"# Future extension 9.0.0\n".to_vec(),
            );
            sample.manifest["extensions"] = json!({"studio.illegal.darkbox.future": {"version": "9.0.0", "required": true, "data": {}}});
        }),
    );

    // Protected packages (official protection extension 1.0.0).
    let trusted = || json!({"trustedSigners": signer_input()});
    let unlocked = |key: [u8; 32]| json!({"trustedSigners": signer_input(), "decryptionKeys": {KEY_ID: hex(key)}});
    let sealed = protected("n2").deflated();
    let mut add = |id, expected, description, inputs, bytes| {
        cases.push((id, expected, "9", description, inputs, bytes));
    };
    add(
        "valid-protected",
        "valid",
        "A sealed protected package verified with its trusted signer key and its decryption key: signature, inventory and every encrypted block pass.",
        unlocked(KEY),
        sealed.clone(),
    );
    add(
        "valid-protected-without-decryption-key",
        "valid",
        "The same package verified with the trusted signer key only: signature and inventory pass, and encrypted blocks stay unauthenticated without making the package invalid.",
        trusted(),
        sealed.clone(),
    );
    add(
        "unsupported-protected-unknown-signer",
        "unsupported",
        "The same package verified without any trusted signer key: its signature cannot be evaluated, which is not corruption.",
        Value::Null,
        sealed.clone(),
    );
    add(
        "invalid-protected-wrong-decryption-key",
        "invalid",
        "The same package verified with a decryption key that is not the one used to encrypt it.",
        unlocked([9; 32]),
        sealed,
    );
    add(
        "invalid-protected-manifest-changed",
        "invalid",
        "One space is appended to manifest.json after signing.",
        trusted(),
        {
            let mut sample = protected("n2");
            sample.files.get_mut("manifest.json").unwrap().push(b' ');
            sample.deflated()
        },
    );
    add(
        "invalid-protected-signature-missing",
        "invalid",
        "The detached signature named by the manifest is absent.",
        trusted(),
        {
            let mut sample = protected("n2");
            sample.files.remove(SIGNATURE);
            sample.deflated()
        },
    );
    add(
        "invalid-protected-resource-changed",
        "invalid",
        "A public attachment is modified after sealing: the signature still verifies, the signed inventory does not.",
        trusted(),
        {
            let mut sample = protected("n2");
            sample
                .files
                .get_mut("assets/public.txt")
                .unwrap()
                .push(b'x');
            sample.deflated()
        },
    );
    add(
        "invalid-protected-resource-added",
        "invalid",
        "A file absent from the signed inventory is added after sealing.",
        trusted(),
        {
            let mut sample = protected("n2");
            sample
                .files
                .insert("assets/added.txt".into(), b"Added\n".to_vec());
            sample.deflated()
        },
    );
    add(
        "invalid-protected-relocated-block",
        "invalid",
        "Record n2 stores a block encrypted for record n1. The package is sealed and signed consistently, so only block authentication against its context detects the relocation.",
        unlocked(KEY),
        protected("n1").deflated(),
    );

    // Delta transfers (envelope 1.0.0).
    let base = identified(|sample| {
        sample
            .files
            .insert("media/first.txt".into(), b"First edition\n".to_vec());
    });
    let target = identified(|sample| {
        sample.files.insert(
            DATABASE.into(),
            database(&format!(
                "{SCHEMA} INSERT INTO notes VALUES('n2','Second note');"
            )),
        );
        sample
            .files
            .insert("media/second.txt".into(), b"Second edition\n".to_vec());
    });
    let transfer = delta(&base, &target);
    let against = |file: &str| json!({"base": file});
    let mut add = |id, expected, section, description, inputs, bytes| {
        cases.push((id, expected, section, description, inputs, bytes));
    };
    add(
        "valid-package-identity",
        "valid",
        "11",
        "A package that declares the optional library identity packageId. It is the base edition of the delta cases.",
        Value::Null,
        base,
    );
    add(
        "valid-delta",
        "valid",
        "12",
        "A delta that replaces the database, adds one file and removes another. Applied to its base it reconstructs a conforming target edition.",
        against("valid-package-identity.zip"),
        transfer.clone(),
    );
    add(
        "invalid-delta-without-base",
        "invalid",
        "12",
        "The same delta verified as if it were a complete package: a delta is a transfer envelope, not a standalone project.",
        Value::Null,
        transfer.clone(),
    );
    add(
        "invalid-delta-other-base",
        "invalid",
        "12",
        "The same delta applied to a conforming package that is not its base edition.",
        against("valid-minimal.zip"),
        transfer.clone(),
    );
    add(
        "invalid-delta-changed-payload",
        "invalid",
        "12",
        "One changed-file payload has an extra byte, with a correct ZIP checksum: the reconstructed file no longer matches targetFiles.",
        against("valid-package-identity.zip"),
        rewritten(&transfer, |files| {
            files.get_mut("files/0").unwrap().push(b'x')
        }),
    );
    add(
        "invalid-delta-extra-entry",
        "invalid",
        "12",
        "The envelope contains a regular file that is neither delta.json nor an indexed payload.",
        against("valid-package-identity.zip"),
        rewritten(&transfer, |files| {
            files.insert("notes.txt".into(), b"Not part of the envelope\n".to_vec());
        }),
    );
    add(
        "invalid-delta-unknown-member",
        "invalid",
        "12",
        "delta.json has a member the envelope version does not define.",
        against("valid-package-identity.zip"),
        rewritten(&transfer, |files| {
            let mut document: Value = serde_json::from_slice(&files["delta.json"]).unwrap();
            document["comment"] = json!("unrecognized");
            files.insert("delta.json".into(), serde_json::to_vec(&document).unwrap());
        }),
    );
    cases
}

#[test]
#[ignore = "updates conformance/1.6.0; run explicitly after changing the cases"]
fn regenerate_corpus() {
    let directory = root().join(VERSION);
    fs::create_dir_all(&directory).unwrap();
    let mut index = Vec::new();
    let mut cases = cases();
    // Committed archives are the test vectors: keep their bytes and write only
    // the cases that have no file yet. Every file is in place before any case is
    // verified, because a delta case needs its base edition on disk.
    for (id, .., bytes) in &mut cases {
        let path = directory.join(format!("{id}.zip"));
        match fs::read(&path) {
            Ok(committed) => *bytes = committed,
            Err(_) => fs::write(&path, &*bytes).unwrap(),
        }
    }
    // Drop the archives of cases that no longer exist.
    for entry in fs::read_dir(&directory).unwrap() {
        let path = entry.unwrap().path();
        let stem = path.file_stem().unwrap().to_str().unwrap().to_owned();
        if path.extension().is_some_and(|extension| extension == "zip")
            && !cases.iter().any(|case| case.0 == stem)
        {
            fs::remove_file(path).unwrap();
        }
    }
    for (id, expected, section, description, inputs, bytes) in cases {
        let file = format!("{id}.zip");
        let mut case = json!({"file": file});
        if !inputs.is_null() {
            case["inputs"] = inputs;
        }
        let report = run(&directory, &case);
        assert_eq!(
            outcome(report.status),
            expected,
            "{id}: {}",
            serde_json::to_string_pretty(&report.diagnostics).unwrap()
        );
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == "error")
            .map(|diagnostic| diagnostic.code.clone());
        assert_eq!(
            diagnostic.is_some(),
            expected != "valid",
            "{id}: a failing case needs an error diagnostic"
        );
        let entry = case.as_object_mut().unwrap();
        entry.insert("id".into(), json!(id));
        entry.insert("expected".into(), json!(expected));
        entry.insert("section".into(), json!(section));
        entry.insert("description".into(), json!(description));
        entry.insert("referenceDiagnostic".into(), json!(diagnostic));
        entry.insert("sha256".into(), json!(hex(Sha256::digest(&bytes))));
        index.push(case);
    }
    let document = json!({
        "darkbox": VERSION,
        "outcomes": {
            "valid": "Every common machine-checkable rule passes, with the rules of declared official extensions that the given inputs allow to check.",
            "invalid": "A rule of the declared common version is violated or data is damaged.",
            "unsupported": "The package needs a version or extension the reader does not implement, or names a signer for which the case supplies no trusted key. This is not corruption.",
        },
        "cases": index,
    });
    fs::write(
        directory.join("cases.json"),
        serde_json::to_string_pretty(&document).unwrap() + "\n",
    )
    .unwrap();
}
