//! The language-neutral conformance corpus in `conformance/`. Every committed
//! case must produce its documented outcome with this reference implementation.
//! `regenerate_corpus` rebuilds the cases; it is ignored by default because the
//! committed archives are the test vectors, not a build product.
use darkbox::Status;
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
fn outcome(status: Status) -> &'static str {
    match status {
        Status::Passed => "valid",
        Status::Invalid => "invalid",
        Status::Unsupported => "unsupported",
        other => panic!("The corpus has no case for {other}"),
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
            let report = darkbox::verify(&path);
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

/// One case: identifier, expected outcome, specification section, description, archive bytes.
type Case = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Vec<u8>,
);

fn edited(edit: impl FnOnce(&mut Sample)) -> Vec<u8> {
    let mut sample = Sample::new();
    edit(&mut sample);
    sample.deflated()
}

fn cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut add = |id, expected, section, description, bytes| {
        cases.push((id, expected, section, description, bytes));
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
    cases
}

#[test]
#[ignore = "rewrites conformance/1.6.0; run explicitly after changing the cases"]
fn regenerate_corpus() {
    let directory = root().join(VERSION);
    if directory.exists() {
        fs::remove_dir_all(&directory).unwrap();
    }
    fs::create_dir_all(&directory).unwrap();
    let mut index = Vec::new();
    for (id, expected, section, description, bytes) in cases() {
        let file = format!("{id}.zip");
        let path = directory.join(&file);
        fs::write(&path, &bytes).unwrap();
        let report = darkbox::verify(&path);
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
        index.push(json!({
            "id": id,
            "file": file,
            "expected": expected,
            "section": section,
            "description": description,
            "referenceDiagnostic": diagnostic,
            "sha256": hex(Sha256::digest(&bytes)),
        }));
    }
    let document = json!({
        "darkbox": VERSION,
        "outcomes": {
            "valid": "Every common machine-checkable rule passes.",
            "invalid": "A rule of the declared common version is violated or data is damaged.",
            "unsupported": "The package needs a version or extension the reader does not implement. This is not corruption.",
        },
        "cases": index,
    });
    fs::write(
        directory.join("cases.json"),
        serde_json::to_string_pretty(&document).unwrap() + "\n",
    )
    .unwrap();
}
