use darkbox::Status;
#[cfg(feature = "cli")]
use darkbox::{Limits, Mode};
use rusqlite::Connection;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
#[cfg(feature = "cli")]
use std::process::Command;
use tempfile::TempDir;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

struct Fixture {
    dir: TempDir,
    files: BTreeMap<String, Vec<u8>>,
}

fn collect(base: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(dir).unwrap() {
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

impl Fixture {
    fn new(name: &str) -> Self {
        Self::for_version("1.0.0", name)
    }
    fn for_version(version: &str, name: &str) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let dir = tempfile::Builder::new()
            .prefix("darkbox-tests-")
            .tempdir()
            .unwrap();
        let mut files = BTreeMap::new();
        let base = root.join("archive").join(version);
        collect(&base, &base, &mut files);
        let manifest: Value = serde_json::from_slice(
            &fs::read(root.join(format!("tests/fixtures/{version}/{name}.manifest.json"))).unwrap(),
        )
        .unwrap();
        let profile =
            fs::read_to_string(root.join(format!("tests/fixtures/{version}/{name}.md"))).unwrap();
        let sql: Vec<_> = profile
            .split("```sql\n")
            .skip(1)
            .map(|block| block.split("```").next().unwrap())
            .collect();
        for (index, declaration) in manifest["databases"].as_array().unwrap().iter().enumerate() {
            let path = dir.path().join(format!("source-{index}.sqlite"));
            let db = Connection::open(&path).unwrap();
            db.execute_batch(sql[index]).unwrap();
            if name == "notebook" {
                db.execute(
                    "INSERT INTO project VALUES (?1,?2)",
                    ["f236e209-2cbb-46a0-88d9-6187c5ee573e", "Example notebook"],
                )
                .unwrap();
            } else if index == 0 {
                let document = json!({"version":7,"id":"f236e209-2cbb-46a0-88d9-6187c5ee573e","name":"Example canvas","viewport":{"x":0,"y":0,"scale":1},"items":[]});
                db.execute("INSERT INTO project VALUES (1,?1)", [document.to_string()])
                    .unwrap();
            }
            drop(db);
            files.insert(
                declaration["path"].as_str().unwrap().into(),
                fs::read(path).unwrap(),
            );
        }
        files.insert("docs/profile.md".into(), profile.into_bytes());
        files.insert(
            "manifest.json".into(),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        );
        for folder in manifest["folders"].as_array().unwrap() {
            let path = folder["path"].as_str().unwrap();
            if !files
                .keys()
                .any(|name| name.starts_with(&format!("{path}/")))
            {
                files.insert(format!("{path}/"), Vec::new());
            }
        }
        Self { dir, files }
    }
    fn manifest(&mut self, edit: impl FnOnce(&mut Value)) {
        let mut manifest: Value = serde_json::from_slice(&self.files["manifest.json"]).unwrap();
        edit(&mut manifest);
        self.files.insert(
            "manifest.json".into(),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        );
    }
    fn archive(&self, method: CompressionMethod, zip64_entries: bool) -> PathBuf {
        let bytes = self.zip_bytes(method, zip64_entries);
        let path = self.dir.path().join("example.project");
        fs::write(&path, bytes).unwrap();
        path
    }
    fn zip_bytes(&self, method: CompressionMethod, zip64_entries: bool) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .compression_method(method)
            .large_file(zip64_entries);
        for (name, bytes) in &self.files {
            if name.ends_with('/') {
                zip.add_directory(name, options).unwrap();
            } else {
                zip.start_file(name, options).unwrap();
                zip.write_all(bytes).unwrap();
            }
        }
        zip.finish().unwrap().into_inner()
    }
    fn streaming_zip(&self, signature: bool, zip64: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut central = Vec::new();
        for (name, data) in &self.files {
            let offset = bytes.len() as u32;
            let crc = crc32fast::hash(data);
            let size = data.len() as u32;
            let mut header = [0u8; 30];
            header[..4].copy_from_slice(b"PK\x03\x04");
            header[4..6].copy_from_slice(&(if zip64 { 45u16 } else { 20 }).to_le_bytes());
            header[6..8].copy_from_slice(&8u16.to_le_bytes());
            header[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
            if zip64 {
                header[18..26].fill(0xff);
                header[28..30].copy_from_slice(&20u16.to_le_bytes());
            }
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(name.as_bytes());
            if zip64 {
                bytes.extend_from_slice(&[1, 0, 16, 0]);
                bytes.extend_from_slice(&[0; 16]);
            }
            bytes.extend_from_slice(data);
            if signature {
                bytes.extend_from_slice(b"PK\x07\x08");
            }
            bytes.extend_from_slice(&crc.to_le_bytes());
            if zip64 {
                bytes.extend_from_slice(&(size as u64).to_le_bytes());
                bytes.extend_from_slice(&(size as u64).to_le_bytes());
            } else {
                bytes.extend_from_slice(&size.to_le_bytes());
                bytes.extend_from_slice(&size.to_le_bytes());
            }
            let mut entry = [0u8; 46];
            entry[..4].copy_from_slice(b"PK\x01\x02");
            entry[4..6].copy_from_slice(&20u16.to_le_bytes());
            entry[6..8].copy_from_slice(&header[4..6]);
            entry[8..10].copy_from_slice(&8u16.to_le_bytes());
            entry[16..20].copy_from_slice(&crc.to_le_bytes());
            entry[20..24].copy_from_slice(&size.to_le_bytes());
            entry[24..28].copy_from_slice(&size.to_le_bytes());
            entry[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
            entry[42..46].copy_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(&entry);
            central.extend_from_slice(name.as_bytes());
        }
        let offset = bytes.len() as u32;
        let mut end = [0u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&(self.files.len() as u16).to_le_bytes());
        end[10..12].copy_from_slice(&(self.files.len() as u16).to_le_bytes());
        end[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
        end[16..20].copy_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(&central);
        bytes.extend_from_slice(&end);
        bytes
    }
    fn verify(&self) -> darkbox::Report {
        darkbox::verify(self.archive(CompressionMethod::Deflated, false))
    }
}

fn assert_status(report: &darkbox::Report, expected: Status) {
    assert_eq!(
        report.status,
        expected,
        "{}",
        serde_json::to_string_pretty(report).unwrap()
    );
}

fn assert_code(report: &darkbox::Report, expected: &str) {
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == expected),
        "Expected {expected}: {}",
        serde_json::to_string_pretty(report).unwrap()
    );
}

fn replace_name(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let positions: Vec<_> = bytes
        .windows(from.len())
        .enumerate()
        .filter(|(_, part)| *part == from)
        .map(|(index, _)| index)
        .collect();
    assert!(!positions.is_empty());
    for position in positions {
        bytes[position..position + to.len()].copy_from_slice(to);
    }
}

#[test]
fn both_profiles_pass_common_checks_without_full_profile_claims() {
    for name in ["notebook", "canvas"] {
        let fixture = Fixture::new(name);
        for (method, large) in [
            (CompressionMethod::Stored, false),
            (CompressionMethod::Deflated, true),
        ] {
            let path = fixture.archive(method, large);
            let original = fs::read(&path).unwrap();
            let report = darkbox::verify(&path);
            assert_status(&report, Status::Passed);
            assert_eq!(report.scope, "common_machine_checks");
            assert_eq!(report.application_validation, "not_performed");
            assert!(report.entries.iter().all(|entry| entry.crc_verified));
            assert!(report.checks.contains(&"bundle.canonical"));
            assert!(
                report
                    .databases
                    .iter()
                    .all(|db| db.integrity_checked && db.foreign_keys_checked)
            );
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
}

#[test]
fn every_supported_version_has_schema_valid_examples_and_catalog() {
    for (version, _) in darkbox::supported_versions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let schema: Value = serde_json::from_slice(
            &fs::read(root.join(format!("schema/{version}/manifest.schema.json"))).unwrap(),
        )
        .unwrap();
        jsonschema::meta::validate(&schema).unwrap();
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .unwrap();
        for name in ["notebook", "canvas"] {
            let manifest: Value = serde_json::from_slice(
                &fs::read(root.join(format!("tests/fixtures/{version}/{name}.manifest.json")))
                    .unwrap(),
            )
            .unwrap();
            assert!(validator.is_valid(&manifest));
            assert_status(
                &Fixture::for_version(version, name).verify(),
                Status::Passed,
            );
        }
        let catalog: Value = serde_json::from_slice(
            &fs::read(root.join(format!("archive/{version}/docs/darkbox/bundle.json"))).unwrap(),
        )
        .unwrap();
        let schema: Value = serde_json::from_slice(
            &fs::read(root.join(format!("schema/{version}/bundle.schema.json"))).unwrap(),
        )
        .unwrap();
        jsonschema::meta::validate(&schema).unwrap();
        assert!(
            jsonschema::validator_for(&schema)
                .unwrap()
                .is_valid(&catalog)
        );
        assert_eq!(catalog["darkbox"]["version"], version);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["notebook", "canvas"] {
        let manifest: Value = serde_json::from_slice(
            &fs::read(root.join(format!("examples/{name}.manifest.json"))).unwrap(),
        )
        .unwrap();
        let version = manifest["darkbox"]["version"].as_str().unwrap();
        let schema: Value = serde_json::from_slice(
            &fs::read(root.join(format!("schema/{version}/manifest.schema.json"))).unwrap(),
        )
        .unwrap();
        assert!(
            jsonschema::draft202012::options()
                .should_validate_formats(true)
                .build(&schema)
                .unwrap()
                .is_valid(&manifest)
        );
    }
}

#[test]
fn missing_and_modified_canonical_files_fail_even_with_valid_zip_crc() {
    let baseline = Fixture::new("notebook");
    let canonical: Vec<_> = baseline
        .files
        .keys()
        .filter(|name| {
            *name != "manifest.json" && *name != "docs/profile.md" && !name.starts_with("data/")
        })
        .cloned()
        .collect();
    for path in canonical {
        let mut fixture = Fixture::new("notebook");
        fixture.files.remove(&path);
        assert_status(&fixture.verify(), Status::Invalid);
        let mut fixture = Fixture::new("notebook");
        fixture
            .files
            .get_mut(&path)
            .unwrap()
            .extend_from_slice(b"changed");
        let report = fixture.verify();
        assert_status(&report, Status::Invalid);
        assert_code(
            &report,
            if path == "docs/darkbox/bundle.json" {
                "bundle.catalog"
            } else {
                "bundle.file"
            },
        );
    }
}

#[test]
fn forged_archive_catalog_cannot_authorize_modified_documentation() {
    let mut fixture = Fixture::new("notebook");
    fixture
        .files
        .get_mut("README.md")
        .unwrap()
        .extend_from_slice(b"\nChanged\n");
    let bytes = &fixture.files["README.md"];
    let mut catalog: Value =
        serde_json::from_slice(&fixture.files["docs/darkbox/bundle.json"]).unwrap();
    for entry in catalog["files"].as_array_mut().unwrap() {
        if entry["path"] == "README.md" {
            entry["size"] = json!(bytes.len());
            entry["sha256"] = json!(format!("{:x}", Sha256::digest(bytes)));
        }
    }
    fixture.files.insert(
        "docs/darkbox/bundle.json".into(),
        serde_json::to_vec(&catalog).unwrap(),
    );
    let report = fixture.verify();
    assert_status(&report, Status::Invalid);
    assert_code(&report, "bundle.catalog");
    assert_code(&report, "bundle.file");
}

#[test]
fn missing_required_folders_and_extra_reserved_resources_fail() {
    for path in ["docs", "docs/darkbox", "docs/sqlite", "docs/sqlite/images"] {
        let mut fixture = Fixture::new("notebook");
        fixture.manifest(|manifest| {
            manifest["folders"]
                .as_array_mut()
                .unwrap()
                .retain(|folder| folder["path"] != path)
        });
        assert_status(&fixture.verify(), Status::Invalid);
    }
    for path in ["docs/darkbox/extra.md", "docs/sqlite/extra.md"] {
        let mut fixture = Fixture::new("notebook");
        fixture.files.insert(path.into(), b"Extra".to_vec());
        assert_code(&fixture.verify(), "bundle.extra");
    }
}

#[test]
fn json_schema_and_profile_presence_errors_are_reported() {
    let mut fixture = Fixture::new("notebook");
    fixture.manifest(|manifest| manifest["unknown"] = json!(true));
    assert_code(&fixture.verify(), "manifest.schema");
    let mut fixture = Fixture::new("notebook");
    let text = String::from_utf8(fixture.files["manifest.json"].clone())
        .unwrap()
        .replace(
            "\"id\": \"darkbox\"",
            "\"id\": \"darkbox\", \"\\u0069d\": \"darkbox\"",
        );
    fixture
        .files
        .insert("manifest.json".into(), text.into_bytes());
    assert_code(&fixture.verify(), "manifest.json");
    let mut fixture = Fixture::new("notebook");
    fixture.files.remove("docs/profile.md");
    assert_code(&fixture.verify(), "profile.missing");
    let mut fixture = Fixture::new("notebook");
    fixture
        .files
        .insert("docs/profile.md".into(), b"\xef\xbb\xbftext".to_vec());
    assert_code(&fixture.verify(), "profile.encoding");
    let mut fixture = Fixture::new("notebook");
    fixture.manifest(|manifest| {
        manifest["creator"] =
            json!({"id":"org.example.writer","version":"1","createdAt":"2026-02-30T10:00:00Z"})
    });
    assert_code(&fixture.verify(), "manifest.schema");
}

#[test]
fn arbitrary_json_extension_numbers_and_private_named_keys_remain_data() {
    let mut fixture = Fixture::new("notebook");
    let mut text = String::from_utf8(fixture.files["manifest.json"].clone()).unwrap();
    text.pop();
    text.push_str(",\"extensions\":{\"org.example.extra\":{\"version\":\"1\",\"required\":false,\"data\":{\"number\":1e500,\"$serde_json::private::Number\":\"ordinary data\"}}}}");
    fixture
        .files
        .insert("manifest.json".into(), text.into_bytes());
    assert_status(&fixture.verify(), Status::Passed);
}

#[test]
fn unsupported_versions_and_required_extensions_are_distinct_from_corruption() {
    let mut fixture = Fixture::new("notebook");
    fixture.manifest(|manifest| manifest["darkbox"]["version"] = json!("9.0.0"));
    assert_status(&fixture.verify(), Status::Unsupported);
    let path = fixture.archive(CompressionMethod::Deflated, false);
    let report = darkbox::inspect(path);
    assert_status(&report, Status::Inspected);
    assert_eq!(
        report.manifest.as_ref().unwrap()["darkbox"]["version"],
        "9.0.0"
    );
    let mut fixture = Fixture::new("notebook");
    fixture.manifest(|manifest| {
        manifest["extensions"] =
            json!({"org.example.required":{"version":"1","required":true,"data":{}}})
    });
    assert_status(&fixture.verify(), Status::Unsupported);
    let mut fixture = Fixture::new("notebook");
    fixture.files.insert("manifest.json".into(), b"{}".to_vec());
    assert_status(&fixture.verify(), Status::Invalid);
}

#[test]
fn unsafe_paths_case_collisions_and_duplicate_entries_fail() {
    for path in [
        "../escape",
        "data/CON.txt",
        "data\\file",
        "Data/extra",
        "data/project.sqlite/child",
    ] {
        let mut fixture = Fixture::new("notebook");
        fixture.files.insert(path.into(), b"Bad path".to_vec());
        assert_status(&fixture.verify(), Status::Invalid);
    }
    let mut fixture = Fixture::new("notebook");
    fixture.files.insert("data/aa".into(), b"a".to_vec());
    fixture.files.insert("data/bb".into(), b"b".to_vec());
    let path = fixture.archive(CompressionMethod::Stored, false);
    let mut bytes = fs::read(&path).unwrap();
    replace_name(&mut bytes, b"data/bb", b"data/aa");
    fs::write(&path, bytes).unwrap();
    assert_code(&darkbox::verify(path), "path.collision");
}

#[test]
fn truncated_zip_crc_damage_and_header_disagreement_fail() {
    let mut fixture = Fixture::new("notebook");
    fixture
        .files
        .insert("data/crc.txt".into(), b"CRC-DAMAGE-MARKER".to_vec());
    let path = fixture.archive(CompressionMethod::Stored, false);
    let original = fs::read(&path).unwrap();
    fs::write(&path, &original[..original.len() - 12]).unwrap();
    assert_status(&darkbox::verify(&path), Status::Invalid);
    let mut bytes = original.clone();
    let pos = bytes
        .windows(17)
        .position(|part| part == b"CRC-DAMAGE-MARKER")
        .unwrap();
    bytes[pos] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert_status(&darkbox::verify(&path), Status::Invalid);
    let mut bytes = original;
    let name_pos = bytes
        .windows(9)
        .position(|part| part == b"README.md")
        .unwrap();
    bytes[name_pos] = b'X';
    fs::write(&path, bytes).unwrap();
    assert_code(&darkbox::verify(path), "zip.local_header");
}

#[test]
fn split_encrypted_wrapped_and_symlink_entries_fail() {
    let fixture = Fixture::new("notebook");
    let path = fixture.archive(CompressionMethod::Stored, false);
    let original = fs::read(&path).unwrap();
    let mut split = original.clone();
    let end = split.len() - 22;
    split[end + 4] = 1;
    fs::write(&path, split).unwrap();
    assert_code(&darkbox::verify(&path), "zip.split_volume");
    let mut encrypted = original.clone();
    let central = encrypted
        .windows(4)
        .position(|part| part == b"PK\x01\x02")
        .unwrap();
    encrypted[central + 8] |= 1;
    fs::write(&path, encrypted).unwrap();
    assert_code(&darkbox::verify(&path), "zip.encryption");
    let mut symlink = original.clone();
    symlink[central + 5] = 3;
    symlink[central + 38..central + 42].copy_from_slice(&(0o120777u32 << 16).to_le_bytes());
    fs::write(&path, symlink).unwrap();
    assert_code(&darkbox::verify(&path), "zip.entry_type");
    let mut wrapped = b"MZ wrapper".to_vec();
    wrapped.extend_from_slice(&original);
    fs::write(&path, wrapped).unwrap();
    assert_status(&darkbox::verify(path), Status::Invalid);
}

#[test]
fn zip64_end_records_are_supported() {
    let fixture = Fixture::new("notebook");
    let path = fixture.archive(CompressionMethod::Deflated, false);
    let mut bytes = fs::read(&path).unwrap();
    let end = bytes.len() - 22;
    let mut record = bytes.split_off(end);
    let count = u16::from_le_bytes(record[10..12].try_into().unwrap()) as u64;
    let size = u32::from_le_bytes(record[12..16].try_into().unwrap()) as u64;
    let offset = u32::from_le_bytes(record[16..20].try_into().unwrap()) as u64;
    bytes.extend_from_slice(b"PK\x06\x06");
    bytes.extend_from_slice(&44u64.to_le_bytes());
    bytes.extend_from_slice(&45u16.to_le_bytes());
    bytes.extend_from_slice(&45u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    for value in [count, count, size, offset] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(b"PK\x06\x07");
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(end as u64).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    record[8..12].fill(0xff);
    record[12..20].fill(0xff);
    bytes.extend_from_slice(&record);
    fs::write(&path, bytes).unwrap();
    assert_status(&darkbox::verify(path), Status::Passed);
}

#[test]
fn streaming_zip_descriptors_are_validated_for_both_widths() {
    let fixture = Fixture::new("notebook");
    let path = fixture.dir.path().join("streamed.project");
    for signature in [false, true] {
        for zip64 in [false, true] {
            fs::write(&path, fixture.streaming_zip(signature, zip64)).unwrap();
            assert_status(&darkbox::verify(&path), Status::Passed);
        }
    }
    let mut malformed = fixture.streaming_zip(true, true);
    let descriptor = malformed
        .windows(4)
        .position(|part| part == b"PK\x07\x08")
        .unwrap();
    malformed[descriptor + 4] ^= 1;
    fs::write(&path, malformed).unwrap();
    assert_code(&darkbox::verify(&path), "zip.descriptor");
    let mut conflicting = fixture.zip_bytes(CompressionMethod::Stored, false);
    conflicting[22] ^= 1;
    fs::write(&path, conflicting).unwrap();
    assert_code(&darkbox::verify(&path), "zip.local_header");
}

#[test]
fn database_inventory_integrity_versions_and_foreign_keys_are_checked() {
    let mut fixture = Fixture::new("notebook");
    fixture.manifest(|manifest| manifest["databases"][0]["userVersion"] = json!(13));
    assert_code(&fixture.verify(), "sqlite.user_version");
    let mut fixture = Fixture::new("notebook");
    fixture.manifest(|manifest| {
        manifest["databases"][0]["tables"]
            .as_array_mut()
            .unwrap()
            .pop()
            .map(|_| ())
            .unwrap()
    });
    assert_code(&fixture.verify(), "sqlite.tables");
    let mut fixture = Fixture::new("notebook");
    fixture.files.insert(
        "data/unlisted.bin".into(),
        fixture.files["data/project.sqlite"].clone(),
    );
    assert_code(&fixture.verify(), "sqlite.undeclared");
    let mut fixture = Fixture::new("notebook");
    fixture.files.get_mut("data/project.sqlite").unwrap()[100] = 0xff;
    assert_status(&fixture.verify(), Status::Invalid);
    let mut fixture = Fixture::new("notebook");
    let path = fixture.dir.path().join("foreign-keys.sqlite");
    fs::write(&path, &fixture.files["data/project.sqlite"]).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA foreign_keys=OFF; CREATE TABLE parents(id INTEGER PRIMARY KEY); CREATE TABLE children(parent_id INTEGER REFERENCES parents(id)); INSERT INTO children VALUES(99);").unwrap();
    drop(db);
    fixture
        .files
        .insert("data/project.sqlite".into(), fs::read(&path).unwrap());
    fixture.manifest(|manifest| {
        let tables = manifest["databases"][0]["tables"].as_array_mut().unwrap();
        tables.push(json!({"name":"parents","description":"Parent keys"}));
        tables.push(json!({"name":"children","description":"Foreign key references"}));
    });
    assert_code(&fixture.verify(), "sqlite.foreign_keys");
}

#[test]
fn wal_dependence_and_sidecars_are_rejected() {
    let mut fixture = Fixture::new("notebook");
    fixture.files.get_mut("data/project.sqlite").unwrap()[18..20].copy_from_slice(&[2, 2]);
    assert_code(&fixture.verify(), "sqlite.journal_mode");
    for suffix in ["-wal", "-shm", "-journal", "-mj123456789"] {
        let mut fixture = Fixture::new("notebook");
        fixture
            .files
            .insert(format!("data/project.sqlite{suffix}"), b"Sidecar".to_vec());
        assert_code(&fixture.verify(), "sqlite.sidecar");
    }
}

#[test]
fn missing_virtual_table_modules_are_unsupported() {
    let mut fixture = Fixture::new("notebook");
    let path = fixture.dir.path().join("module.sqlite");
    fs::write(&path, &fixture.files["data/project.sqlite"]).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'USING fts5','USING unavailable_module') WHERE name='document_search'; PRAGMA writable_schema=OFF;").unwrap();
    drop(db);
    fixture
        .files
        .insert("data/project.sqlite".into(), fs::read(&path).unwrap());
    assert_status(&fixture.verify(), Status::Unsupported);
}

#[test]
#[cfg(feature = "cli")]
fn limits_operational_failures_and_cli_exit_codes_are_distinct() {
    let fixture = Fixture::new("notebook");
    let path = fixture.archive(CompressionMethod::Deflated, false);
    for limits in [
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
        Limits {
            max_metadata_bytes: 10,
            ..Limits::default()
        },
        Limits {
            max_total_bytes: 100,
            ..Limits::default()
        },
        Limits {
            max_entry_bytes: 100,
            ..Limits::default()
        },
    ] {
        assert_status(
            &darkbox::analyze(&path, Mode::Verify, limits),
            Status::ResourceLimit,
        );
    }
    assert_status(
        &darkbox::verify(fixture.dir.path().join("missing")),
        Status::OperationalError,
    );
    for (args, exit, status) in [
        (vec!["verify", "--json"], 0, "passed"),
        (vec!["inspect", "--json"], 0, "inspected"),
        (
            vec!["verify", "--require-profile", "--json"],
            3,
            "unsupported",
        ),
        (
            vec!["verify", "--max-entries", "1", "--json"],
            4,
            "resource_limit",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_darkbox"))
            .args(args)
            .arg(&path)
            .env("TMPDIR", fixture.dir.path())
            .env("TMP", fixture.dir.path())
            .env("TEMP", fixture.dir.path())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["status"], status);
        assert_eq!(
            report["application_validation"],
            if status == "unsupported" {
                "unsupported"
            } else {
                "not_performed"
            }
        );
        assert!(!fs::read_dir(fixture.dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("darkbox-")
        }));
    }
    let versions = Command::new(env!("CARGO_BIN_EXE_darkbox"))
        .args(["versions", "--json"])
        .output()
        .unwrap();
    assert!(versions.status.success());
    let value: Value = serde_json::from_slice(&versions.stdout).unwrap();
    assert_eq!(value["versions"][0]["version"], "1.0.0");
    let usage = Command::new(env!("CARGO_BIN_EXE_darkbox"))
        .arg("verify")
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2));
    assert!(!usage.stderr.is_empty());
    for (kind, expected) in [("invalid", 1), ("unsupported", 3), ("missing", 5)] {
        let mut fixture = Fixture::new("notebook");
        if kind == "invalid" {
            fixture.files.remove("README.md");
        } else if kind == "unsupported" {
            fixture.manifest(|manifest| manifest["darkbox"]["version"] = json!("99.0.0"));
        }
        let path = if kind == "missing" {
            fixture.dir.path().join("absent.project")
        } else {
            fixture.archive(CompressionMethod::Stored, false)
        };
        let output = Command::new(env!("CARGO_BIN_EXE_darkbox"))
            .args(["verify", "--json"])
            .arg(path)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["status"],
            if kind == "missing" {
                "operational_error"
            } else {
                kind
            }
        );
    }
}
