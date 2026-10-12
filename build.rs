use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const CATALOG: &str = "docs/darkbox/bundle.json";

fn collect(
    base: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, PathBuf>,
    folders: &mut BTreeSet<String>,
) {
    for entry in fs::read_dir(dir).expect("Read canonical directory") {
        let entry = entry.expect("Read canonical entry");
        let path = entry.path();
        let relative = path
            .strip_prefix(base)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        let kind = entry.file_type().unwrap();
        assert!(
            !kind.is_symlink(),
            "Canonical bundles cannot contain symlinks"
        );
        if kind.is_dir() {
            folders.insert(relative);
            collect(base, &path, files, folders);
        } else {
            assert!(kind.is_file(), "Canonical bundles require regular files");
            files.insert(relative, path);
        }
    }
}

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-changed=archive");
    println!("cargo:rerun-if-changed=schema");
    println!("cargo:rerun-if-changed=specification");
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("versions.json")).unwrap()).unwrap();
    let mut output = String::from("pub static VERSIONS: &[VersionSpec] = &[\n");
    let mut versions = BTreeSet::new();
    for row in registry["versions"]
        .as_array()
        .expect("Version registry array")
    {
        let version = row["version"].as_str().expect("Version string");
        assert!(
            version.split('.').count() == 3
                && version.split('.').all(|part| !part.is_empty()
                    && (part == "0" || !part.starts_with('0'))
                    && part.bytes().all(|b| b.is_ascii_digit())),
            "Invalid registered version"
        );
        assert!(
            root.join("specification")
                .join(format!("{version}.md"))
                .is_file(),
            "A supported version needs its retained specification"
        );
        assert!(
            versions.insert(version.to_string()),
            "Duplicate registered version"
        );
        assert_eq!(
            row["rules"], "v1",
            "Register an implemented rule set before adding a version"
        );
        let released = row["released"].as_bool().expect("Release status");
        let base = root.join("archive").join(version);
        let mut files = BTreeMap::new();
        let mut folders = BTreeSet::new();
        collect(&base, &base, &mut files, &mut folders);
        let catalog_path = files
            .remove(CATALOG)
            .expect("Generate the catalog before compiling");
        let catalog: Value = serde_json::from_slice(&fs::read(&catalog_path).unwrap()).unwrap();
        assert_eq!(catalog["darkbox"]["id"], "darkbox");
        assert_eq!(catalog["darkbox"]["version"], version);
        let declared_folders: BTreeSet<_> = catalog["folders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            folders, declared_folders,
            "Canonical folder inventory changed"
        );
        let entries = catalog["files"]
            .as_array()
            .expect("Canonical file inventory");
        assert_eq!(
            entries.len(),
            files.len(),
            "Canonical file inventory changed"
        );
        let mut seen = BTreeSet::new();
        let mut generated_files = String::new();
        for entry in entries {
            let path = entry["path"].as_str().unwrap();
            assert!(seen.insert(path), "Duplicate catalog path");
            let source = files.get(path).expect("Unknown catalog path");
            let bytes = fs::read(source).unwrap();
            let digest = format!("{:x}", Sha256::digest(&bytes));
            assert_eq!(
                entry["size"].as_u64(),
                Some(bytes.len() as u64),
                "Catalog size differs: {path}"
            );
            assert_eq!(entry["sha256"], digest, "Regenerate the catalog: {path}");
            generated_files.push_str(&format!("CanonicalFile {{ path: {path:?}, bytes: include_bytes!({source:?}), sha256: {digest:?} }},\n"));
        }
        let schema = root
            .join("schema")
            .join(version)
            .join("manifest.schema.json");
        let schema_value: Value =
            serde_json::from_slice(&fs::read(&schema).expect("Versioned manifest schema")).unwrap();
        assert_eq!(
            schema_value["properties"]["darkbox"]["properties"]["version"]["const"],
            version
        );
        output.push_str(&format!("VersionSpec {{ version: {version:?}, released: {released}, rules: RuleSet::V1, catalog: include_bytes!({catalog_path:?}), schema: include_str!({schema:?}), files: &[{generated_files}] }},\n"));
    }
    let disk_versions: BTreeSet<_> = fs::read_dir(root.join("archive"))
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_type().unwrap().is_dir())
        .map(|e| e.file_name().into_string().unwrap())
        .collect();
    assert_eq!(
        versions, disk_versions,
        "Every canonical version needs a supported registry entry"
    );
    output.push_str("];\n");
    let destination = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("versions.rs");
    fs::write(destination, output).unwrap();
}
