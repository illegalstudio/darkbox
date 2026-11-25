use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Lowercase hexadecimal digits of a digest.
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

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

const CAPABILITIES: [(&str, &str); 5] = [
    ("protection", "protection"),
    ("directory", "directory"),
    ("liveDirectory", "live_directory"),
    ("hotCapture", "hot_capture"),
    ("extensionBundles", "extension_bundles"),
];
const OFFICIAL_NAMESPACE: &str = "studio.illegal.darkbox.";

fn assert_version(version: &str) {
    assert!(
        version.split('.').count() == 3
            && version.split('.').all(|part| !part.is_empty()
                && (part == "0" || !part.starts_with('0'))
                && part.bytes().all(|b| b.is_ascii_digit())),
        "Invalid registered version"
    );
}

fn capabilities(row: &Value) -> String {
    let declared: BTreeSet<_> = row["capabilities"]
        .as_array()
        .expect("Every registered version declares its capabilities")
        .iter()
        .map(|value| value.as_str().expect("Capability name"))
        .collect();
    for name in &declared {
        assert!(
            CAPABILITIES.iter().any(|(known, _)| known == name),
            "Unknown capability: {name}"
        );
    }
    let fields: Vec<_> = CAPABILITIES
        .iter()
        .map(|(name, field)| format!("{field}: {}", declared.contains(name)))
        .collect();
    format!("Capabilities {{ {} }}", fields.join(", "))
}

/// Embed one independently versioned official extension bundle. Its files are
/// copied to the package root only when the manifest declares that extension.
fn extension_bundle(root: &Path, row: &Value) -> String {
    let namespace = row["namespace"].as_str().expect("Extension namespace");
    let version = row["version"].as_str().expect("Extension version");
    let minimum = row["minCommon"].as_str().expect("Minimum common version");
    let released = row["released"].as_bool().expect("Extension release status");
    assert_version(version);
    assert_version(minimum);
    let name = namespace
        .strip_prefix(OFFICIAL_NAMESPACE)
        .filter(|name| !name.is_empty() && !name.contains('.'))
        .expect("Only official single-segment extension names own a reserved directory");
    let directory = format!("docs/darkbox/{name}");
    let catalog_path = format!("{directory}/{version}.bundle.json");
    let base = root.join("extensions").join(namespace).join(version);
    let mut files = BTreeMap::new();
    let mut folders = BTreeSet::new();
    collect(&base, &base, &mut files, &mut folders);
    for shared in ["docs", "docs/darkbox"] {
        folders.remove(shared);
    }
    assert!(
        files
            .keys()
            .all(|path| path.starts_with(&format!("{directory}/")))
            && folders
                .iter()
                .all(|path| *path == directory || path.starts_with(&format!("{directory}/"))),
        "Extension bundle files must stay inside {directory}"
    );
    let catalog_source = files
        .get(&catalog_path)
        .expect("Generate the extension catalog before compiling")
        .clone();
    let catalog: Value = serde_json::from_slice(&fs::read(&catalog_source).unwrap()).unwrap();
    assert_eq!(catalog["extension"]["namespace"], namespace);
    assert_eq!(catalog["extension"]["version"], version);
    let declared_folders: BTreeSet<_> = catalog["folders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        folders, declared_folders,
        "Extension folder inventory changed"
    );
    let entries = catalog["files"]
        .as_array()
        .expect("Extension file inventory");
    assert_eq!(
        entries.len() + 1,
        files.len(),
        "Extension file inventory changed"
    );
    let mut generated = String::new();
    for entry in entries {
        let path = entry["path"].as_str().unwrap();
        assert_ne!(path, catalog_path, "The catalog excludes itself");
        let source = files.get(path).expect("Unknown extension catalog path");
        let bytes = fs::read(source).unwrap();
        let digest = hex(Sha256::digest(&bytes));
        assert_eq!(entry["size"].as_u64(), Some(bytes.len() as u64));
        assert_eq!(
            entry["sha256"], digest,
            "Regenerate the extension catalog: {path}"
        );
        generated.push_str(&format!("CanonicalFile {{ path: {path:?}, bytes: include_bytes!({source:?}), sha256: {digest:?} }},\n"));
    }
    // The catalog is compared with the embedded reference like any other file.
    let bytes = fs::read(&catalog_source).unwrap();
    let digest = hex(Sha256::digest(&bytes));
    generated.push_str(&format!("CanonicalFile {{ path: {catalog_path:?}, bytes: include_bytes!({catalog_source:?}), sha256: {digest:?} }},\n"));
    let folders: Vec<_> = folders.iter().map(|folder| format!("{folder:?}")).collect();
    format!(
        "ExtensionBundle {{ namespace: {namespace:?}, version: {version:?}, released: {released}, min_common: {minimum:?}, folders: &[{}], files: &[{generated}] }},\n",
        folders.join(", ")
    )
}

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-changed=archive");
    println!("cargo:rerun-if-changed=extensions");
    println!("cargo:rerun-if-changed=schema");
    println!("cargo:rerun-if-changed=specification");
    let registry: Value =
        serde_json::from_slice(&fs::read(root.join("versions.json")).unwrap()).unwrap();
    let mut output = String::from("pub static VERSIONS: &[VersionSpec] = &[\n");
    let mut versions = BTreeSet::new();
    let mut newest_writable = false;
    for row in registry["versions"]
        .as_array()
        .expect("Version registry array")
    {
        let version = row["version"].as_str().expect("Version string");
        assert_version(version);
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
        // Versions retired for writing stay readable forever.
        let writable = row["writable"].as_bool().expect("Writable status");
        newest_writable = writable;
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
            let digest = hex(Sha256::digest(&bytes));
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
        let capabilities = capabilities(row);
        output.push_str(&format!("VersionSpec {{ version: {version:?}, released: {released}, writable: {writable}, rules: RuleSet::V1, capabilities: {capabilities}, catalog: include_bytes!({catalog_path:?}), schema: include_str!({schema:?}), files: &[{generated_files}] }},\n"));
    }
    assert!(
        newest_writable,
        "The newest registered version must remain writable"
    );
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
    output.push_str("pub static EXTENSION_BUNDLES: &[ExtensionBundle] = &[\n");
    let mut bundles = BTreeSet::new();
    for row in registry["extensions"].as_array().into_iter().flatten() {
        let key = (
            row["namespace"].as_str().unwrap().to_string(),
            row["version"].as_str().unwrap().to_string(),
        );
        assert!(
            versions.contains(row["minCommon"].as_str().unwrap()),
            "An extension bundle needs a registered minimum common version"
        );
        output.push_str(&extension_bundle(&root, row));
        assert!(bundles.insert(key), "Duplicate registered extension bundle");
    }
    let mut disk_bundles = BTreeSet::new();
    if let Ok(namespaces) = fs::read_dir(root.join("extensions")) {
        for namespace in namespaces.map(|e| e.unwrap()) {
            for version in fs::read_dir(namespace.path()).unwrap().map(|e| e.unwrap()) {
                disk_bundles.insert((
                    namespace.file_name().into_string().unwrap(),
                    version.file_name().into_string().unwrap(),
                ));
            }
        }
    }
    assert_eq!(
        bundles, disk_bundles,
        "Every extension bundle needs a registry entry"
    );
    output.push_str("];\n");
    let destination = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("versions.rs");
    fs::write(destination, output).unwrap();
}
