use serde::Deserialize;

pub(crate) const CATALOG_PATH: &str = "docs/darkbox/bundle.json";

#[derive(Clone, Copy)]
pub(crate) enum RuleSet {
    V1,
}

pub(crate) struct CanonicalFile {
    pub path: &'static str,
    pub bytes: &'static [u8],
    pub sha256: &'static str,
}

/// Optional structures a common version defines. Declared in `versions.json`
/// so that registering a version states its features in exactly one place.
#[derive(Clone, Copy, Default)]
pub(crate) struct Capabilities {
    /// The official protection extension may be declared.
    pub protection: bool,
    /// Directory representation, `packageId`, unsigned inventory and deltas.
    pub directory: bool,
    /// Coordinated live directory storage and application-trusted digests.
    pub live_directory: bool,
    /// Retained hot captures with a short write barrier.
    pub hot_capture: bool,
    /// Official extension documentation travels in separate per-extension bundles.
    pub extension_bundles: bool,
}

pub(crate) struct VersionSpec {
    pub version: &'static str,
    pub released: bool,
    pub rules: RuleSet,
    pub capabilities: Capabilities,
    pub catalog: &'static [u8],
    pub schema: &'static str,
    pub files: &'static [CanonicalFile],
}

/// Canonical documentation of one official extension version. It is included
/// exactly when a manifest of a bundle-capable common version declares it.
pub(crate) struct ExtensionBundle {
    pub namespace: &'static str,
    pub version: &'static str,
    pub released: bool,
    pub min_common: &'static str,
    pub folders: &'static [&'static str],
    /// Every bundle file, including its own catalog.
    pub files: &'static [CanonicalFile],
}

pub(crate) const OFFICIAL_NAMESPACE: &str = "studio.illegal.darkbox.";

#[derive(Deserialize)]
pub(crate) struct Catalog {
    pub folders: Vec<String>,
}

include!(concat!(env!("OUT_DIR"), "/versions.rs"));

pub(crate) fn find_in<'a>(versions: &'a [VersionSpec], version: &str) -> Option<&'a VersionSpec> {
    versions.iter().find(|entry| entry.version == version)
}

pub(crate) fn find(version: &str) -> Option<&'static VersionSpec> {
    find_in(VERSIONS, version)
}

/// Capabilities of the common version a manifest declares; none when unsupported.
pub(crate) fn capabilities(manifest: &serde_json::Value) -> Capabilities {
    manifest["darkbox"]["version"]
        .as_str()
        .and_then(find)
        .map(|spec| spec.capabilities)
        .unwrap_or_default()
}

pub(crate) fn numbers(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.').map(|part| part.parse().ok());
    let numbers = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(numbers)
}

/// Reserved documentation directory of an official namespace, for example
/// `docs/darkbox/protection`.
pub(crate) fn official_directory(namespace: &str) -> Option<String> {
    namespace
        .strip_prefix(OFFICIAL_NAMESPACE)
        .filter(|name| !name.is_empty() && !name.contains('.'))
        .map(|name| format!("docs/darkbox/{name}"))
}

/// The trusted bundle for one extension version under one common version.
pub(crate) fn extension_bundle(
    spec: &VersionSpec,
    namespace: &str,
    version: &str,
) -> Option<&'static ExtensionBundle> {
    if !spec.capabilities.extension_bundles {
        return None;
    }
    let common = numbers(spec.version)?;
    EXTENSION_BUNDLES.iter().find(|bundle| {
        bundle.namespace == namespace
            && bundle.version == version
            && numbers(bundle.min_common)
                .is_some_and(|minimum| minimum.0 == common.0 && minimum <= common)
    })
}

/// Extension bundles selected by the manifest's declared extension versions.
pub(crate) fn declared_bundles(
    spec: &VersionSpec,
    manifest: &serde_json::Value,
) -> Vec<&'static ExtensionBundle> {
    manifest["extensions"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(namespace, descriptor)| {
            extension_bundle(spec, namespace, descriptor["version"].as_str()?)
        })
        .collect()
}

/// Every static canonical file except the common catalog: the common bundle
/// plus the bundles of declared official extensions.
pub(crate) fn canonical_files(
    spec: &'static VersionSpec,
    manifest: &serde_json::Value,
) -> Vec<&'static CanonicalFile> {
    spec.files
        .iter()
        .chain(
            declared_bundles(spec, manifest)
                .into_iter()
                .flat_map(|bundle| bundle.files.iter()),
        )
        .collect()
}

/// Canonical directories the manifest must declare for its exact contents.
pub(crate) fn canonical_folders(
    spec: &VersionSpec,
    manifest: &serde_json::Value,
) -> Result<Vec<String>, serde_json::Error> {
    let catalog: Catalog = serde_json::from_slice(spec.catalog)?;
    let mut folders = catalog.folders;
    for bundle in declared_bundles(spec, manifest) {
        folders.extend(bundle.folders.iter().map(|folder| folder.to_string()));
    }
    Ok(folders)
}

/// Align official extension documentation with a manifest about to be saved:
/// insert the bundle of every declared extension version, declare its folders
/// and drop registered bundles that are no longer declared.
pub(crate) fn align_extension_bundles(
    manifest: &mut serde_json::Value,
    files: &mut std::collections::BTreeMap<String, Vec<u8>>,
) {
    let Some(spec) = manifest["darkbox"]["version"].as_str().and_then(find) else {
        return;
    };
    if !spec.capabilities.extension_bundles {
        return;
    }
    let declared = declared_bundles(spec, manifest);
    let keep: std::collections::BTreeSet<&str> = declared
        .iter()
        .flat_map(|bundle| bundle.files.iter().map(|file| file.path))
        .collect();
    let folders: std::collections::BTreeSet<&str> = declared
        .iter()
        .flat_map(|bundle| bundle.folders.iter().copied())
        .collect();
    for bundle in EXTENSION_BUNDLES {
        for file in bundle.files {
            if !keep.contains(file.path) {
                files.remove(file.path);
            }
        }
    }
    for bundle in &declared {
        for file in bundle.files {
            files.insert(file.path.to_owned(), file.bytes.to_vec());
        }
    }
    if let Some(list) = manifest["folders"].as_array_mut() {
        list.retain(|folder| {
            let path = folder["path"].as_str().unwrap_or_default();
            folders.contains(path)
                || !EXTENSION_BUNDLES
                    .iter()
                    .any(|bundle| bundle.folders.contains(&path))
        });
        for folder in folders {
            if !list.iter().any(|entry| entry["path"] == folder) {
                list.push(serde_json::json!({
                    "path": folder,
                    "description": "Official extension documentation"
                }));
            }
        }
    }
}

/// Paths of all static canonical files for this manifest, including the
/// common catalog. Empty for an unsupported common version.
pub(crate) fn canonical_paths(
    manifest: &serde_json::Value,
) -> std::collections::BTreeSet<&'static str> {
    manifest["darkbox"]["version"]
        .as_str()
        .and_then(find)
        .map(|spec| {
            canonical_files(spec, manifest)
                .iter()
                .map(|file| file.path)
                .chain([CATALOG_PATH])
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a path is static canonical documentation for this manifest.
pub(crate) fn is_canonical(manifest: &serde_json::Value, path: &str) -> bool {
    manifest["darkbox"]["version"]
        .as_str()
        .and_then(find)
        .is_some_and(|spec| {
            path == CATALOG_PATH
                || canonical_files(spec, manifest)
                    .iter()
                    .any(|file| file.path == path)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dispatch_uses_exact_registered_versions() {
        let versions = [
            VersionSpec {
                version: "1.0.0",
                released: false,
                rules: RuleSet::V1,
                capabilities: Capabilities::default(),
                catalog: b"first",
                schema: "",
                files: &[],
            },
            VersionSpec {
                version: "1.1.0",
                released: false,
                rules: RuleSet::V1,
                capabilities: Capabilities::default(),
                catalog: b"second",
                schema: "",
                files: &[],
            },
        ];
        assert_eq!(find_in(&versions, "1.0.0").unwrap().catalog, b"first");
        assert_eq!(find_in(&versions, "1.1.0").unwrap().catalog, b"second");
        assert!(find_in(&versions, "1.0.1").is_none());
        assert!(find_in(&versions, "2.0.0").is_none());
    }
}
