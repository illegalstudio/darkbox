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

pub(crate) struct VersionSpec {
    pub version: &'static str,
    pub released: bool,
    pub rules: RuleSet,
    pub catalog: &'static [u8],
    pub schema: &'static str,
    pub files: &'static [CanonicalFile],
}

#[derive(Deserialize)]
pub(crate) struct Catalog {
    pub folders: Vec<String>,
}

include!(concat!(env!("OUT_DIR"), "/versions.rs"));

pub(crate) fn find_in<'a>(versions: &'a [VersionSpec], version: &str) -> Option<&'a VersionSpec> {
    versions.iter().find(|entry| entry.version == version)
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
                catalog: b"first",
                schema: "",
                files: &[],
            },
            VersionSpec {
                version: "1.1.0",
                released: false,
                rules: RuleSet::V1,
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
