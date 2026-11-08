//! Optional unsigned resource inventory, introduced by Darkbox 1.2.0.
use crate::{Error, Report, extensions::EntryDigest, versions};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn dynamic(manifest: &Value, path: &str) -> bool {
    path != "manifest.json"
        && path != crate::protection::SIGNATURE_PATH
        && manifest["darkbox"]["version"]
            .as_str()
            .and_then(|v| versions::find_in(versions::VERSIONS, v))
            .is_none_or(|spec| {
                path != versions::CATALOG_PATH && !spec.files.iter().any(|f| f.path == path)
            })
}

pub(crate) fn update(manifest: &mut Value, inventory: &BTreeMap<String, EntryDigest>) {
    if manifest.get("resourceInventory").is_some() {
        let entries: Vec<_> = inventory
            .values()
            .filter(|entry| dynamic(manifest, &entry.path))
            .collect();
        manifest["resourceInventory"] = serde_json::to_value(entries).unwrap();
    }
}

pub(crate) fn check(
    manifest: &Value,
    actual: &BTreeMap<String, EntryDigest>,
    report: &mut Report,
) -> Result<(), Error> {
    let Some(value) = manifest.get("resourceInventory") else {
        return Ok(());
    };
    let declared: Vec<EntryDigest> = serde_json::from_value(value.clone())
        .map_err(|_| Error::invalid("inventory.structure", "Malformed resource inventory"))?;
    let mut paths = BTreeSet::new();
    for entry in &declared {
        if !paths.insert(entry.path.as_str())
            || !dynamic(manifest, &entry.path)
            || actual.get(&entry.path) != Some(entry)
        {
            return Err(Error::invalid(
                "inventory.digest",
                "Resource inventory differs from actual file bytes",
            )
            .at(&entry.path));
        }
    }
    if paths.len() != actual.keys().filter(|path| dynamic(manifest, path)).count() {
        return Err(Error::invalid(
            "inventory.coverage",
            "Resource inventory must cover every dynamic file exactly once",
        ));
    }
    report.checks.push("inventory.sha256");
    report.note(
        "inventory.unsigned",
        "Unsigned hashes detect accidental changes but provide no authenticity or signer trust",
    );
    Ok(())
}

pub(crate) fn claims(report: &mut Report) -> Result<(), Error> {
    let manifest = report.manifest.as_ref().unwrap();
    let declared: Vec<EntryDigest> =
        serde_json::from_value(manifest.get("resourceInventory").cloned().ok_or_else(|| {
            Error::invalid(
                "inventory.missing",
                "Inventory inspection requires resourceInventory",
            )
        })?)
        .map_err(|_| Error::invalid("inventory.structure", "Malformed resource inventory"))?;
    let actual: BTreeMap<_, _> = report
        .entries
        .iter()
        .filter(|e| e.kind == "file" && dynamic(manifest, &e.path))
        .map(|e| (e.path.as_str(), e.bytes))
        .collect();
    let mut paths = BTreeSet::new();
    for entry in &declared {
        if !paths.insert(entry.path.as_str())
            || !dynamic(manifest, &entry.path)
            || actual.get(entry.path.as_str()) != Some(&entry.size)
        {
            return Err(Error::invalid(
                "inventory.coverage",
                "Inventory path/size claims disagree with the container",
            )
            .at(&entry.path));
        }
    }
    if paths.len() != actual.len() {
        return Err(Error::invalid(
            "inventory.coverage",
            "Inventory must cover every dynamic file exactly once",
        ));
    }
    report.checks.push("inventory.claims");
    report.note("inventory.unverified", "Only structure and declared sizes/hashes were inspected. Payload bytes, CRC, hashes, canonical bytes, SQLite, signatures and profile semantics were not verified. Matching cached timestamps or sizes do not establish unchanged content");
    Ok(())
}
