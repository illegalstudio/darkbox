//! Typed construction helpers. The complete JSON remains accessible for extension data.
use crate::{Error, protection::ProtectionData, versions};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
/// One logical application table of a declared database.
pub struct TableDeclaration {
    /// The exact SQL table name.
    pub name: String,
    /// A short human-readable description.
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
/// One declared SQLite database.
pub struct DatabaseDeclaration {
    /// Package-relative path of the database.
    pub path: String,
    /// A short human-readable description.
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The expected SQLite `PRAGMA user_version`.
    pub user_version: Option<i64>,
    /// Every logical application table.
    pub tables: Vec<TableDeclaration>,
}

impl TableDeclaration {
    /// Declare one logical application table by its exact SQL name.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

impl DatabaseDeclaration {
    /// Declare one SQLite database and its logical application tables.
    pub fn new(
        path: impl Into<String>,
        description: impl Into<String>,
        tables: impl IntoIterator<Item = TableDeclaration>,
    ) -> Self {
        Self {
            path: path.into(),
            description: description.into(),
            user_version: None,
            tables: tables.into_iter().collect(),
        }
    }
    /// Declare the expected SQLite `PRAGMA user_version`.
    pub fn with_user_version(mut self, user_version: i64) -> Self {
        self.user_version = Some(user_version);
        self
    }
}

/// Builds a manifest for one exact common version, then validates it against that version's schema.
pub struct ManifestBuilder {
    value: Value,
}

impl ManifestBuilder {
    /// Include all directory declarations for the exact embedded canonical version.
    pub fn new(version: &str, application_id: &str, format_version: &str) -> Result<Self, Error> {
        let spec = versions::find_in(versions::VERSIONS, version).ok_or_else(|| {
            Error::new(
                crate::Status::Unsupported,
                "version.unsupported",
                "Unsupported common version",
            )
        })?;
        let catalog: versions::Catalog = serde_json::from_slice(spec.catalog).unwrap();
        let folders: Vec<_> = catalog.folders.iter().map(|path| json!({"path":path,"description":"Official version-specific Darkbox documentation"})).collect();
        Ok(Self {
            value: json!({"darkbox":{"id":"darkbox","version":version},"application":{"id":application_id,"formatVersion":format_version,"profilePath":"docs/profile.md"},"folders":folders,"databases":[]}),
        })
    }
    /// Stable library identity for Darkbox 1.2.0 delta editions.
    pub fn package_id(mut self, id: &str) -> Self {
        self.value["packageId"] = json!(id);
        self
    }
    /// Include an unsigned inventory, automatically rebuilt by SDK writers.
    pub fn resource_inventory(mut self) -> Self {
        self.value["resourceInventory"] = json!([]);
        self
    }
    /// Set the path of the included application profile document.
    pub fn profile_path(mut self, path: &str) -> Self {
        self.value["application"]["profilePath"] = json!(path);
        self
    }
    /// Declare a folder, or replace the description of one already declared.
    pub fn folder(mut self, path: &str, description: &str) -> Self {
        let folders = self.value["folders"].as_array_mut().unwrap();
        if let Some(folder) = folders.iter_mut().find(|folder| folder["path"] == path) {
            folder["description"] = json!(description);
        } else {
            folders.push(json!({"path":path,"description":description}));
        }
        self
    }
    /// Declare a database.
    pub fn database(mut self, database: DatabaseDeclaration) -> Self {
        self.value["databases"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(database).unwrap());
        self
    }
    /// Record the software that packaged this copy and, optionally, when (RFC 3339 UTC).
    pub fn creator(mut self, id: &str, version: &str, created_at: Option<&str>) -> Self {
        self.value["creator"] = json!({"id":id,"version":version});
        if let Some(date) = created_at {
            self.value["creator"]["createdAt"] = json!(date);
        }
        self
    }
    /// Declare an extension. On common versions with extension bundles, an official extension also declares its documentation folders.
    pub fn extension(
        mut self,
        namespace: &str,
        version: &str,
        required: bool,
        data: Value,
    ) -> Self {
        self.value["extensions"][namespace] =
            json!({"version":version,"required":required,"data":data});
        // A bundle-capable common version carries official extension
        // documentation in that extension's own canonical bundle.
        if let Some(bundle) = self.value["darkbox"]["version"]
            .as_str()
            .and_then(versions::find)
            .and_then(|spec| versions::extension_bundle(spec, namespace, version))
        {
            for folder in bundle.folders {
                self = self.folder(folder, "Official extension documentation");
            }
        }
        self
    }
    /// Declare the official protection extension and the folder of its detached signature.
    pub fn protection(self, data: ProtectionData) -> Self {
        self.folder("extensions", "Application extension resources")
            .folder(
                &format!("extensions/{}", crate::protection::NAMESPACE),
                "Authenticated protection signature",
            )
            .extension(
                crate::protection::NAMESPACE,
                crate::protection::VERSION,
                true,
                serde_json::to_value(data).unwrap(),
            )
    }
    /// Validate the metadata schema. Resource relationships are checked at publication.
    pub fn build(self) -> Result<Value, Error> {
        crate::creation::specification(&self.value)?;
        Ok(self.value)
    }
}
