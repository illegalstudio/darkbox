//! Typed construction helpers. The complete JSON remains accessible for extension data.
use crate::{
    Error,
    protection::ProtectionData,
    versions::{self, Catalog},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableDeclaration {
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseDeclaration {
    pub path: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_version: Option<i64>,
    pub tables: Vec<TableDeclaration>,
}

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
        let catalog: Catalog = serde_json::from_slice(spec.catalog).unwrap();
        let folders: Vec<_> = catalog.folders.iter().map(|path| json!({"path":path,"description":"Official version-specific Darkbox documentation"})).collect();
        Ok(Self {
            value: json!({"darkbox":{"id":"darkbox","version":version},"application":{"id":application_id,"formatVersion":format_version,"profilePath":"docs/profile.md"},"folders":folders,"databases":[]}),
        })
    }
    pub fn profile_path(mut self, path: &str) -> Self {
        self.value["application"]["profilePath"] = json!(path);
        self
    }
    pub fn folder(mut self, path: &str, description: &str) -> Self {
        let folders = self.value["folders"].as_array_mut().unwrap();
        if let Some(folder) = folders.iter_mut().find(|folder| folder["path"] == path) {
            folder["description"] = json!(description);
        } else {
            folders.push(json!({"path":path,"description":description}));
        }
        self
    }
    pub fn database(mut self, database: DatabaseDeclaration) -> Self {
        self.value["databases"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::to_value(database).unwrap());
        self
    }
    pub fn creator(mut self, id: &str, version: &str, created_at: Option<&str>) -> Self {
        self.value["creator"] = json!({"id":id,"version":version});
        if let Some(date) = created_at {
            self.value["creator"]["createdAt"] = json!(date);
        }
        self
    }
    pub fn extension(
        mut self,
        namespace: &str,
        version: &str,
        required: bool,
        data: Value,
    ) -> Self {
        self.value["extensions"][namespace] =
            json!({"version":version,"required":required,"data":data});
        self
    }
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
