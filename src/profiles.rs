//! Application-owned semantic validation, separate from common container checks.
use crate::{Error, Limits, VerificationOptions, extensions::EntryDigest};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, time::Instant};

#[non_exhaustive]
/// What a registered application profile can read while validating a package.
pub struct ProfileContext<'a> {
    /// The parsed manifest.
    pub manifest: &'a Value,
    /// Size and digest of every file in the package.
    pub inventory: &'a BTreeMap<String, EntryDigest>,
    /// The limits in force.
    pub limits: &'a Limits,
    /// When the analysis must stop.
    pub deadline: Instant,
    /// The verification options in force.
    pub options: &'a VerificationOptions<'a>,
    pub(crate) staged: &'a BTreeMap<String, PathBuf>,
}

impl ProfileContext<'_> {
    /// Authenticate an encrypted attachment for application semantic validation.
    /// Missing keys return protection.key_absent; profiles choose their policy.
    pub fn decrypt_resource(&self, path: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
        let context = crate::package::file_context(self.manifest, path)?;
        let keys = self.options.decryption_keys.ok_or_else(|| {
            Error::new(
                crate::Status::Unsupported,
                "protection.key_absent",
                "Profile decryption requires an application key provider",
            )
        })?;
        let key = crate::package::key(keys, &context.key_id)?;
        self.with_resource(path, |reader| {
            let mut block = Vec::new();
            reader.read_to_end(&mut block).map_err(crate::io_failure)?;
            crate::protection::decrypt_block(&block, &key, &context)
        })
    }
    /// Authenticate and decrypt one protected database value for semantic validation.
    pub fn decrypt_value(
        &self,
        address: crate::ValueAddress<'_>,
    ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, Error> {
        let (context, id_column) = crate::package::value_context(
            self.manifest,
            address.database,
            address.table,
            address.column,
            address.record_id,
        )?;
        let keys = self.options.decryption_keys.ok_or_else(|| {
            Error::new(
                crate::Status::Unsupported,
                "protection.key_absent",
                "Profile decryption requires an application key provider",
            )
        })?;
        self.with_database(address.database, |db| {
            crate::package::decrypt_value(db, &context, &id_column, keys)
        })
    }
    /// Read one resource's raw bytes from private staging.
    pub fn with_resource<T>(
        &self,
        path: &str,
        read: impl FnOnce(&mut dyn Read) -> Result<T, Error>,
    ) -> Result<T, Error> {
        crate::container::check_deadline(self.deadline)?;
        let path = self.staged.get(path).ok_or_else(|| {
            Error::invalid("profile.resource", "Profile resource is absent").at(path)
        })?;
        let mut file = File::open(path).map_err(crate::io_failure)?;
        let result = read(&mut file)?;
        crate::container::check_deadline(self.deadline)?;
        Ok(result)
    }

    /// Only databases declared by the manifest are exposed. No archive SQL is executed.
    pub fn with_database<T>(
        &self,
        path: &str,
        read: impl FnOnce(&rusqlite::Connection) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.manifest["databases"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|db| db["path"] == path)
        {
            return Err(Error::invalid("profile.database", "Database is not declared").at(path));
        }
        let file = self
            .staged
            .get(path)
            .ok_or_else(|| Error::invalid("profile.database", "Database is absent").at(path))?;
        let db = crate::sqlite::open(file, self.limits, self.deadline)?;
        let result = read(&db)?;
        crate::container::check_deadline(self.deadline)?;
        Ok(result)
    }
}

/// Registered code is supplied by the integrating application, never by the archive.
/// Validation runs after successful common, SQLite and required-extension checks.
/// Missing plaintext keys should be handled explicitly by the profile's own policy.
pub trait ApplicationProfile {
    /// The `application.id` this profile validates.
    fn id(&self) -> &str;
    /// Whether this profile implements the given `application.formatVersion`.
    fn supports(&self, format_version: &str) -> bool;
    /// Validate application semantics; an error marks application validation as failed.
    fn validate(&self, context: &ProfileContext<'_>) -> Result<(), Error>;
}

#[derive(Default)]
/// Application profiles by identifier.
pub struct ProfileRegistry {
    profiles: BTreeMap<String, Box<dyn ApplicationProfile>>,
}

impl ProfileRegistry {
    /// Register a profile, replacing any earlier one with the same identifier.
    pub fn register(&mut self, profile: impl ApplicationProfile + 'static) {
        self.profiles.insert(profile.id().into(), Box::new(profile));
    }
    /// The profile for an identifier, if it supports that data-format version.
    pub fn get(&self, id: &str, version: &str) -> Option<&dyn ApplicationProfile> {
        self.profiles
            .get(id)
            .filter(|profile| profile.supports(version))
            .map(Box::as_ref)
    }
}
