//! Application-owned semantic validation, separate from common container checks.
use crate::{Error, Limits, VerificationOptions, extensions::EntryDigest};
use serde_json::Value;
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, time::Instant};

pub struct ProfileContext<'a> {
    pub manifest: &'a Value,
    pub inventory: &'a BTreeMap<String, EntryDigest>,
    pub limits: &'a Limits,
    pub deadline: Instant,
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
    fn id(&self) -> &str;
    fn supports(&self, format_version: &str) -> bool;
    fn validate(&self, context: &ProfileContext<'_>) -> Result<(), Error>;
}

#[derive(Default)]
pub struct ProfileRegistry {
    profiles: BTreeMap<String, Box<dyn ApplicationProfile>>,
}

impl ProfileRegistry {
    pub fn register(&mut self, profile: impl ApplicationProfile + 'static) {
        self.profiles.insert(profile.id().into(), Box::new(profile));
    }
    pub fn get(&self, id: &str, version: &str) -> Option<&dyn ApplicationProfile> {
        self.profiles
            .get(id)
            .filter(|profile| profile.supports(version))
            .map(Box::as_ref)
    }
}
