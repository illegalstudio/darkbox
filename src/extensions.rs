//! Application-controlled extension registration and verification.
use crate::{Error, Limits, Report, Status};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryDigest {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

pub struct ExtensionContext<'a> {
    pub manifest: &'a Value,
    pub manifest_bytes: &'a [u8],
    pub inventory: &'a BTreeMap<String, EntryDigest>,
    pub options: &'a VerificationOptions<'a>,
    pub limits: &'a Limits,
    pub deadline: Instant,
    pub(crate) staged: &'a BTreeMap<String, PathBuf>,
}

impl ExtensionContext<'_> {
    /// Read bounded, CRC-checked uncompressed bytes from isolated staging.
    pub fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        crate::container::check_deadline(self.deadline)?;
        let file = self.staged.get(path).ok_or_else(|| {
            Error::invalid(
                "extension.resource_missing",
                "Extension resource is missing",
            )
            .at(path)
        })?;
        std::fs::read(file).map_err(crate::io_failure)
    }
}

pub trait ExtensionVerifier {
    fn namespace(&self) -> &str;
    fn supports(&self, version: &str) -> bool;
    fn verify(&self, context: &ExtensionContext<'_>, report: &mut Report) -> Result<(), Error>;

    /// Update extension metadata/resources before final validation and publication.
    /// The default refuses saving, even for a recognized extension.
    fn prepare_save(
        &self,
        _previous: &Value,
        _manifest: &mut Value,
        _files: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), Error> {
        Err(Error::new(
            Status::Unsupported,
            "save.extension_capability",
            "The registered verifier has no writer capability",
        ))
    }

    /// Approve a complete streamed edition and synchronize its descriptor.
    /// Resource bytes have already been written; only metadata can be changed.
    /// The default does not imply creation capability from a registered verifier.
    fn prepare_streamed_package(
        &self,
        _previous: Option<&Value>,
        _manifest: &mut Value,
        _inventory: &BTreeMap<String, EntryDigest>,
    ) -> Result<(), Error> {
        Err(Error::new(
            Status::Unsupported,
            "create.extension_capability",
            "The registered verifier has no streaming writer capability",
        ))
    }
}

pub struct ExtensionRegistry {
    verifiers: BTreeMap<String, Box<dyn ExtensionVerifier>>,
}

impl ExtensionRegistry {
    pub fn empty() -> Self {
        Self {
            verifiers: BTreeMap::new(),
        }
    }

    pub fn register(&mut self, verifier: impl ExtensionVerifier + 'static) {
        self.verifiers
            .insert(verifier.namespace().into(), Box::new(verifier));
    }

    pub fn get(&self, namespace: &str, version: &str) -> Option<&dyn ExtensionVerifier> {
        self.verifiers
            .get(namespace)
            .filter(|verifier| verifier.supports(version))
            .map(Box::as_ref)
    }
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        let mut registry = Self::empty();
        registry.register(crate::protection::ProtectionVerifier);
        registry
    }
}

#[derive(Default)]
pub struct VerificationOptions<'a> {
    pub extensions: ExtensionRegistry,
    pub profiles: crate::profiles::ProfileRegistry,
    pub require_profile: bool,
    pub decryption_keys: Option<&'a dyn crate::protection::DecryptionKeys>,
    /// Only application-supplied keys are trusted. Archive keys are never consulted.
    pub trusted_signers: BTreeMap<String, [u8; 32]>,
    /// Applications can require protection even if an attacker removes its descriptor.
    pub require_protection: bool,
}
