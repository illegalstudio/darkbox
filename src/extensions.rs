//! Application-controlled extension registration and verification.
use crate::{Error, Limits, Report, Status};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One file of a package: its path, exact byte size and lowercase SHA-256.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct EntryDigest {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[non_exhaustive]
/// What a registered extension verifier can see of the package under analysis.
pub struct ExtensionContext<'a> {
    /// The parsed manifest.
    pub manifest: &'a Value,
    /// The exact manifest bytes, as signed.
    pub manifest_bytes: &'a [u8],
    /// Size and digest of every file in the package.
    pub inventory: &'a BTreeMap<String, EntryDigest>,
    /// The verification options in force.
    pub options: &'a VerificationOptions<'a>,
    /// The limits in force.
    pub limits: &'a Limits,
    /// When the analysis must stop.
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

/// Application- or SDK-supplied verification of one extension namespace.
pub trait ExtensionVerifier {
    /// The extension namespace this verifier handles.
    fn namespace(&self) -> &str;
    /// Whether this verifier implements the given extension version.
    fn supports(&self, version: &str) -> bool;
    /// Check the extension's semantics; record findings in `report` or return the blocking error.
    fn verify(&self, context: &ExtensionContext<'_>, report: &mut Report) -> Result<(), Error>;

    /// Select raw resources needed by this verifier once per scan. Digests are always available.
    /// None stages every file so existing application verifiers retain access.
    fn resources_to_stage(&self, _manifest: &Value) -> Option<std::collections::BTreeSet<String>> {
        None
    }

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

/// Extension verifiers by namespace. The default registers the official protection and sync verifiers.
pub struct ExtensionRegistry {
    verifiers: BTreeMap<String, Box<dyn ExtensionVerifier>>,
}

impl ExtensionRegistry {
    /// A registry without any verifier, not even the official ones.
    pub fn empty() -> Self {
        Self {
            verifiers: BTreeMap::new(),
        }
    }

    /// Register a verifier, replacing any earlier one for the same namespace.
    pub fn register(&mut self, verifier: impl ExtensionVerifier + 'static) {
        self.verifiers
            .insert(verifier.namespace().into(), Box::new(verifier));
    }

    /// The verifier for a namespace, if it supports that extension version.
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
        registry.register(crate::sync::SyncVerifier::default());
        registry
    }
}

/// Application-owned cache for immutable, independently identified resource bytes.
/// Never populate this from untrusted manifest claims or timestamps alone.
/// Returning None requests a complete byte pass. Metadata, databases and staged
/// callback resources are always read in full, even when the hook returns a hash.
pub trait TrustedDigests {
    /// The lowercase SHA-256 of an unchanged resource with this path and size, if the application guarantees it.
    fn sha256(&self, path: &str, size: u64) -> Option<String>;
}

#[derive(Default)]
#[non_exhaustive]
/// Application policy for one verification: extensions, profiles, keys and trust.
pub struct VerificationOptions<'a> {
    /// Verifiers for extension namespaces.
    pub extensions: ExtensionRegistry,
    /// Application-guaranteed digests for immutable live-directory resources.
    pub trusted_digests: Option<&'a dyn TrustedDigests>,
    /// Validators for application profiles.
    pub profiles: crate::profiles::ProfileRegistry,
    /// Fail unless a registered application profile validates the data.
    pub require_profile: bool,
    /// Decryption keys for protected content.
    pub decryption_keys: Option<&'a dyn crate::protection::DecryptionKeys>,
    /// Only application-supplied keys are trusted. Archive keys are never consulted.
    pub trusted_signers: BTreeMap<String, [u8; 32]>,
    /// Applications can require protection even if an attacker removes its descriptor.
    pub require_protection: bool,
}

impl<'a> VerificationOptions<'a> {
    /// Replace the registered extension verifiers.
    pub fn with_extensions(mut self, extensions: ExtensionRegistry) -> Self {
        self.extensions = extensions;
        self
    }
    /// Accept application-guaranteed digests for immutable live-directory resources.
    pub fn with_trusted_digests(mut self, digests: &'a dyn TrustedDigests) -> Self {
        self.trusted_digests = Some(digests);
        self
    }
    /// Replace the registered application profiles.
    pub fn with_profiles(mut self, profiles: crate::profiles::ProfileRegistry) -> Self {
        self.profiles = profiles;
        self
    }
    /// Fail unless a registered application profile validates the data.
    pub fn with_require_profile(mut self, required: bool) -> Self {
        self.require_profile = required;
        self
    }
    /// Supply decryption keys for protected content.
    pub fn with_decryption_keys(mut self, keys: &'a dyn crate::protection::DecryptionKeys) -> Self {
        self.decryption_keys = Some(keys);
        self
    }
    /// Replace the trusted signer public keys, by signer identifier.
    pub fn with_trusted_signers(mut self, signers: BTreeMap<String, [u8; 32]>) -> Self {
        self.trusted_signers = signers;
        self
    }
    /// Trust one signer public key.
    pub fn with_trusted_signer(mut self, id: impl Into<String>, public_key: [u8; 32]) -> Self {
        self.trusted_signers.insert(id.into(), public_key);
        self
    }
    /// Reject packages that do not declare the protection extension.
    pub fn with_require_protection(mut self, required: bool) -> Self {
        self.require_protection = required;
        self
    }
}
