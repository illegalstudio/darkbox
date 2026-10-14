//! Official selective protection extension, version 1.0.0.
use crate::extensions::{EntryDigest, ExtensionContext, ExtensionVerifier};
use crate::{Error, Report, Status};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

pub const NAMESPACE: &str = "studio.illegal.darkbox.protection";
pub const VERSION: &str = "1.0.0";
pub const SIGNATURE_PATH: &str = "extensions/studio.illegal.darkbox.protection/manifest.ed25519";
const HEADER: usize = 28;
const MAX_PLAINTEXT: u64 = (1u64 << 36) - 32;

pub trait DecryptionKeys {
    fn key(&self, key_id: &str) -> Option<Zeroizing<[u8; 32]>>;
}

/// Implementations MUST reserve nonces durably and globally for the actual key,
/// across sessions, devices, packages and key identifier aliases.
pub trait NonceSequence {
    fn next_nonce(&mut self, key_id: &str) -> Result<[u8; 12], Error>;
}

pub trait ManifestSigner {
    fn signer_id(&self) -> &str;
    fn public_key(&self) -> [u8; 32];
    fn sign(&self, manifest_bytes: &[u8]) -> Result<[u8; 64], Error>;
}

/// An application-owned, zeroizing in-memory key provider. Keys are never serialized.
#[derive(Default)]
pub struct KeyRing {
    keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
}
impl KeyRing {
    pub fn insert(&mut self, id: impl Into<String>, key: Zeroizing<[u8; 32]>) {
        self.keys.insert(id.into(), key);
    }
    pub fn remove(&mut self, id: &str) -> bool {
        self.keys.remove(id).is_some()
    }
    pub fn contains(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }
}
impl DecryptionKeys for KeyRing {
    fn key(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        self.keys.get(id).map(|key| Zeroizing::new(**key))
    }
}

/// Local pure Ed25519 signing. Applications can instead implement ManifestSigner
/// with an external signer or secure key storage.
pub struct Ed25519Signer {
    id: String,
    key: ed25519_dalek::SigningKey,
}
impl Ed25519Signer {
    pub fn from_seed(id: impl Into<String>, seed: Zeroizing<[u8; 32]>) -> Self {
        Self {
            id: id.into(),
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }
}
impl ManifestSigner for Ed25519Signer {
    fn signer_id(&self) -> &str {
        &self.id
    }
    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    fn sign(&self, bytes: &[u8]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;
        Ok(self.key.sign(bytes).to_bytes())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BlockLocation {
    File {
        path: String,
    },
    Sqlite {
        database: String,
        table: String,
        column: String,
        record_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockContext {
    pub package_id: String,
    pub key_id: String,
    pub location: BlockLocation,
}

fn lp(output: &mut Vec<u8>, text: &str) -> Result<(), Error> {
    let length = u32::try_from(text.len()).map_err(|_| Error::limit("AAD string is too long"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(text.as_bytes());
    Ok(())
}

impl BlockContext {
    pub fn aad(&self, header: &[u8]) -> Result<Vec<u8>, Error> {
        if header.len() != HEADER {
            return Err(block_error());
        }
        if self.package_id.len() != 32
            || !self
                .package_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self.key_id.is_empty()
            || self.key_id.len() > 255
            || !self
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(Error::invalid(
                "protection.context",
                "Invalid package or key identifier",
            ));
        }
        let mut output = b"Darkbox-PROTECTION-AAD\0".to_vec();
        output.extend_from_slice(header);
        for text in [NAMESPACE, VERSION, &self.package_id, &self.key_id] {
            lp(&mut output, text)?;
        }
        match &self.location {
            BlockLocation::File { path } => {
                crate::paths::validate(path)?;
                output.push(1);
                lp(&mut output, path)?;
            }
            BlockLocation::Sqlite {
                database,
                table,
                column,
                record_id,
            } => {
                crate::paths::validate(database)?;
                if [table, column]
                    .iter()
                    .any(|s| s.is_empty() || s.len() > 255 || s.contains('\0'))
                    || record_id.is_empty()
                    || record_id.len() > 1024
                    || record_id.contains('\0')
                {
                    return Err(Error::invalid(
                        "protection.context",
                        "Invalid SQLite context identifier",
                    ));
                }
                output.push(2);
                for text in [database, table, column, record_id] {
                    lp(&mut output, text)?;
                }
            }
        }
        Ok(output)
    }
}

fn block_error() -> Error {
    Error::invalid("protection.block", "Malformed encrypted block")
}

pub fn block_header(block: &[u8]) -> Result<&[u8], Error> {
    if block.len() < HEADER + 16 || &block[..4] != b"DBXP" {
        return Err(block_error());
    }
    if block[4] != 1 || block[5] != 1 {
        return Err(Error::new(
            Status::Unsupported,
            "protection.block_version",
            "Unsupported block version or algorithm",
        ));
    }
    let size = u64::from_be_bytes(block[20..28].try_into().unwrap());
    if block[6..8] != [0, 0] || size > MAX_PLAINTEXT || size != (block.len() - HEADER - 16) as u64 {
        return Err(block_error());
    }
    Ok(&block[..HEADER])
}

pub fn encrypt_block(
    plaintext: &[u8],
    key: &[u8; 32],
    context: &BlockContext,
    nonces: &mut dyn NonceSequence,
) -> Result<Vec<u8>, Error> {
    if plaintext.len() as u64 > MAX_PLAINTEXT {
        return Err(Error::limit("AES-GCM plaintext is too large"));
    }
    let mut header = b"DBXP\x01\x01\0\0".to_vec();
    header.extend_from_slice(&nonces.next_nonce(&context.key_id)?);
    header.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    let aad = context.aad(&header)?;
    let ciphertext = Aes256Gcm::new_from_slice(key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&header[8..20]),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::invalid("protection.encryption", "Encryption failed"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

pub fn decrypt_block(
    block: &[u8],
    key: &[u8; 32],
    context: &BlockContext,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let header = block_header(block)?;
    let aad = context.aad(header)?;
    // An in-place zeroizing buffer also clears unauthenticated plaintext on failure.
    use aes_gcm::aead::AeadInPlace;
    let mut plaintext = Zeroizing::new(block[HEADER..block.len() - 16].to_vec());
    Aes256Gcm::new_from_slice(key)
        .unwrap()
        .decrypt_in_place_detached(
            Nonce::from_slice(&header[8..20]),
            &aad,
            plaintext.as_mut(),
            aes_gcm::Tag::from_slice(&block[block.len() - 16..]),
        )
        .map_err(|_| {
            Error::invalid(
                "protection.authentication",
                "Encrypted block authentication failed",
            )
        })?;
    Ok(plaintext)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileProtection {
    pub path: String,
    pub key_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SqliteProtection {
    pub database: String,
    pub table: String,
    pub column: String,
    pub record_id_column: String,
    pub key_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignatureDeclaration {
    pub algorithm: String,
    pub signer_id: String,
    pub path: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtectionData {
    pub package_id: String,
    pub signature: SignatureDeclaration,
    pub inventory: Vec<EntryDigest>,
    pub files: Vec<FileProtection>,
    pub sqlite: Vec<SqliteProtection>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EncryptedContent {
    pub context: BlockContext,
    pub block_sha256: String,
    pub nonce_hex: Option<String>,
    pub authentication: &'static str,
    pub plaintext_validation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProtectionReport {
    pub extension_version: String,
    pub signature: &'static str,
    pub inventory_verified: bool,
    pub encrypted: Vec<EncryptedContent>,
}

pub struct ProtectionVerifier;

pub(crate) fn data(manifest: &Value) -> Result<ProtectionData, Error> {
    let descriptor = &manifest["extensions"][NAMESPACE];
    if descriptor["version"] != VERSION {
        return Err(Error::new(
            Status::Unsupported,
            "protection.version",
            "Unsupported protection extension version",
        ));
    }
    if descriptor["required"] != true {
        return Err(Error::invalid(
            "protection.required",
            "Protection must be a required extension",
        ));
    }
    let schema: Value = serde_json::from_str(include_str!(
        "../archive/1.1.0/docs/darkbox/protection/1.0.0.schema.json"
    ))
    .unwrap();
    if !jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(descriptor)
    {
        return Err(Error::invalid(
            "protection.schema",
            "Protection descriptor does not match its versioned schema",
        ));
    }
    serde_json::from_value(descriptor["data"].clone())
        .map_err(|_| Error::invalid("protection.schema", "Malformed protection declarations"))
}

impl ExtensionVerifier for ProtectionVerifier {
    fn namespace(&self) -> &str {
        NAMESPACE
    }
    fn supports(&self, version: &str) -> bool {
        version == VERSION
    }
    fn prepare_save(
        &self,
        _: &Value,
        _: &mut Value,
        _: &mut BTreeMap<String, Vec<u8>>,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn prepare_streamed_package(
        &self,
        _: Option<&Value>,
        _: &mut Value,
        _: &BTreeMap<String, EntryDigest>,
    ) -> Result<(), Error> {
        Ok(())
    }
    fn verify(&self, context: &ExtensionContext<'_>, report: &mut Report) -> Result<(), Error> {
        if context.manifest["darkbox"]["version"] == "1.0.0" {
            return Err(Error::invalid(
                "protection.common_version",
                "Protection requires Darkbox 1.1.0 or a later explicitly supported version",
            ));
        }
        let data = data(context.manifest)?;
        report.protection = Some(ProtectionReport {
            extension_version: VERSION.into(),
            signature: "not_verified",
            inventory_verified: false,
            encrypted: Vec::new(),
        });
        let signature_entry = context.inventory.get(&data.signature.path).ok_or_else(|| {
            Error::invalid(
                "protection.signature_missing",
                "Detached signature is missing",
            )
        })?;
        if signature_entry.size != 64 {
            return Err(Error::invalid(
                "protection.signature_invalid",
                "Detached signature must contain exactly 64 bytes",
            ));
        }
        let signature = context.read(&data.signature.path)?;
        if let Some(key) = context
            .options
            .trusted_signers
            .get(&data.signature.signer_id)
        {
            let valid = VerifyingKey::from_bytes(key).ok().is_some_and(|key| {
                key.verify_strict(
                    context.manifest_bytes,
                    &Signature::from_slice(&signature).unwrap(),
                )
                .is_ok()
            });
            if valid {
                report.protection.as_mut().unwrap().signature = "verified";
                report.checks.push("protection.signature");
            } else {
                report.protection.as_mut().unwrap().signature = "invalid";
                report.record(Error::invalid(
                    "protection.signature_invalid",
                    "Manifest signature verification failed",
                ));
            }
        } else {
            report.protection.as_mut().unwrap().signature = "unknown_signer";
            report.record(Error::new(
                Status::Unsupported,
                "protection.signer_unknown",
                "Signer has no application-supplied trusted public key",
            ));
        }
        let expected: BTreeMap<_, _> = data
            .inventory
            .iter()
            .map(|entry| (entry.path.clone(), entry.clone()))
            .collect();
        let actual: BTreeMap<_, _> = context
            .inventory
            .iter()
            .filter(|(path, _)| {
                path.as_str() != "manifest.json" && path.as_str() != data.signature.path
            })
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect();
        if data
            .inventory
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
            || expected != actual
        {
            report.record(Error::invalid("protection.inventory", "Complete file inventory differs: missing, additional, duplicate, unsorted or changed entries"));
        } else {
            report.protection.as_mut().unwrap().inventory_verified = true;
            report.checks.push("protection.inventory");
        }
        let mut seen_files = BTreeSet::new();
        let mut seen_columns = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        for file in &data.files {
            crate::container::check_deadline(context.deadline)?;
            if !seen_files.insert(&file.path)
                || file.path == "manifest.json"
                || file.path == "README.md"
                || file.path.starts_with("docs/darkbox/")
                || file.path.starts_with("docs/sqlite/")
                || file.path == data.signature.path
                || context.manifest["application"]["profilePath"] == file.path
                || context.manifest["databases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|db| db["path"] == file.path)
            {
                return Err(Error::invalid(
                    "protection.file",
                    "Encrypted resource collides with public metadata or a database",
                ));
            }
            let bytes = context.read(&file.path)?;
            let block_context = BlockContext {
                package_id: data.package_id.clone(),
                key_id: file.key_id.clone(),
                location: BlockLocation::File {
                    path: file.path.clone(),
                },
            };
            check_block(&bytes, block_context, context, report, &mut nonces)?;
        }
        for column in &data.sqlite {
            if [&column.table, &column.column, &column.record_id_column]
                .iter()
                .any(|name| name.is_empty() || name.len() > 255 || name.contains('\0'))
            {
                return Err(Error::invalid(
                    "protection.sqlite_declaration",
                    "SQLite column and table names exceed their byte bounds",
                ));
            }
            if !seen_columns.insert((&column.database, &column.table, &column.column))
                || data.sqlite.iter().any(|other| {
                    other.database == column.database
                        && other.table == column.table
                        && other.column == column.record_id_column
                })
            {
                return Err(Error::invalid(
                    "protection.sqlite_declaration",
                    "Duplicate or overlapping protected columns",
                ));
            }
            let declared = context.manifest["databases"]
                .as_array()
                .unwrap()
                .iter()
                .any(|db| {
                    db["path"] == column.database
                        && db["tables"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|table| table["name"] == column.table)
                });
            if !declared {
                return Err(Error::invalid(
                    "protection.sqlite_declaration",
                    "Protected column does not reference a declared database table",
                ));
            }
            let path = context.staged.get(&column.database).ok_or_else(|| {
                Error::invalid(
                    "protection.sqlite_declaration",
                    "Protected database is missing",
                )
            })?;
            crate::sqlite::encrypted_values(
                path,
                column,
                context.limits,
                context.deadline,
                |id, block| {
                    let block_context = BlockContext {
                        package_id: data.package_id.clone(),
                        key_id: column.key_id.clone(),
                        location: BlockLocation::Sqlite {
                            database: column.database.clone(),
                            table: column.table.clone(),
                            column: column.column.clone(),
                            record_id: id.into(),
                        },
                    };
                    check_block(block, block_context, context, report, &mut nonces)
                },
            )?;
        }
        Ok(())
    }
}

fn check_block(
    bytes: &[u8],
    block_context: BlockContext,
    context: &ExtensionContext<'_>,
    report: &mut Report,
    nonces: &mut BTreeSet<(String, [u8; 12])>,
) -> Result<(), Error> {
    use sha2::{Digest, Sha256};
    if report.protection.as_ref().unwrap().encrypted.len() >= context.limits.max_entries {
        return Err(Error::limit(
            "Encrypted block count exceeds configured entry limit",
        ));
    }
    let mut authentication = "not_verified";
    let mut nonce_hex = None;
    match block_header(bytes) {
        Ok(header) => {
            block_context.aad(header)?;
            let nonce: [u8; 12] = header[8..20].try_into().unwrap();
            nonce_hex = Some(nonce.iter().map(|byte| format!("{byte:02x}")).collect());
            // With keys, aliases of the same actual key share the duplicate check.
            let key = context
                .options
                .decryption_keys
                .and_then(|keys| keys.key(&block_context.key_id));
            let key_identity = key
                .as_ref()
                .map(|key| format!("key:{:x}", Sha256::digest(key.as_slice())))
                .unwrap_or_else(|| format!("id:{}", block_context.key_id));
            if !nonces.insert((key_identity, nonce)) {
                report.record(Error::invalid(
                    "protection.nonce_reuse",
                    "Duplicate AES-GCM nonce for a key",
                ));
            }
            if let Some(key) = key {
                match decrypt_block(bytes, &key, &block_context) {
                    Ok(_) => authentication = "verified",
                    Err(error) => {
                        authentication = "failed";
                        report.record(error);
                    }
                }
            } else {
                authentication = "key_absent";
                report.note("protection.key_absent", "Encrypted content was not authenticated after decryption because its key is absent; this does not indicate corruption");
            }
        }
        Err(error) => report.record(error),
    }
    report
        .protection
        .as_mut()
        .unwrap()
        .encrypted
        .push(EncryptedContent {
            context: block_context,
            block_sha256: format!("{:x}", Sha256::digest(bytes)),
            nonce_hex,
            authentication,
            plaintext_validation: "not_performed",
        });
    Ok(())
}
