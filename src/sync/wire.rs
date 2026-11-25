use super::{
    Baseline, MAPPING_VERSION, MAX_BASELINE_BYTES, Result, SyncProtocol, invalid, unsupported,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Largest accepted canonical transaction, in bytes.
pub const MAX_TRANSACTION_BYTES: usize = 1_048_576;
/// Largest accepted segment, in bytes.
pub const MAX_SEGMENT_BYTES: usize = 4_194_304;
/// Largest accepted number of operations in a transaction.
pub const MAX_OPERATIONS: usize = 4096;
/// Largest accepted number of transactions in a segment.
pub const MAX_SEGMENT_TRANSACTIONS: usize = 256;

/// Protocol unsigned integers always serialize as exact canonical decimal strings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Counter(pub u64);
impl Serialize for Counter {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let number = text.parse::<u64>().map_err(serde::de::Error::custom)?;
        if text != number.to_string() {
            return Err(serde::de::Error::custom("Noncanonical unsigned integer"));
        }
        Ok(Self(number))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Identifies one operation: replica, transaction sequence and operation index.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct Dot {
    pub replica_id: String,
    pub sequence: Counter,
    pub index: Counter,
}
impl std::fmt::Display for Dot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.replica_id, self.sequence.0, self.index.0
        )
    }
}
impl Dot {
    /// Parse the `replica:sequence:index` form.
    pub fn parse(text: &str) -> Result<Self> {
        let parts: Vec<_> = text.split(':').collect();
        if parts.len() != 3 || !hex(parts[0], 32) {
            return Err(invalid("Invalid operation dot"));
        }
        let parse = |s: &str| -> Result<Counter> {
            let n = s
                .parse::<u64>()
                .map_err(|_| invalid("Invalid dot counter"))?;
            if s != n.to_string() {
                return Err(invalid("Noncanonical dot counter"));
            }
            Ok(Counter(n))
        };
        let dot = Self {
            replica_id: parts[0].into(),
            sequence: parse(parts[1])?,
            index: parse(parts[2])?,
        };
        if dot.sequence.0 == 0 || dot.index.0 >= MAX_OPERATIONS as u64 {
            return Err(invalid("Dot is outside protocol bounds"));
        }
        Ok(dot)
    }
}
impl Serialize for Dot {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for Dot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Random 128-bit identity from SQLite's process-seeded random generator.
/// This is an identity allocator, not a protection nonce allocator.
pub fn random_id() -> Result<String> {
    rusqlite::Connection::open_in_memory()
        .map_err(super::sql)?
        .query_row("SELECT lower(hex(randomblob(16)))", [], |row| row.get(0))
        .map_err(super::sql)
}

/// Lowercase hexadecimal SHA-256 of bytes.
pub fn sha256(bytes: &[u8]) -> String {
    crate::digest::hex(Sha256::digest(bytes))
}
pub(crate) fn hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn identifier(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphabetic()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn ordered<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|p| p[0] < p[1])
}
pub(crate) fn version(kind: &str, actual: &str, expected: &str) -> Result<()> {
    if kind != expected {
        return Err(invalid("Incorrect record kind"));
    }
    if SyncProtocol::parse(actual).is_none() {
        return Err(unsupported("Unsupported sync protocol version"));
    }
    Ok(())
}

/// RFC 8785 subset: all object keys are ASCII and all numeric values are strings.
/// Sorting is explicit even when a host enables serde_json/preserve_order.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    fn write(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<()> {
        if depth > 128 {
            return Err(super::limit("Sync JSON nesting"));
        }
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::String(s) => {
                out.extend(serde_json::to_vec(s).map_err(|_| invalid("JSON string"))?)
            }
            Value::Number(_) => return Err(invalid("Sync JSON numeric tokens are forbidden")),
            Value::Array(a) => {
                out.push(b'[');
                for (i, v) in a.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    write(v, out, depth + 1)?;
                }
                out.push(b']');
            }
            Value::Object(o) => {
                let mut keys: Vec<_> = o.keys().collect();
                keys.sort();
                out.push(b'{');
                for (i, k) in keys.into_iter().enumerate() {
                    if !k.is_ascii() {
                        return Err(invalid("Protocol keys must be ASCII"));
                    }
                    if i != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(k).map_err(|_| invalid("JSON key"))?);
                    out.push(b':');
                    write(&o[k], out, depth + 1)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }
    let value = serde_json::to_value(value).map_err(|e| invalid(e.to_string()))?;
    let mut bytes = Vec::new();
    write(&value, &mut bytes, 0)?;
    Ok(bytes)
}
/// Parse a record of at most `maximum` bytes, accepting only its exact canonical encoding.
pub fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], maximum: usize) -> Result<T> {
    if bytes.len() > maximum {
        return Err(super::limit("Sync JSON bytes"));
    }
    let value = crate::json::parse(bytes)?;
    if canonical(&value)? != bytes {
        return Err(invalid("Noncanonical sync JSON"));
    }
    let typed: T = serde_json::from_value(value).map_err(|e| invalid(e.to_string()))?;
    if canonical(&typed)? != bytes {
        return Err(invalid("Missing, null or aliased typed protocol member"));
    }
    Ok(typed)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// An immutable object identified by SHA-256 and size.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct Blob {
    pub sha256: String,
    pub size: Counter,
}
impl Blob {
    /// Check the hash syntax.
    pub fn validate(&self) -> Result<()> {
        if !hex(&self.sha256, 64) {
            return Err(invalid("Invalid blob hash"));
        }
        Ok(())
    }
    /// The content-addressed path of this object inside an exchange or store.
    pub fn relative_path(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "objects/{}/{}-{:016x}.blob",
            &self.sha256[..2],
            self.sha256,
            self.size.0
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
/// A typed value carried by an operation.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub enum SyncValue {
    Null,
    Bool {
        value: bool,
    },
    Text {
        value: String,
    },
    Integer {
        value: String,
    },
    Decimal {
        coefficient: String,
        exponent: String,
    },
    List {
        values: Vec<SyncValue>,
    },
    Map {
        entries: Vec<MapEntry>,
    },
    Record {
        collection: String,
        id: Dot,
    },
    Blob {
        sha256: String,
        size: Counter,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One entry of a map value.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct MapEntry {
    pub key: String,
    pub value: SyncValue,
}
impl SyncValue {
    /// A text value.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text {
            value: value.into(),
        }
    }
    /// The protocol name of this value's type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool { .. } => "bool",
            Self::Text { .. } => "text",
            Self::Integer { .. } => "integer",
            Self::Decimal { .. } => "decimal",
            Self::List { .. } => "list",
            Self::Map { .. } => "map",
            Self::Record { .. } => "record",
            Self::Blob { .. } => "blob",
        }
    }
    pub(crate) fn visit(
        &self,
        depth: usize,
        visit: &mut impl FnMut(&Self) -> Result<()>,
    ) -> Result<()> {
        if depth > 64 {
            return Err(invalid("Typed value nesting exceeds 64"));
        }
        visit(self)?;
        match self {
            Self::List { values } => {
                for v in values {
                    v.visit(depth + 1, visit)?;
                }
            }
            Self::Map { entries } => {
                if !entries
                    .windows(2)
                    .all(|p| p[0].key.as_bytes() < p[1].key.as_bytes())
                {
                    return Err(invalid("Map keys must be unique and UTF-8 sorted"));
                }
                for e in entries {
                    e.value.visit(depth + 1, visit)?;
                }
            }
            Self::Integer { value } => validate_integer(value)?,
            Self::Decimal {
                coefficient,
                exponent,
            } => {
                validate_integer(coefficient)?;
                validate_integer(exponent)?;
                let e = exponent
                    .parse::<i32>()
                    .map_err(|_| invalid("Decimal exponent"))?;
                if e.unsigned_abs() > 4096
                    || (coefficient == "0" && exponent != "0")
                    || (coefficient != "0" && coefficient.ends_with('0'))
                {
                    return Err(invalid("Noncanonical decimal"));
                }
            }
            Self::Blob { sha256, size } => Blob {
                sha256: sha256.clone(),
                size: *size,
            }
            .validate()?,
            _ => {}
        }
        Ok(())
    }
}
fn validate_integer(text: &str) -> Result<()> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty()
        || digits.len() > 4096
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || text == "-0"
    {
        return Err(invalid("Noncanonical exact integer"));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
/// One change to the replicated state.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub enum Operation {
    Create {
        collection: String,
    },
    Assign {
        record: Dot,
        field: String,
        present: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<SyncValue>,
    },
    SetAdd {
        record: Dot,
        field: String,
        value: SyncValue,
    },
    SetRemove {
        record: Dot,
        field: String,
        value: SyncValue,
        tags: Vec<Dot>,
    },
    Delete {
        record: Dot,
    },
    Place {
        record: Dot,
        field: String,
        sequence: String,
        owner: Option<Dot>,
        after: Option<Dot>,
    },
    Unplace {
        record: Dot,
        field: String,
    },
}
impl Operation {
    pub(crate) fn value(&self) -> Option<&SyncValue> {
        match self {
            Self::Assign { value, .. } => value.as_ref(),
            Self::SetAdd { value, .. } | Self::SetRemove { value, .. } => Some(value),
            _ => None,
        }
    }
    pub(crate) fn blobs(&self, blobs: &mut BTreeSet<Blob>) -> Result<()> {
        if let Some(value) = self.value() {
            value.visit(0, &mut |v| {
                if let SyncValue::Blob { sha256, size } = v {
                    blobs.insert(Blob {
                        sha256: sha256.clone(),
                        size: *size,
                    });
                }
                Ok(())
            })?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// The latest known transaction of one replica.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct Tip {
    pub replica_id: String,
    pub sequence: Counter,
    pub sha256: String,
}
/// One tip per replica, sorted by replica identifier.
pub type Frontier = Vec<Tip>;
pub(crate) fn validate_frontier(frontier: &Frontier) -> Result<()> {
    if !frontier
        .windows(2)
        .all(|p| p[0].replica_id < p[1].replica_id)
    {
        return Err(invalid("Frontier must be unique and sorted"));
    }
    for tip in frontier {
        if !hex(&tip.replica_id, 32) || !hex(&tip.sha256, 64) || tip.sequence.0 == 0 {
            return Err(invalid("Invalid frontier tip"));
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// An immutable, causally ordered batch of operations by one replica.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct SyncTransaction {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub replica_id: String,
    pub sequence: Counter,
    pub previous: Option<String>,
    pub dependencies: Frontier,
    pub lamport: Counter,
    pub operations: Vec<Operation>,
}
impl SyncTransaction {
    /// The identifier of the operation at this index.
    pub fn dot(&self, index: usize) -> Dot {
        Dot {
            replica_id: self.replica_id.clone(),
            sequence: self.sequence,
            index: Counter(index as u64),
        }
    }
    /// The exact canonical bytes.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = canonical(self)?;
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(super::limit("Sync transaction bytes"));
        }
        Ok(bytes)
    }
    /// The SHA-256 of the canonical bytes.
    pub fn hash(&self) -> Result<String> {
        Ok(sha256(&self.bytes()?))
    }
    /// Every object the operations reference.
    pub fn blobs(&self) -> Result<BTreeSet<Blob>> {
        let mut blobs = BTreeSet::new();
        for op in &self.operations {
            op.blobs(&mut blobs)?;
        }
        Ok(blobs)
    }
    pub(crate) fn shape(&self, domain: &Domain) -> Result<()> {
        domain.record(
            &self.kind,
            "darkbox-sync-transaction",
            &self.protocol_version,
            &self.sync_id,
            &self.root_sha256,
        )?;
        if !hex(&self.replica_id, 32)
            || self.sequence.0 == 0
            || self.lamport.0 == 0
            || self.operations.is_empty()
            || self.operations.len() > MAX_OPERATIONS
        {
            return Err(invalid("Invalid transaction bounds or identity"));
        }
        validate_frontier(&self.dependencies)?;
        let own = self
            .dependencies
            .iter()
            .find(|t| t.replica_id == self.replica_id);
        if self.sequence.0 == 1 {
            if self.previous.is_some() || own.is_some() {
                return Err(invalid("First transaction has predecessor"));
            }
        } else if !own.is_some_and(|t| {
            t.sequence.0 == self.sequence.0 - 1 && Some(&t.sha256) == self.previous.as_ref()
        }) {
            return Err(invalid("Incorrect predecessor dependency"));
        }
        self.bytes()?;
        self.blobs()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// The application profile and data-format version of a domain.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct Application {
    pub profile: String,
    pub format_version: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// A file bound by path, size and SHA-256.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct FileRef {
    pub path: String,
    pub size: Counter,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// The immutable root of a domain (`library.json`).
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct DomainRoot {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub package_id: String,
    pub common_version: String,
    pub application: Application,
    pub profile: FileRef,
    pub mapping: FileRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<FileRef>,
    pub encoding: String,
    pub merge: String,
    pub security: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// Where the mapped application state is stored.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct StorageMapping {
    pub mode: String,
    pub database_path: String,
    pub reserved_prefix: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// The projection a mapping requires.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct ProjectionMapping {
    pub id: String,
    pub version: String,
    pub conflict_policy: String,
    pub documentation_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// How one replicated field maps to database columns.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct FieldMapping {
    pub name: String,
    pub kind: String,
    pub columns: Vec<String>,
    pub codec: String,
    pub value_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_collections: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_root_owner: Option<bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// How one replicated collection maps to a table.
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct CollectionMapping {
    pub name: String,
    pub table: String,
    pub id_column: String,
    pub fields: Vec<FieldMapping>,
    pub local_columns: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
/// The immutable mapping between replicated collections and application tables (`mapping.json`).
#[allow(missing_docs)] // Members mirror the normative record one to one.
pub struct SyncMapping {
    pub kind: String,
    pub mapping_version: String,
    pub application: Application,
    pub storage: StorageMapping,
    pub collections: Vec<CollectionMapping>,
    pub projection: ProjectionMapping,
}
impl SyncMapping {
    /// Check the mapping's own consistency.
    pub fn validate(&self) -> Result<()> {
        if self.kind != "darkbox-sync-mapping" {
            return Err(invalid("Incorrect record kind"));
        }
        if self.mapping_version != MAPPING_VERSION {
            return Err(unsupported("Unsupported sync mapping version"));
        }
        if !matches!(
            self.storage.mode.as_str(),
            "single-database" | "journal-with-caches"
        ) || self.storage.reserved_prefix != "_darkbox_sync_"
            || self.projection.conflict_policy != "quarantine"
            || self.projection.documentation_path != "profile/profile.md"
            || self.projection.id.is_empty()
            || self.projection.version.is_empty()
            || self.application.profile.is_empty()
            || self.application.format_version.is_empty()
        {
            return Err(unsupported(
                "Unsupported sync storage or projection contract",
            ));
        }
        crate::paths::validate(&self.storage.database_path)?;
        if !self.collections.windows(2).all(|p| p[0].name < p[1].name) {
            return Err(invalid("Collection order"));
        }
        let mut tables = BTreeSet::new();
        for c in &self.collections {
            if !identifier(&c.name)
                || !tables.insert(c.table.to_ascii_lowercase())
                || !sql_name(&c.table)
                || !sql_name(&c.id_column)
                || !ordered(&c.local_columns)
                || !c.fields.windows(2).all(|p| p[0].name < p[1].name)
            {
                return Err(invalid("Collection mapping"));
            }
            let mut columns = BTreeSet::from([c.id_column.to_ascii_lowercase()]);
            for column in &c.local_columns {
                if !sql_name(column) || !columns.insert(column.to_ascii_lowercase()) {
                    return Err(invalid("Local column mapping"));
                }
            }
            for field in &c.fields {
                if !identifier(&field.name)
                    || !identifier(&field.codec)
                    || field.columns.is_empty()
                    || !ordered(&field.columns)
                    || !ordered(&field.value_types)
                {
                    return Err(invalid("Field mapping"));
                }
                for column in &field.columns {
                    if !sql_name(column) || !columns.insert(column.to_ascii_lowercase()) {
                        return Err(invalid("Repeated storage column"));
                    }
                }
                if field.kind == "position" {
                    let seq = field
                        .sequences
                        .as_ref()
                        .ok_or_else(|| invalid("Missing position sequences"))?;
                    let owners = field
                        .owner_collections
                        .as_ref()
                        .ok_or_else(|| invalid("Missing position owners"))?;
                    if seq.is_empty()
                        || !ordered(seq)
                        || seq.iter().any(|s| !identifier(s))
                        || !ordered(owners)
                        || owners
                            .iter()
                            .any(|s| !self.collections.iter().any(|c| &c.name == s))
                        || field.allow_root_owner.is_none()
                        || !field.value_types.is_empty()
                    {
                        return Err(invalid("Position mapping"));
                    }
                } else if !matches!(field.kind.as_str(), "register" | "set")
                    || field.sequences.is_some()
                    || field.owner_collections.is_some()
                    || field.allow_root_owner.is_some()
                    || field.value_types.is_empty()
                    || field.value_types.iter().any(|s| {
                        !matches!(
                            s.as_str(),
                            "null"
                                | "bool"
                                | "text"
                                | "integer"
                                | "decimal"
                                | "list"
                                | "map"
                                | "record"
                                | "blob"
                        )
                    })
                {
                    return Err(invalid("Field kind or accepted types"));
                }
            }
        }
        Ok(())
    }
    /// The collection with this name.
    pub fn collection(&self, name: &str) -> Result<&CollectionMapping> {
        self.collections
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| invalid("Unknown collection"))
    }
    /// The field with this name and kind in a collection.
    pub fn field(&self, collection: &str, field: &str, kind: &str) -> Result<&FieldMapping> {
        self.collection(collection)?
            .fields
            .iter()
            .find(|f| f.name == field && f.kind == kind)
            .ok_or_else(|| invalid("Unknown field or kind"))
    }
}
fn sql_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && !s.contains('\0')
}

/// Validated, immutable root, mapping and offline profile bytes.
#[derive(Clone, Debug)]
pub struct Domain {
    root: DomainRoot,
    mapping: SyncMapping,
    profile: Vec<u8>,
    hash: String,
    baseline: Option<Baseline>,
}
impl Domain {
    /// Create a domain with random identities. The protocol is permanent for
    /// the domain: `SyncProtocol::V1_0` requires common 1.5.0 packages and
    /// `SyncProtocol::V1_1` requires common 1.6.0 or later.
    pub fn generate(
        protocol: SyncProtocol,
        mapping: SyncMapping,
        profile: Vec<u8>,
    ) -> Result<Self> {
        Self::new(protocol, random_id()?, random_id()?, mapping, profile)
    }

    /// Create a domain with explicit identities, for example to keep an existing `packageId`.
    pub fn new(
        protocol: SyncProtocol,
        sync_id: String,
        package_id: String,
        mapping: SyncMapping,
        profile: Vec<u8>,
    ) -> Result<Self> {
        let mapping_bytes = canonical(&mapping)?;
        let root = DomainRoot {
            kind: "darkbox-sync-domain".into(),
            protocol_version: protocol.version().into(),
            sync_id,
            package_id,
            common_version: protocol.minimum_common().into(),
            application: mapping.application.clone(),
            profile: FileRef {
                path: "profile/profile.md".into(),
                size: Counter(profile.len() as u64),
                sha256: sha256(&profile),
            },
            mapping: FileRef {
                path: "profile/mapping.json".into(),
                size: Counter(mapping_bytes.len() as u64),
                sha256: sha256(&mapping_bytes),
            },
            baseline: None,
            encoding: "jcs-strings-v1".into(),
            merge: "causal-records-v1".into(),
            security: "trusted-folder-plaintext".into(),
        };
        Self::from_parts(&canonical(&root)?, &mapping_bytes, &profile)
    }
    /// Rebuild a domain from its exact root, mapping and profile bytes.
    pub fn from_parts(root_bytes: &[u8], mapping_bytes: &[u8], profile: &[u8]) -> Result<Self> {
        Self::from_parts_with_baseline(root_bytes, mapping_bytes, profile, None)
    }
    /// Rebuild a domain whose root pins a compact baseline.
    pub fn from_parts_with_baseline(
        root_bytes: &[u8],
        mapping_bytes: &[u8],
        profile: &[u8],
        baseline: Option<&[u8]>,
    ) -> Result<Self> {
        let root: DomainRoot = decode(root_bytes, MAX_SEGMENT_BYTES)?;
        version(&root.kind, &root.protocol_version, "darkbox-sync-domain")?;
        let protocol = SyncProtocol::parse(&root.protocol_version)
            .ok_or_else(|| unsupported("Unsupported sync protocol version"))?;
        let floor = crate::versions::numbers(&root.common_version)
            .filter(|(major, minor, patch)| {
                format!("{major}.{minor}.{patch}") == root.common_version
            })
            .ok_or_else(|| invalid("Sync domain common version"))?;
        let admitted = match protocol {
            SyncProtocol::V1_0 => root.common_version == protocol.minimum_common(),
            SyncProtocol::V1_1 => floor.0 == 1 && floor >= (1, 6, 0),
        };
        if !admitted {
            return Err(invalid(
                "Sync domain common version is outside its protocol version",
            ));
        }
        if SyncProtocol::for_common(&root.common_version) != Some(protocol) {
            return Err(unsupported(
                "Sync domain requires a common version this build does not support",
            ));
        }
        if root.encoding != "jcs-strings-v1"
            || root.merge
                != if root.baseline.is_some() {
                    "causal-records-seed-v1"
                } else {
                    "causal-records-v1"
                }
            || root.security != "trusted-folder-plaintext"
        {
            return Err(unsupported("Unsupported sync domain capability"));
        }
        if !hex(&root.sync_id, 32)
            || !hex(&root.package_id, 32)
            || root.profile.path != "profile/profile.md"
            || root.mapping.path != "profile/mapping.json"
            || root.profile.size.0 != profile.len() as u64
            || root.profile.sha256 != sha256(profile)
            || root.mapping.size.0 != mapping_bytes.len() as u64
            || root.mapping.sha256 != sha256(mapping_bytes)
            || profile.is_empty()
            || profile.len() > MAX_SEGMENT_BYTES
            || profile.starts_with(&[0xef, 0xbb, 0xbf])
            || std::str::from_utf8(profile).is_err()
        {
            return Err(invalid("Domain identity, profile or mapping bytes differ"));
        }
        let mapping: SyncMapping = decode(mapping_bytes, MAX_SEGMENT_BYTES)?;
        mapping.validate()?;
        if root.application != mapping.application {
            return Err(invalid("Profile identity differs"));
        }
        let baseline = match (&root.baseline, baseline) {
            (None, None) => None,
            (Some(reference), Some(bytes))
                if reference.path == "profile/base.json"
                    && reference.size.0 == bytes.len() as u64
                    && reference.sha256 == sha256(bytes) =>
            {
                let base: Baseline = decode(bytes, MAX_BASELINE_BYTES)?;
                base.validate(&mapping)?;
                Some(base)
            }
            _ => return Err(invalid("Pinned compact baseline is missing or mismatched")),
        };
        Ok(Self {
            root,
            mapping,
            profile: profile.to_vec(),
            hash: sha256(root_bytes),
            baseline,
        })
    }
    /// The compact baseline this domain starts from, if any.
    pub fn baseline(&self) -> Option<&Baseline> {
        self.baseline.as_ref()
    }
    pub(crate) fn with_baseline(&self, base: Baseline) -> Result<Self> {
        let bytes = canonical(&base)?;
        let mut root = self.root.clone();
        root.sync_id = random_id()?;
        root.baseline = Some(FileRef {
            path: "profile/base.json".into(),
            size: Counter(bytes.len() as u64),
            sha256: sha256(&bytes),
        });
        root.merge = "causal-records-seed-v1".into();
        Self::from_parts_with_baseline(
            &canonical(&root)?,
            &canonical(&self.mapping)?,
            &self.profile,
            Some(&bytes),
        )
    }
    /// The immutable root record.
    pub fn root(&self) -> &DomainRoot {
        &self.root
    }
    /// The mapping.
    pub fn mapping(&self) -> &SyncMapping {
        &self.mapping
    }
    /// The exact bytes of the application profile document.
    pub fn profile(&self) -> &[u8] {
        &self.profile
    }
    /// The SHA-256 of the canonical root, which every other record carries.
    pub fn root_hash(&self) -> &str {
        &self.hash
    }
    /// The permanent protocol of this domain.
    pub fn protocol(&self) -> SyncProtocol {
        SyncProtocol::parse(&self.root.protocol_version).expect("validated at construction")
    }
    /// Check one record's kind, its protocol version against this domain's
    /// and its domain binding.
    pub(crate) fn record(
        &self,
        kind: &str,
        expected: &str,
        protocol_version: &str,
        sync_id: &str,
        root_hash: &str,
    ) -> Result<()> {
        version(kind, protocol_version, expected)?;
        if protocol_version != self.root.protocol_version {
            return Err(invalid("Record protocol version differs from its domain"));
        }
        self.bind(sync_id, root_hash)
    }
    /// Fail unless a record's `syncId` and `rootSha256` name this domain.
    pub fn bind(&self, sync_id: &str, root_hash: &str) -> Result<()> {
        if sync_id != self.root.sync_id || root_hash != self.hash {
            return Err(invalid("Wrong sync domain or root"));
        }
        Ok(())
    }
    /// Fail unless a manifest can carry this domain: same package, profile and a common version the protocol admits.
    pub fn check_manifest(&self, manifest: &Value) -> Result<()> {
        if manifest["extensions"]
            .get(crate::protection::NAMESPACE)
            .is_some()
        {
            return Err(unsupported("Sync v1 refuses protected libraries"));
        }
        let declared = &manifest["extensions"][super::NAMESPACE]["version"];
        if !declared.is_null() && *declared != self.root.protocol_version {
            return Err(invalid(
                "Sync extension version differs from the domain protocol",
            ));
        }
        if !self.protocol().admits(
            &self.root.common_version,
            manifest["darkbox"]["version"].as_str().unwrap_or_default(),
        ) || manifest["packageId"] != self.root.package_id
            || manifest["application"]["id"] != self.root.application.profile
            || manifest["application"]["formatVersion"] != self.root.application.format_version
        {
            return Err(invalid("Manifest differs from sync domain"));
        }
        Ok(())
    }
}

pub(crate) fn require_working_writer(manifest: &Value) -> Result<()> {
    if manifest["extensions"]
        .as_object()
        .into_iter()
        .flatten()
        .any(|(namespace, descriptor)| {
            namespace != super::NAMESPACE && descriptor["required"] == true
        })
    {
        return Err(unsupported(
            "Working sync mutation requires writer support for every required extension; additional required namespaces are not supported by this adapter",
        ));
    }
    Ok(())
}
