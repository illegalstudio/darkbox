use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Reader-owned resource limits. Hitting a limit never drops history or dependencies.
#[derive(Clone, Debug)]
pub struct SyncLimits {
    pub io: crate::Limits,
    pub max_history_bytes: u64,
    pub max_transactions: usize,
    pub max_scan_files: usize,
}
impl Default for SyncLimits {
    fn default() -> Self {
        Self {
            io: crate::Limits::default(),
            max_history_bytes: 64 * 1024 * 1024,
            max_transactions: 100_000,
            max_scan_files: 100_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisterCandidate {
    pub dot: Dot,
    pub lamport: Counter,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<SyncValue>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PositionCandidate {
    pub dot: Dot,
    pub lamport: Counter,
    pub present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<Dot>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegisterField {
    pub field: String,
    pub candidates: Vec<RegisterCandidate>,
}
impl RegisterField {
    pub fn selected(&self) -> Option<&RegisterCandidate> {
        self.candidates.iter().max_by_key(|c| (c.lamport, &c.dot))
    }
    pub fn conflicted(&self) -> bool {
        self.candidates.first().is_some_and(|first| {
            self.candidates
                .iter()
                .any(|c| (c.present, &c.value) != (first.present, &first.value))
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddTag {
    pub dot: Dot,
    pub value: SyncValue,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetField {
    pub field: String,
    pub adds: Vec<AddTag>,
    pub removed: BTreeSet<Dot>,
}
impl SetField {
    pub fn values(&self) -> Result<Vec<SyncValue>> {
        let mut values = BTreeMap::new();
        for add in &self.adds {
            if !self.removed.contains(&add.dot) {
                values.insert(canonical(&add.value)?, add.value.clone());
            }
        }
        Ok(values.into_values().collect())
    }
    pub fn observed_tags(&self, value: &SyncValue) -> Vec<Dot> {
        self.adds
            .iter()
            .filter(|a| &a.value == value && !self.removed.contains(&a.dot))
            .map(|a| a.dot.clone())
            .collect()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PositionField {
    pub field: String,
    pub candidates: Vec<PositionCandidate>,
}
impl PositionField {
    pub fn selected(&self) -> Option<&PositionCandidate> {
        self.candidates.iter().max_by_key(|c| (c.lamport, &c.dot))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordState {
    pub id: Dot,
    pub collection: String,
    pub deleted_by: BTreeSet<Dot>,
    pub registers: Vec<RegisterField>,
    pub sets: Vec<SetField>,
    pub positions: Vec<PositionField>,
}
impl RecordState {
    pub fn live(&self) -> bool {
        self.deleted_by.is_empty()
    }
    pub fn register(&self, field: &str) -> Option<&RegisterField> {
        self.registers.iter().find(|f| f.field == field)
    }
    pub fn set(&self, field: &str) -> Option<&SetField> {
        self.sets.iter().find(|f| f.field == field)
    }
    pub fn position(&self, field: &str) -> Option<&PositionField> {
        self.positions.iter().find(|f| f.field == field)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PositionNode {
    pub id: Dot,
    pub record: Dot,
    pub field: String,
    pub sequence: String,
    pub owner: Option<Dot>,
    pub after: Option<Dot>,
    pub lamport: Counter,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogicalState {
    pub kind: String,
    pub protocol_version: String,
    pub sync_id: String,
    pub root_sha256: String,
    pub frontier: Frontier,
    pub records: Vec<RecordState>,
    pub nodes: Vec<PositionNode>,
}
impl LogicalState {
    pub fn record(&self, id: &Dot) -> Option<&RecordState> {
        self.records.iter().find(|r| &r.id == id)
    }
    /// Nodes are retained when inactive; only the selected live occurrence is emitted.
    pub fn ordered_records(
        &self,
        field: &str,
        sequence: &str,
        owner: Option<&Dot>,
    ) -> Result<Vec<Dot>> {
        let mut children: BTreeMap<Option<&Dot>, Vec<&PositionNode>> = BTreeMap::new();
        let mut selected = BTreeMap::new();
        for record in self.records.iter().filter(|r| r.live()) {
            if let Some(node) = record
                .position(field)
                .and_then(|f| f.selected())
                .and_then(|c| c.node.as_ref())
            {
                selected.insert(node, &record.id);
            }
        }
        let mut count = 0;
        for node in self
            .nodes
            .iter()
            .filter(|n| n.field == field && n.sequence == sequence && n.owner.as_ref() == owner)
        {
            children.entry(node.after.as_ref()).or_default().push(node);
            count += 1;
        }
        for values in children.values_mut() {
            values.sort_by_key(|n| (n.lamport, &n.id));
        }
        let mut stack = children.get(&None).cloned().unwrap_or_default();
        let mut visited = BTreeSet::new();
        let mut result = Vec::new();
        while let Some(node) = stack.pop() {
            if !visited.insert(&node.id) {
                return Err(invalid("Position tree cycle"));
            }
            if let Some(record) = selected.get(&node.id) {
                result.push((*record).clone());
            }
            if let Some(values) = children.get(&Some(&node.id)) {
                stack.extend_from_slice(values);
            }
        }
        if visited.len() != count {
            return Err(invalid("Position tree has disconnected anchors"));
        }
        Ok(result)
    }
}

#[derive(Clone, Debug, Default)]
struct Core {
    records: BTreeMap<Dot, RecordState>,
    nodes: BTreeMap<Dot, PositionNode>,
    removals: BTreeMap<Dot, BTreeSet<Dot>>,
    baseline: BTreeSet<Dot>,
}
fn observes(tx: &SyncTransaction, index: usize, dot: &Dot) -> bool {
    (dot.replica_id == tx.replica_id && dot.sequence == tx.sequence && dot.index.0 < index as u64)
        || tx
            .dependencies
            .iter()
            .any(|d| d.replica_id == dot.replica_id && d.sequence >= dot.sequence)
}
impl Core {
    fn author_context(&self, tx: &SyncTransaction) -> Self {
        let known = |dot: &Dot| self.baseline.contains(dot) || observes(tx, 0, dot);
        let records = self
            .records
            .iter()
            .filter(|(id, _)| known(id))
            .map(|(id, row)| {
                let sets = row
                    .sets
                    .iter()
                    .map(|set| SetField {
                        field: set.field.clone(),
                        adds: set.adds.iter().filter(|a| known(&a.dot)).cloned().collect(),
                        removed: set
                            .removed
                            .iter()
                            .filter(|tag| {
                                self.removals
                                    .get(*tag)
                                    .is_some_and(|events| events.iter().any(&known))
                            })
                            .cloned()
                            .collect(),
                    })
                    .collect();
                (
                    id.clone(),
                    RecordState {
                        id: id.clone(),
                        collection: row.collection.clone(),
                        deleted_by: row
                            .deleted_by
                            .iter()
                            .filter(|d| known(d))
                            .cloned()
                            .collect(),
                        registers: Vec::new(),
                        sets,
                        positions: Vec::new(),
                    },
                )
            })
            .collect();
        Self {
            records,
            nodes: self
                .nodes
                .iter()
                .filter(|(id, _)| known(id))
                .map(|(id, node)| (id.clone(), node.clone()))
                .collect(),
            removals: BTreeMap::new(),
            baseline: self.baseline.clone(),
        }
    }
    fn record(&self, id: &Dot) -> Result<&RecordState> {
        self.records
            .get(id)
            .ok_or_else(|| invalid("Record create is not in author context"))
    }
    fn validate_value(&self, value: &SyncValue) -> Result<()> {
        value.visit(0, &mut |v| {
            if let SyncValue::Record { collection, id } = v
                && &self.record(id)?.collection != collection
            {
                return Err(invalid("Reference target collection differs"));
            }
            Ok(())
        })
    }
    fn validate_op(&self, domain: &Domain, op: &Operation) -> Result<()> {
        if let Operation::Create { collection } = op {
            domain.mapping().collection(collection)?;
            return Ok(());
        }
        let (id, field, kind) = match op {
            Operation::Create { .. } => unreachable!(),
            Operation::Assign {
                record,
                field,
                present,
                value,
            } => {
                if *present != value.is_some() {
                    return Err(invalid("Assignment presence/value differs"));
                }
                (record, Some(field), "register")
            }
            Operation::SetAdd { record, field, .. }
            | Operation::SetRemove { record, field, .. } => (record, Some(field), "set"),
            Operation::Place { record, field, .. } | Operation::Unplace { record, field } => {
                (record, Some(field), "position")
            }
            Operation::Delete { record } => (record, None, ""),
        };
        let record = self.record(id)?;
        if field.is_some() && !record.live() {
            return Err(invalid("Cannot edit a known deleted record"));
        }
        let mapping = field
            .map(|field| domain.mapping().field(&record.collection, field, kind))
            .transpose()?;
        if let Some(value) = op.value() {
            self.validate_value(value)?;
            if !mapping
                .unwrap()
                .value_types
                .iter()
                .any(|t| t == value.type_name())
            {
                return Err(invalid("Value type not accepted by profile"));
            }
        }
        match op {
            Operation::SetRemove {
                field, value, tags, ..
            } => {
                let expected = record
                    .set(field)
                    .map(|s| s.observed_tags(value))
                    .unwrap_or_default();
                if tags != &expected {
                    return Err(invalid(
                        "Remove tags differ from author-observed active adds",
                    ));
                }
            }
            Operation::Place {
                field,
                sequence,
                owner,
                after,
                ..
            } => {
                let mapping = mapping.unwrap();
                if !mapping.sequences.as_ref().unwrap().contains(sequence) {
                    return Err(invalid("Unknown sequence"));
                }
                if let Some(owner) = owner {
                    let target = self.record(owner)?;
                    if !target.live()
                        || !mapping
                            .owner_collections
                            .as_ref()
                            .unwrap()
                            .contains(&target.collection)
                    {
                        return Err(invalid("Invalid position owner"));
                    }
                } else if mapping.allow_root_owner != Some(true) {
                    return Err(invalid("Root sequence owner forbidden"));
                }
                if let Some(anchor) = after {
                    let node = self
                        .nodes
                        .get(anchor)
                        .ok_or_else(|| invalid("Anchor is not observed"))?;
                    if &node.sequence != sequence || &node.owner != owner || &node.field != field {
                        return Err(invalid("Anchor belongs to another sequence/field"));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn apply(&mut self, tx: &SyncTransaction, index: usize) -> Result<()> {
        let dot = tx.dot(index);
        match &tx.operations[index] {
            Operation::Create { collection } => {
                if self.records.contains_key(&dot) {
                    return Err(invalid("Duplicate create dot"));
                }
                self.records.insert(
                    dot.clone(),
                    RecordState {
                        id: dot,
                        collection: collection.clone(),
                        deleted_by: BTreeSet::new(),
                        registers: Vec::new(),
                        sets: Vec::new(),
                        positions: Vec::new(),
                    },
                );
            }
            Operation::Delete { record } => {
                self.records
                    .get_mut(record)
                    .ok_or_else(|| invalid("Missing record"))?
                    .deleted_by
                    .insert(dot);
            }
            Operation::Assign {
                record,
                field,
                present,
                value,
            } => {
                let row = self
                    .records
                    .get_mut(record)
                    .ok_or_else(|| invalid("Missing record"))?;
                if !row.registers.iter().any(|f| &f.field == field) {
                    row.registers.push(RegisterField {
                        field: field.clone(),
                        candidates: Vec::new(),
                    });
                    row.registers.sort_by(|a, b| a.field.cmp(&b.field));
                }
                let candidates = &mut row
                    .registers
                    .iter_mut()
                    .find(|f| &f.field == field)
                    .unwrap()
                    .candidates;
                candidates
                    .retain(|c| !(self.baseline.contains(&c.dot) || observes(tx, index, &c.dot)));
                candidates.push(RegisterCandidate {
                    dot,
                    lamport: tx.lamport,
                    present: *present,
                    value: value.clone(),
                });
                candidates.sort_by(|a, b| a.dot.cmp(&b.dot));
            }
            Operation::SetAdd {
                record,
                field,
                value,
            }
            | Operation::SetRemove {
                record,
                field,
                value,
                ..
            } => {
                let row = self
                    .records
                    .get_mut(record)
                    .ok_or_else(|| invalid("Missing record"))?;
                if !row.sets.iter().any(|f| &f.field == field) {
                    row.sets.push(SetField {
                        field: field.clone(),
                        adds: Vec::new(),
                        removed: BTreeSet::new(),
                    });
                    row.sets.sort_by(|a, b| a.field.cmp(&b.field));
                }
                let set = row.sets.iter_mut().find(|f| &f.field == field).unwrap();
                if let Operation::SetRemove { tags, .. } = &tx.operations[index] {
                    for tag in tags {
                        self.removals
                            .entry(tag.clone())
                            .or_default()
                            .insert(dot.clone());
                    }
                    set.removed.extend(tags.iter().cloned());
                } else {
                    set.adds.push(AddTag {
                        dot,
                        value: value.clone(),
                    });
                    set.adds.sort_by(|a, b| a.dot.cmp(&b.dot));
                }
            }
            Operation::Place { record, field, .. } | Operation::Unplace { record, field } => {
                let node = if let Operation::Place {
                    sequence,
                    owner,
                    after,
                    ..
                } = &tx.operations[index]
                {
                    self.nodes.insert(
                        dot.clone(),
                        PositionNode {
                            id: dot.clone(),
                            record: record.clone(),
                            field: field.clone(),
                            sequence: sequence.clone(),
                            owner: owner.clone(),
                            after: after.clone(),
                            lamport: tx.lamport,
                        },
                    );
                    Some(dot.clone())
                } else {
                    None
                };
                let row = self
                    .records
                    .get_mut(record)
                    .ok_or_else(|| invalid("Missing record"))?;
                if !row.positions.iter().any(|f| &f.field == field) {
                    row.positions.push(PositionField {
                        field: field.clone(),
                        candidates: Vec::new(),
                    });
                    row.positions.sort_by(|a, b| a.field.cmp(&b.field));
                }
                let candidates = &mut row
                    .positions
                    .iter_mut()
                    .find(|f| &f.field == field)
                    .unwrap()
                    .candidates;
                candidates
                    .retain(|c| !(self.baseline.contains(&c.dot) || observes(tx, index, &c.dot)));
                candidates.push(PositionCandidate {
                    dot,
                    lamport: tx.lamport,
                    present: node.is_some(),
                    node,
                });
                candidates.sort_by(|a, b| a.dot.cmp(&b.dot));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyStatus {
    Applied,
    Duplicate,
    Pending(Frontier),
}
#[derive(Clone, Debug)]
struct Entry {
    tx: SyncTransaction,
    hash: String,
    bytes: Vec<u8>,
}
/// Verified causal history. Pure replay assumes object availability was checked by the caller.
#[derive(Clone, Debug)]
pub struct History {
    domain: Domain,
    entries: BTreeMap<(String, Counter), Arc<Entry>>,
    core: Core,
    bytes: u64,
    limits: SyncLimits,
}
impl History {
    pub fn new(domain: Domain, limits: SyncLimits) -> Self {
        let core = domain
            .baseline()
            .map(|base| Core {
                records: base
                    .records
                    .iter()
                    .map(|row| (row.id.clone(), row.clone()))
                    .collect(),
                nodes: base
                    .nodes
                    .iter()
                    .map(|node| (node.id.clone(), node.clone()))
                    .collect(),
                removals: BTreeMap::new(),
                baseline: base.dots(),
            })
            .unwrap_or_default();
        Self {
            domain,
            entries: BTreeMap::new(),
            core,
            bytes: 0,
            limits,
        }
    }
    /// Start a new domain from current live state, retaining unresolved alternatives.
    pub fn compact(&self) -> Result<Self> {
        let base = Baseline::compact(&self.state())?;
        let domain = self.domain.with_baseline(base)?;
        Ok(Self::new(domain, self.limits.clone()))
    }
    pub fn domain(&self) -> &Domain {
        &self.domain
    }
    pub fn limits(&self) -> &SyncLimits {
        &self.limits
    }
    pub(crate) fn contains_transaction(&self, transaction: &SyncTransaction) -> bool {
        self.entries
            .get(&(transaction.replica_id.clone(), transaction.sequence))
            .is_some_and(|entry| entry.tx == *transaction)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn transactions(&self) -> impl Iterator<Item = &SyncTransaction> {
        self.entries.values().map(|e| &e.tx)
    }
    pub fn transaction_bytes(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.values().map(|e| e.bytes.as_slice())
    }
    pub fn blobs(&self) -> Result<BTreeSet<Blob>> {
        let mut blobs = self
            .domain
            .baseline()
            .map(Baseline::blobs)
            .transpose()?
            .unwrap_or_default();
        for tx in self.transactions() {
            blobs.extend(tx.blobs()?);
        }
        Ok(blobs)
    }
    pub fn frontier(&self) -> Frontier {
        let mut tips = BTreeMap::new();
        for e in self.entries.values() {
            tips.insert(
                e.tx.replica_id.clone(),
                Tip {
                    replica_id: e.tx.replica_id.clone(),
                    sequence: e.tx.sequence,
                    sha256: e.hash.clone(),
                },
            );
        }
        tips.into_values().collect()
    }
    pub fn state(&self) -> LogicalState {
        LogicalState {
            kind: "darkbox-sync-state".into(),
            protocol_version: VERSION.into(),
            sync_id: self.domain.root().sync_id.clone(),
            root_sha256: self.domain.root_hash().into(),
            frontier: self.frontier(),
            records: self.core.records.values().cloned().collect(),
            nodes: self.core.nodes.values().cloned().collect(),
        }
    }
    pub fn prepare(&self, replica_id: &str, operations: Vec<Operation>) -> Result<SyncTransaction> {
        if self
            .core
            .baseline
            .iter()
            .any(|dot| dot.replica_id == replica_id)
        {
            return Err(invalid(
                "New generation cannot reuse a baseline actor identity",
            ));
        }
        let dependencies = self.frontier();
        let own = dependencies.iter().find(|t| t.replica_id == replica_id);
        let sequence = own
            .map_or(Some(1), |t| t.sequence.0.checked_add(1))
            .ok_or_else(|| unsupported("Replica sequence exhausted"))?;
        let lamport = self
            .entries
            .values()
            .map(|e| e.tx.lamport.0)
            .max()
            .unwrap_or(0)
            .max(self.domain.baseline().map_or(0, Baseline::clock_floor))
            .checked_add(1)
            .ok_or_else(|| unsupported("Logical clock exhausted"))?;
        let tx = SyncTransaction {
            kind: "darkbox-sync-transaction".into(),
            protocol_version: VERSION.into(),
            sync_id: self.domain.root().sync_id.clone(),
            root_sha256: self.domain.root_hash().into(),
            replica_id: replica_id.into(),
            sequence: Counter(sequence),
            previous: own.map(|t| t.sha256.clone()),
            dependencies,
            lamport: Counter(lamport),
            operations,
        };
        tx.shape(&self.domain)?;
        if self.entries.len() >= self.limits.max_transactions
            || self
                .bytes
                .checked_add(tx.bytes()?.len() as u64 + 1)
                .is_none_or(|n| n > self.limits.max_history_bytes)
        {
            return Err(super::limit("Sync history budget"));
        }
        let mut author = self.core.author_context(&tx);
        for (index, operation) in tx.operations.iter().enumerate() {
            author.validate_op(&self.domain, operation)?;
            author.apply(&tx, index)?;
        }
        Ok(tx)
    }
    pub fn missing_dependencies(&self, tx: &SyncTransaction) -> Result<Frontier> {
        tx.shape(&self.domain)?;
        self.check_known_hashes(tx)?;
        Ok(tx
            .dependencies
            .iter()
            .filter(|tip| {
                !self
                    .entries
                    .contains_key(&(tip.replica_id.clone(), tip.sequence))
            })
            .cloned()
            .collect())
    }
    pub(crate) fn check_known_hashes(&self, tx: &SyncTransaction) -> Result<()> {
        if let Some(entry) = self.entries.get(&(tx.replica_id.clone(), tx.sequence))
            && entry.bytes != tx.bytes()?
        {
            return Err(fork("Different transaction bytes at one replica sequence"));
        }
        for tip in &tx.dependencies {
            if let Some(entry) = self.entries.get(&(tip.replica_id.clone(), tip.sequence))
                && entry.hash != tip.sha256
            {
                return Err(fork("Dependency hash conflicts with known history"));
            }
        }
        Ok(())
    }
    pub fn accept(&mut self, tx: SyncTransaction) -> Result<ApplyStatus> {
        tx.shape(&self.domain)?;
        if self
            .core
            .baseline
            .iter()
            .any(|dot| dot.replica_id == tx.replica_id)
        {
            return Err(invalid(
                "New generation cannot reuse a baseline actor identity",
            ));
        }
        let bytes = tx.bytes()?;
        let hash = sha256(&bytes);
        let key = (tx.replica_id.clone(), tx.sequence);
        if let Some(existing) = self.entries.get(&key) {
            return if existing.hash == hash && existing.bytes == bytes {
                Ok(ApplyStatus::Duplicate)
            } else {
                Err(fork("Different transaction bytes at one replica sequence"))
            };
        }
        if self.entries.len() >= self.limits.max_transactions
            || self
                .bytes
                .checked_add(bytes.len() as u64 + 1)
                .is_none_or(|b| b > self.limits.max_history_bytes)
        {
            return Err(super::limit("Sync history budget"));
        }
        let mut pending = Vec::new();
        let mut max_clock = self.domain.baseline().map_or(0, Baseline::clock_floor);
        for tip in &tx.dependencies {
            match self.entries.get(&(tip.replica_id.clone(), tip.sequence)) {
                None => pending.push(tip.clone()),
                Some(e) => {
                    if e.hash != tip.sha256 {
                        return Err(fork("Dependency hash conflicts with known chain"));
                    }
                    max_clock = max_clock.max(e.tx.lamport.0);
                    for ancestor in &e.tx.dependencies {
                        if !tx.dependencies.iter().any(|d| {
                            d.replica_id == ancestor.replica_id && d.sequence >= ancestor.sequence
                        }) {
                            return Err(invalid("Dependency frontier is not causally closed"));
                        }
                    }
                }
            }
        }
        if !pending.is_empty() {
            return Ok(ApplyStatus::Pending(pending));
        }
        if max_clock.checked_add(1) != Some(tx.lamport.0) {
            return Err(invalid("Logical clock differs from dependency tips"));
        }
        // Reconstruct precisely the author's context. Concurrent local deletions or
        // assignments must not change validation of an independently valid edit.
        let mut author = self.core.author_context(&tx);
        for (i, op) in tx.operations.iter().enumerate() {
            author.validate_op(&self.domain, op)?;
            author.apply(&tx, i)?;
        }
        let mut core = self.core.clone();
        for i in 0..tx.operations.len() {
            core.apply(&tx, i)?;
        }
        self.bytes += bytes.len() as u64 + 1;
        self.entries
            .insert(key, Arc::new(Entry { tx, hash, bytes }));
        self.core = core;
        Ok(ApplyStatus::Applied)
    }
    pub fn replay(
        domain: Domain,
        transactions: Vec<SyncTransaction>,
        limits: SyncLimits,
    ) -> Result<Self> {
        let end = crate::transfer::deadline(&limits.io)?;
        let mut result = Self::new(domain, limits);
        let mut pending = BTreeMap::new();
        let mut pending_bytes = 0u64;
        for tx in transactions {
            crate::container::check_deadline(end)?;
            tx.shape(&result.domain)?;
            let key = (tx.replica_id.clone(), tx.sequence);
            if let Some(old) = pending.get(&key) {
                if old != &tx {
                    return Err(fork("History contains a fork"));
                }
            } else {
                pending_bytes = pending_bytes
                    .checked_add(tx.bytes()?.len() as u64 + 1)
                    .ok_or_else(|| super::limit("History bytes"))?;
                if pending.len() >= result.limits.max_transactions
                    || pending_bytes > result.limits.max_history_bytes
                {
                    return Err(super::limit("Replay history budget"));
                }
                pending.insert(key, tx);
            }
        }
        while !pending.is_empty() {
            let before = pending.len();
            let keys: Vec<_> = pending.keys().cloned().collect();
            for key in keys {
                crate::container::check_deadline(end)?;
                if matches!(
                    result.accept(pending[&key].clone())?,
                    ApplyStatus::Applied | ApplyStatus::Duplicate
                ) {
                    pending.remove(&key);
                }
            }
            if pending.len() == before {
                return Err(invalid(
                    "History has missing dependencies or a causal cycle",
                ));
            }
        }
        Ok(result)
    }
}
