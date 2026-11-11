use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_BASELINE_BYTES: usize = 64 * 1024 * 1024;

/// A root-bound generation seed. Historical transactions are deliberately excluded.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Baseline {
    pub kind: String,
    pub protocol_version: String,
    pub source_root_sha256: String,
    pub source_frontier: Frontier,
    pub records: Vec<RecordState>,
    pub nodes: Vec<PositionNode>,
}
impl Baseline {
    pub(crate) fn compact(state: &LogicalState) -> Result<Self> {
        let node_index: BTreeMap<_, _> = state.nodes.iter().map(|node| (&node.id, node)).collect();
        let mut needed = BTreeSet::new();
        let mut records = Vec::new();
        for record in state.records.iter().filter(|record| record.live()) {
            let mut record = record.clone();
            for set in &mut record.sets {
                let mut values = BTreeMap::new();
                for add in &set.adds {
                    if !set.removed.contains(&add.dot) {
                        values
                            .entry(canonical(&add.value)?)
                            .or_insert_with(|| add.clone());
                    }
                }
                set.adds = values.into_values().collect();
                set.adds.sort_by(|a, b| a.dot.cmp(&b.dot));
                set.removed.clear();
            }
            visit_values(&record, &mut |value| {
                if let SyncValue::Record { id, .. } = value {
                    needed.insert(id.clone());
                }
                Ok(())
            })?;
            for field in &record.positions {
                for candidate in &field.candidates {
                    if let Some(node) = &candidate.node {
                        let node = node_index
                            .get(node)
                            .copied()
                            .ok_or_else(|| invalid("Compaction position node is absent"))?;
                        needed.extend(node.owner.iter().cloned());
                    }
                }
            }
            records.push(record);
        }
        for record in state
            .records
            .iter()
            .filter(|record| !record.live() && needed.contains(&record.id))
        {
            records.push(RecordState {
                id: record.id.clone(),
                collection: record.collection.clone(),
                deleted_by: record.deleted_by.iter().take(1).cloned().collect(),
                registers: Vec::new(),
                sets: Vec::new(),
                positions: Vec::new(),
            });
        }
        records.sort_by(|a, b| a.id.cmp(&b.id));
        let retained: BTreeSet<_> = records
            .iter()
            .flat_map(|r| &r.positions)
            .flat_map(|f| &f.candidates)
            .filter_map(|c| c.node.clone())
            .collect();
        let mut groups = BTreeMap::new();
        for node in &state.nodes {
            groups
                .entry((
                    node.field.clone(),
                    node.sequence.clone(),
                    node.owner.clone(),
                ))
                .or_insert_with(BTreeMap::new)
                .entry(node.after.clone())
                .or_insert_with(Vec::new)
                .push(node);
        }
        let mut nodes = Vec::new();
        for children in groups.values_mut() {
            for siblings in children.values_mut() {
                siblings.sort_by_key(|node| (node.lamport, &node.id));
            }
            let mut stack = children.get(&None).cloned().unwrap_or_default();
            let mut visited = BTreeSet::new();
            let mut previous = None;
            while let Some(node) = stack.pop() {
                if !visited.insert(&node.id) {
                    return Err(invalid("Compaction position cycle"));
                }
                if retained.contains(&node.id) {
                    let mut compact = node.clone();
                    compact.after = previous.clone();
                    previous = Some(compact.id.clone());
                    nodes.push(compact);
                }
                if let Some(next) = children.get(&Some(node.id.clone())) {
                    stack.extend_from_slice(next);
                }
            }
            if visited.len() != children.values().map(Vec::len).sum::<usize>() {
                return Err(invalid("Compaction position anchors are disconnected"));
            }
        }
        nodes.sort_by(|a, b| a.id.cmp(&b.id));
        let priorities: BTreeSet<_> = records
            .iter()
            .flat_map(|record| {
                record
                    .registers
                    .iter()
                    .flat_map(|field| {
                        field
                            .candidates
                            .iter()
                            .map(|candidate| (candidate.lamport, candidate.dot.clone()))
                    })
                    .chain(record.positions.iter().flat_map(|field| {
                        field
                            .candidates
                            .iter()
                            .map(|candidate| (candidate.lamport, candidate.dot.clone()))
                    }))
            })
            .collect();
        let ranks: BTreeMap<_, _> = priorities
            .into_iter()
            .enumerate()
            .map(|(rank, key)| (key, Counter(rank as u64 + 1)))
            .collect();
        for record in &mut records {
            for candidate in record
                .registers
                .iter_mut()
                .flat_map(|field| &mut field.candidates)
            {
                candidate.lamport = ranks[&(candidate.lamport, candidate.dot.clone())];
            }
            for candidate in record
                .positions
                .iter_mut()
                .flat_map(|field| &mut field.candidates)
            {
                candidate.lamport = ranks[&(candidate.lamport, candidate.dot.clone())];
            }
        }
        for node in &mut nodes {
            node.lamport = ranks[&(node.lamport, node.id.clone())];
        }

        Ok(Self {
            kind: "darkbox-sync-baseline".into(),
            protocol_version: VERSION.into(),
            source_root_sha256: state.root_sha256.clone(),
            source_frontier: state.frontier.clone(),
            records,
            nodes,
        })
    }
    pub(crate) fn validate(&self, mapping: &SyncMapping) -> Result<()> {
        super::wire::version(&self.kind, &self.protocol_version, "darkbox-sync-baseline")?;
        if !hex(&self.source_root_sha256, 64) {
            return Err(invalid("Baseline source root"));
        }
        super::wire::validate_frontier(&self.source_frontier)?;
        if canonical(self)?.len() > MAX_BASELINE_BYTES {
            return Err(super::limit("Compact baseline bytes"));
        }
        sorted(&self.records, |r| &r.id)?;
        sorted(&self.nodes, |n| &n.id)?;
        let records: BTreeMap<_, _> = self.records.iter().map(|r| (&r.id, r)).collect();
        let nodes: BTreeMap<_, _> = self.nodes.iter().map(|n| (&n.id, n)).collect();
        let mut events = BTreeSet::new();
        for record in &self.records {
            mapping.collection(&record.collection)?;
            claim(&mut events, &record.id)?;
            for dot in &record.deleted_by {
                claim(&mut events, dot)?;
            }
            sorted(&record.registers, |f| &f.field)?;
            sorted(&record.sets, |f| &f.field)?;
            sorted(&record.positions, |f| &f.field)?;
            for field in &record.registers {
                let declaration = mapping.field(&record.collection, &field.field, "register")?;
                if field.candidates.is_empty() {
                    return Err(invalid("Empty baseline register"));
                }
                sorted(&field.candidates, |c| &c.dot)?;
                for candidate in &field.candidates {
                    claim(&mut events, &candidate.dot)?;
                    if candidate.lamport.0 == 0 || candidate.present != candidate.value.is_some() {
                        return Err(invalid("Baseline register candidate"));
                    }
                    if let Some(value) = &candidate.value {
                        check_type(value, declaration)?;
                    }
                }
            }
            for field in &record.sets {
                let declaration = mapping.field(&record.collection, &field.field, "set")?;
                sorted(&field.adds, |a| &a.dot)?;
                if !field.removed.is_empty() {
                    return Err(invalid("Baseline has removed set tags"));
                }
                let mut values = BTreeSet::new();
                for add in &field.adds {
                    claim(&mut events, &add.dot)?;
                    check_type(&add.value, declaration)?;
                    if !values.insert(canonical(&add.value)?) {
                        return Err(invalid("Duplicate baseline set value"));
                    }
                }
            }
            for field in &record.positions {
                let declaration = mapping.field(&record.collection, &field.field, "position")?;
                if field.candidates.is_empty() {
                    return Err(invalid("Empty baseline placement"));
                }
                sorted(&field.candidates, |c| &c.dot)?;
                for candidate in &field.candidates {
                    claim(&mut events, &candidate.dot)?;
                    if candidate.lamport.0 == 0 || candidate.present != candidate.node.is_some() {
                        return Err(invalid("Baseline position candidate"));
                    }
                    if let Some(id) = &candidate.node {
                        let node = nodes
                            .get(id)
                            .ok_or_else(|| invalid("Baseline position node missing"))?;
                        if node.id != candidate.dot
                            || node.record != record.id
                            || node.field != field.field
                            || node.lamport != candidate.lamport
                            || !declaration
                                .sequences
                                .as_ref()
                                .unwrap()
                                .contains(&node.sequence)
                        {
                            return Err(invalid("Baseline position node binding"));
                        }
                        match &node.owner {
                            Some(owner) => {
                                let owner = records
                                    .get(owner)
                                    .ok_or_else(|| invalid("Missing baseline owner"))?;
                                if !declaration
                                    .owner_collections
                                    .as_ref()
                                    .unwrap()
                                    .contains(&owner.collection)
                                {
                                    return Err(invalid("Baseline owner collection"));
                                }
                            }
                            None if declaration.allow_root_owner != Some(true) => {
                                return Err(invalid("Baseline root owner forbidden"));
                            }
                            None => {}
                        }
                    }
                }
            }
            visit_values(record, &mut |value| {
                if let SyncValue::Record { id, collection } = value
                    && records.get(id).is_none_or(|r| &r.collection != collection)
                {
                    return Err(invalid("Baseline reference target differs"));
                }
                Ok(())
            })?;
        }
        let state = LogicalState {
            kind: "darkbox-sync-state".into(),
            protocol_version: VERSION.into(),
            sync_id: "0".repeat(32),
            root_sha256: self.source_root_sha256.clone(),
            frontier: self.source_frontier.clone(),
            records: self.records.clone(),
            nodes: self.nodes.clone(),
        };
        if Self::compact(&state)? != *self {
            return Err(invalid("Baseline is not minimally normalized"));
        }
        Ok(())
    }
    pub(crate) fn clock_floor(&self) -> u64 {
        self.records
            .iter()
            .flat_map(|record| {
                record
                    .registers
                    .iter()
                    .flat_map(|field| field.candidates.iter().map(|candidate| candidate.lamport.0))
                    .chain(record.positions.iter().flat_map(|field| {
                        field.candidates.iter().map(|candidate| candidate.lamport.0)
                    }))
            })
            .max()
            .unwrap_or(0)
    }
    pub(crate) fn dots(&self) -> BTreeSet<Dot> {
        let mut dots = BTreeSet::new();
        for r in &self.records {
            dots.insert(r.id.clone());
            dots.extend(r.deleted_by.iter().cloned());
            dots.extend(
                r.registers
                    .iter()
                    .flat_map(|f| &f.candidates)
                    .map(|c| c.dot.clone()),
            );
            dots.extend(r.sets.iter().flat_map(|f| &f.adds).map(|a| a.dot.clone()));
            dots.extend(
                r.positions
                    .iter()
                    .flat_map(|f| &f.candidates)
                    .map(|c| c.dot.clone()),
            );
        }
        dots
    }
    pub(crate) fn blobs(&self) -> Result<BTreeSet<Blob>> {
        let mut blobs = BTreeSet::new();
        for record in &self.records {
            visit_values(record, &mut |value| {
                if let SyncValue::Blob { sha256, size } = value {
                    blobs.insert(Blob {
                        sha256: sha256.clone(),
                        size: *size,
                    });
                }
                Ok(())
            })?;
        }
        Ok(blobs)
    }
}
fn visit_values(
    record: &RecordState,
    visit: &mut impl FnMut(&SyncValue) -> Result<()>,
) -> Result<()> {
    for value in record
        .registers
        .iter()
        .flat_map(|f| &f.candidates)
        .filter_map(|c| c.value.as_ref())
        .chain(record.sets.iter().flat_map(|f| &f.adds).map(|a| &a.value))
    {
        value.visit(0, visit)?;
    }
    Ok(())
}
fn sorted<T, K: Ord + ?Sized>(values: &[T], key: impl Fn(&T) -> &K) -> Result<()> {
    if !values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])) {
        return Err(invalid("Baseline entries must be sorted and unique"));
    }
    Ok(())
}
fn claim(events: &mut BTreeSet<Dot>, dot: &Dot) -> Result<()> {
    Dot::parse(&dot.to_string())?;
    if !events.insert(dot.clone()) {
        return Err(invalid("Baseline operation identity reused"));
    }
    Ok(())
}
fn check_type(value: &SyncValue, field: &FieldMapping) -> Result<()> {
    if !field
        .value_types
        .iter()
        .any(|kind| kind == value.type_name())
    {
        return Err(invalid("Baseline value type is not mapped"));
    }
    value.visit(0, &mut |_| Ok(()))
}
