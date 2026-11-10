//! Fictional application adapter shared by the runnable SDK example and integration tests.
use darkbox::{Error, sync::*};
use rusqlite::{Connection, Transaction, params};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, sync::OnceLock};

type Row = (
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);
fn failure(error: impl std::fmt::Display) -> Error {
    Error::invalid("example.sync", error.to_string())
}
fn encoded(value: &impl Serialize) -> Result<String, Error> {
    String::from_utf8(canonical(value)?).map_err(failure)
}
fn reference() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!(
            "../../archive/1.5.0/docs/darkbox/sync/1.0.0.vectors.json"
        ))
        .expect("Included example profile")
    })
}
pub fn mapping() -> SyncMapping {
    serde_json::from_value(reference()["mapping"].clone()).expect("Included mapping")
}
pub fn profile() -> Vec<u8> {
    reference()["profile"]
        .as_str()
        .expect("Included profile")
        .as_bytes()
        .to_vec()
}
fn rows(state: &LogicalState) -> Result<BTreeMap<String, Row>, Error> {
    state
        .records
        .iter()
        .filter(|r| r.live())
        .map(|record| {
            let register = |field: &str| {
                record
                    .register(field)
                    .and_then(|f| f.selected())
                    .and_then(|c| c.value.as_ref())
                    .map(encoded)
                    .transpose()
            };
            let position = record.position("position").map(encoded).transpose()?;
            let tags = encoded(
                &record
                    .set("tags")
                    .map(|f| f.values())
                    .transpose()?
                    .unwrap_or_default(),
            )?;
            Ok((
                record.id.to_string(),
                (
                    register("asset")?,
                    register("data")?,
                    position,
                    tags,
                    register("title")?,
                ),
            ))
        })
        .collect()
}
/// An application supplies its own deterministic projection and conflict presentation.
pub struct Notes;
impl SyncProjection for Notes {
    fn id(&self) -> &str {
        "org.example.sync-notes.projection"
    }
    fn version(&self) -> &str {
        "1"
    }
    fn initialize(&self, transaction: &Transaction<'_>, _: &Domain) -> Result<(), Error> {
        transaction.execute_batch("CREATE TABLE items(id TEXT PRIMARY KEY,asset TEXT,data TEXT,position TEXT,tags TEXT,title TEXT,local_note TEXT);CREATE TABLE item_conflicts(id TEXT PRIMARY KEY,payload BLOB NOT NULL);").map_err(failure)
    }
    fn validate_mapping(&self, domain: &Domain, connection: &Connection) -> Result<(), Error> {
        if domain.mapping() != &mapping() {
            return Err(failure("Unsupported example mapping"));
        }
        connection
            .prepare("SELECT id,asset,data,position,tags,title,local_note FROM items")
            .map_err(failure)?;
        Ok(())
    }
    fn project(
        &self,
        transaction: &Transaction<'_>,
        _: &Domain,
        _: &LogicalState,
        next: &LogicalState,
    ) -> Result<(), Error> {
        let local: BTreeMap<String, Option<String>> = {
            let mut q = transaction
                .prepare("SELECT id,local_note FROM items")
                .map_err(failure)?;
            q.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(failure)?
                .collect::<rusqlite::Result<_>>()
                .map_err(failure)?
        };
        transaction
            .execute_batch("DELETE FROM items;DELETE FROM item_conflicts;")
            .map_err(failure)?;
        for (id, (asset, data, position, tags, title)) in rows(next)? {
            transaction.execute("INSERT INTO items(id,asset,data,position,tags,title,local_note)VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,asset,data,position,tags,title,local.get(&id).cloned().flatten()]).map_err(failure)?;
        }
        for record in &next.records {
            transaction
                .execute(
                    "INSERT INTO item_conflicts(id,payload)VALUES(?1,?2)",
                    params![record.id.to_string(), canonical(record)?],
                )
                .map_err(failure)?;
        }
        Ok(())
    }
    fn verify(
        &self,
        connection: &Connection,
        _: &Domain,
        state: &LogicalState,
    ) -> Result<(), Error> {
        let actual = {
            let mut q = connection
                .prepare("SELECT id,asset,data,position,tags,title FROM items")
                .map_err(failure)?;
            q.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ),
                ))
            })
            .map_err(failure)?
            .collect::<rusqlite::Result<BTreeMap<_, _>>>()
            .map_err(failure)?
        };
        if actual != rows(state)? {
            return Err(failure("Application projection differs from causal state"));
        }
        let actual = {
            let mut q = connection
                .prepare("SELECT id,payload FROM item_conflicts")
                .map_err(failure)?;
            q.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(failure)?
            .collect::<rusqlite::Result<BTreeMap<_, _>>>()
            .map_err(failure)?
        };
        let expected = state
            .records
            .iter()
            .map(|r| Ok((r.id.to_string(), canonical(r)?)))
            .collect::<Result<BTreeMap<_, _>, Error>>()?;
        if actual != expected {
            return Err(failure(
                "Conflict view differs from retained logical records",
            ));
        }
        Ok(())
    }
}
