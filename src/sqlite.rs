use crate::model::{Database, DatabaseInfo, Failure, Limits, Mode, Result, Status};
use rusqlite::{Connection, Error, ErrorCode, OpenFlags, config::DbConfig, limits::Limit};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) fn classify(error: Error) -> Failure {
    let message = error.to_string();
    let status = match &error {
        Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                ErrorCode::OperationInterrupted | ErrorCode::TooBig | ErrorCode::OutOfMemory
            ) =>
        {
            Status::ResourceLimit
        }
        Error::SqliteFailure(_, _)
            if message.contains("no such module")
                || message.contains("no such collation")
                || message.contains("no such function")
                || message.contains("unsafe use of") =>
        {
            Status::Unsupported
        }
        Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                ErrorCode::CannotOpen | ErrorCode::SystemIoFailure
            ) =>
        {
            Status::OperationalError
        }
        _ => Status::Invalid,
    };
    Failure::new(
        status,
        "sqlite.check",
        message.chars().take(500).collect::<String>(),
    )
}

pub(crate) fn open(path: &Path, limits: &Limits, deadline: Instant) -> Result<Connection> {
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(classify)?;
    db.busy_timeout(Duration::ZERO).map_err(classify)?;
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(classify)?;
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(classify)?;
    db.load_extension_disable().map_err(classify)?;
    db.set_limit(
        Limit::SQLITE_LIMIT_LENGTH,
        limits.max_entry_bytes.min(i32::MAX as u64) as i32,
    )
    .map_err(classify)?;
    db.set_limit(
        Limit::SQLITE_LIMIT_SQL_LENGTH,
        limits.max_metadata_bytes.min(i32::MAX as u64) as i32,
    )
    .map_err(classify)?;
    db.set_limit(Limit::SQLITE_LIMIT_EXPR_DEPTH, 100)
        .map_err(classify)?;
    db.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(classify)?;
    db.execute_batch("PRAGMA query_only=ON; PRAGMA cache_size=-2048;")
        .map_err(classify)?;
    Ok(db)
}

pub(crate) fn encrypted_values(
    path: &Path,
    declaration: &crate::protection::SqliteProtection,
    limits: &Limits,
    deadline: Instant,
    mut visit: impl FnMut(&str, &[u8]) -> Result<()>,
) -> Result<()> {
    use rusqlite::types::ValueRef;
    let db = open(path, limits, deadline)?;
    let mut tables = db.prepare("PRAGMA main.table_list").map_err(classify)?;
    let ordinary = tables
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(classify)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(classify)?
        .into_iter()
        .any(|(schema, name, kind)| {
            schema == "main"
                && name == declaration.table
                && kind == "table"
                && !name.starts_with("sqlite_")
        });
    if !ordinary {
        return Err(Failure::invalid(
            "protection.sqlite_table",
            "Protected columns require an ordinary application table",
        ));
    }
    let quote = |name: &str| format!("\"{}\"", name.replace('"', "\"\""));
    let mut columns = db
        .prepare(&format!(
            "PRAGMA main.table_xinfo({})",
            quote(&declaration.table)
        ))
        .map_err(classify)?;
    let names = columns
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(6)?))
        })
        .map_err(classify)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(classify)?;
    if [&declaration.column, &declaration.record_id_column]
        .iter()
        .any(|name| {
            !names
                .iter()
                .any(|(actual, hidden)| actual == *name && *hidden == 0)
        })
    {
        return Err(Failure::invalid(
            "protection.sqlite_column",
            "Protected and identifier columns must exist with exact names and cannot be generated or hidden",
        ));
    }
    let query = format!(
        "SELECT {}, {} FROM main.{}",
        quote(&declaration.record_id_column),
        quote(&declaration.column),
        quote(&declaration.table)
    );
    let mut statement = db.prepare(&query).map_err(classify)?;
    let mut rows = statement.query([]).map_err(classify)?;
    let mut ids = BTreeSet::new();
    while let Some(row) = rows.next().map_err(classify)? {
        crate::container::check_deadline(deadline)?;
        let id = match row.get_ref(0).map_err(classify)? {
            ValueRef::Text(text) => std::str::from_utf8(text).ok(),
            _ => None,
        }
        .filter(|id| !id.is_empty() && id.len() <= 1024 && !id.contains('\0'))
        .ok_or_else(|| {
            Failure::invalid(
                "protection.record_id",
                "Record identifiers must be nonempty UTF-8 TEXT without NUL, at most 1024 bytes",
            )
        })?;
        if ids.len() >= limits.max_entries {
            return Err(Failure::limit(
                "Protected table row count exceeds configured entry limit",
            ));
        }
        if !ids.insert(id.to_owned()) {
            return Err(Failure::invalid(
                "protection.record_id",
                "Record identifiers must be unique using exact UTF-8 bytes",
            ));
        }
        match row.get_ref(1).map_err(classify)? {
            ValueRef::Null => {}
            ValueRef::Blob(block) => visit(id, block)?,
            _ => {
                return Err(Failure::invalid(
                    "protection.sqlite_blob",
                    "Protected values must be encrypted BLOBs or SQL NULL",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn examine(
    path: &Path,
    declaration: &Database,
    mode: Mode,
    limits: &Limits,
    deadline: Instant,
) -> Result<DatabaseInfo> {
    let db = open(path, limits, deadline)?;
    let user_version = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(classify)?;
    let journal_mode: String = db
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(classify)?;
    if mode == Mode::Verify && journal_mode != "delete" {
        return Err(Failure::invalid(
            "sqlite.journal_mode",
            "Packaged databases must use DELETE journal mode",
        ));
    }
    let mut statement = db.prepare("PRAGMA main.table_list").map_err(classify)?;
    let mut rows = statement.query([]).map_err(classify)?;
    let mut tables = Vec::new();
    while let Some(row) = rows.next().map_err(classify)? {
        let schema: String = row.get(0).map_err(classify)?;
        let name: String = row.get(1).map_err(classify)?;
        let kind: String = row.get(2).map_err(classify)?;
        if schema == "main"
            && matches!(kind.as_str(), "table" | "virtual")
            && !name.starts_with("sqlite_")
        {
            if tables.len() >= limits.max_entries {
                return Err(Failure::limit(
                    "SQLite table count exceeds the configured entry limit",
                ));
            }
            if kind == "virtual" {
                // Preparing a zero-row query connects required built-in modules without loading code.
                let quoted = name.replace('"', "\"\"");
                db.prepare(&format!("SELECT * FROM \"{quoted}\" LIMIT 0"))
                    .map_err(classify)?;
            }
            tables.push(name);
        }
    }
    tables.sort();
    if mode == Mode::Verify {
        if declaration
            .user_version
            .is_some_and(|expected| expected != user_version)
        {
            return Err(Failure::invalid(
                "sqlite.user_version",
                "SQLite user_version differs from the manifest",
            ));
        }
        let actual: BTreeSet<_> = tables.iter().collect();
        let expected: BTreeSet<_> = declaration.tables.iter().map(|table| &table.name).collect();
        if actual != expected {
            return Err(Failure::invalid(
                "sqlite.tables",
                "Logical SQLite table inventory differs from the manifest",
            ));
        }
        let mut check = db.prepare("PRAGMA integrity_check").map_err(classify)?;
        let results: Vec<String> = check
            .query_map([], |row| row.get(0))
            .map_err(classify)?
            .collect::<std::result::Result<_, _>>()
            .map_err(classify)?;
        if results != ["ok"] {
            return Err(Failure::invalid(
                "sqlite.integrity",
                format!(
                    "SQLite integrity check failed: {}",
                    results.join("; ").chars().take(500).collect::<String>()
                ),
            ));
        }
        let mut check = db.prepare("PRAGMA foreign_key_check").map_err(classify)?;
        if check
            .query([])
            .map_err(classify)?
            .next()
            .map_err(classify)?
            .is_some()
        {
            return Err(Failure::invalid(
                "sqlite.foreign_keys",
                "SQLite foreign key violations found",
            ));
        }
    }
    Ok(DatabaseInfo {
        path: declaration.path.clone(),
        user_version,
        journal_mode,
        tables,
        integrity_checked: mode == Mode::Verify,
        foreign_keys_checked: mode == Mode::Verify,
    })
}
