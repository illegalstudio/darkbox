# Synchronizing local libraries

Software 1.5.0 provides the `darkbox::sync` SDK for the official
`studio.illegal.darkbox.sync` extension 1.0.0 and common Darkbox 1.5.0.
Each computer uses its own local live library. An existing cloud client copies a
separate exchange folder containing immutable transactions, resources and complete
checkpoints. Darkbox requires no additional sync executable, server or CRDT runtime.

The [normative reference](../archive/1.5.0/docs/darkbox/sync/1.0.0.md),
[JSON Schema](../archive/1.5.0/docs/darkbox/sync/1.0.0.schema.json) and
[independent vectors](../archive/1.5.0/docs/darkbox/sync/1.0.0.vectors.json)
are included in the canonical bundle. Protocol replay and package verification
operate offline. Complete checkpoint creation/opening requires full byte verification;
application-trusted digest reuse does not certify a complete sync checkpoint. The application supplies its exact data mapping and projection;
Darkbox does not infer merge intent from arbitrary SQLite writes.

## Run the complete example

From a source checkout:

```sh
cargo run --example sync_notes -- /absolute/path/to/a-new-demo-directory
```

The directory must be absent. The example creates an initial checkpoint, two
separate live libraries, private object stores and one exchange folder. Both
peers edit the same title offline, exchange their transactions and retain both
competing values. It then produces a full checkpoint and rebuilds a third local
library. This demonstrates folder transport locally; a cloud client can copy the
exchange folder between actual computers.

The executable is [examples/sync_notes.rs](../examples/sync_notes.rs). Its
[fictional notes adapter](../examples/support/sync_notes.rs) implements schema
creation, projection, local-only field preservation and verification. The included
profile describes its tables and exact typed-value encodings. Applications adapt
those responsibilities to their own independently versioned profile.

## Domain and storage

A `Domain` binds a random `syncId`, a stable common `packageId`, exact application
profile/data-format version, the complete human-readable profile, an immutable
`SyncMapping`, and a projection identifier/version. `Domain::generate` allocates
new identities. When importing the same logical existing library, use
`Domain::new(random_id()?, existing_package_id, mapping, profile_bytes)` to retain
its package identity. The format/profile change needed to integrate sync belongs
to the application; attaching sync never silently migrates an older library.

Use three distinct locations:

| Location | Contents | Owner |
| --- | --- | --- |
| Local working library | Authoritative SQLite database, live WAL and working metadata | Application holding `DirectoryLibrary` |
| Private `ObjectStore` | Complete immutable resource bytes, addressed by hash and length | Application/SDK |
| Shared `Exchange` | Immutable root/profile, per-incarnation segments/checkpoints/receipts and object pool | SDK plus the selected cloud client |

The working library and private store must remain outside the selected exchange.
The SDK rejects overlap between those paths. The application must also ensure
its local live database is outside any other cloud-synchronized directory.
Local OS locks coordinate processes on one computer; they never coordinate peers.

Create an exchange with `Exchange::create(path, domain, limits)`. Join an existing
one with `Exchange::open(path, pinned_root_sha256, limits)`. Obtain/pin the intended
root identity through the application's library-selection flow; a root file
changing under the same domain is a conflict, not a migration.

## Profile integration

`SyncMapping` declares collections, physical table/identity columns, register,
set and position fields, exact codecs and local-only columns. It also identifies
the single authoritative database or an authoritative-journal/rebuildable-cache
model. Protocol record identity is the create-operation dot. A profile may retain
application UUIDs through its documented codec and mapping.

Implement `SyncProjection` with these responsibilities:

- `id` and `version` match the domain's exact projection contract.
- `validate_mapping` confirms the complete supported mapping and physical schema.
- `initialize` creates a fresh private projection database for checkpoints/bootstrap.
- `project` materializes the next logical state and its deterministic conflict view
  in the supplied SQLite transaction, preserving local-only values.
- `verify` checks the database against the synchronized logical state and profile
  invariants. It excludes installation-local values from replicated equality.

Registered adapter code comes from the integrating application. Never load SQL,
JavaScript, plugins or other executable projection code from a package or exchange.
The example's full-table projection is easy to inspect; production adapters can
compare previous/next state and update affected rows while preserving the same
semantics.

A valid concurrent change can violate an application's uniqueness or reference
rules. Accept its causal history and retain the affected data in the profile's
deterministic conflict view. Do not discard the transaction or block all peers
because a naive SQL projection would violate a constraint. Unexpected database
or adapter failures roll back the entire incoming transaction.

## Initial import and opening a session

Import existing application data once into create/assign/set/place operations.
`History::prepare` and `History::accept` support this controlled initial import;
the application interprets its existing schema and resources. Publish a complete
initial checkpoint before offering the domain to other computers. Joining an
existing domain starts from its checkpoint/history instead of importing a second
independent copy of the original database.

`SnapshotBuilder` creates a new closed application projection from verified
history using the registered adapter. It adds the common canonical bundle,
profile, exact root/mapping, complete transaction history, logical state and
all historically referenced objects. Additional declared profile files or cache
databases can be supplied with `add_path`/`add_reader`. The output must be absent;
checkpoints are never edited or replaced.

Open a checkpoint with `SyncSnapshot::open`. Call `verify_projection` with the
adapter to certify the application materialization. `bootstrap` checks it,
rebuilds privately from history and atomically publishes an absent local
working-library directory. It does not adopt archive-supplied SQL as an executable
projection. Existing local libraries merge checkpoint history through
`SyncSession::receive_history`, preserving local unpublished operations.

For a new compatible common 1.5.0 working library, `attach_working` installs the
domain's exact metadata while the application owns its directory guard and write
barrier. It refuses protected libraries and inconsistent existing sync metadata.
It does not translate existing rows into sync operations.

Open the authoritative database with persistent journaling and durable commits:

```rust,ignore
connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
let session = SyncSession::open(
    &mut library,
    &mut connection,
    domain,
    objects,
    SessionOptions::new(persisted_device_id, "My computer"),
    &adapter,
)?;
```

The main database must be exactly the domain's declared database inside that
working library. `SyncSession` borrows the library guard exclusively. It creates
a fresh replica incarnation on every opening, including after crash, backup
restore or copied installation. A persistent device ID/label is display metadata,
not operation identity. Previously committed outgoing bytes remain publishable;
new transactions never append to an old incarnation.

## Local edits and immutable resources

Stage resources into the private `ObjectStore` before referring to them. `put`
streams, hashes, flushes and publishes a complete object without overwriting an
existing different file. `put_expected` also requires an exact expected digest
and length. The caller must retain these objects unchanged. Do not edit files
under the store directly or synchronize it as a writable cloud database.

Submit a transaction with `edit`, or use `edit_with` when new records need IDs
within the same atomic group:

```rust,ignore
let committed = session.edit_with(&mut connection, &adapter, |batch| {
    let id = batch.dot(0)?;
    Ok(vec![
        Operation::Create { collection: "items".into() },
        Operation::Assign {
            record: id,
            field: "title".into(),
            present: true,
            value: Some(SyncValue::text("A new note")),
        },
    ])
})?;
```

The builder uses the allocated transaction sequence and must only construct its
operation group. Expensive resource hashing happens outside the SQLite write
transaction. Before committing, the SDK rechecks the causal revision and retained
resource identities. A changed revision returns `sync.revision_changed` and requires rebuilding the group.
The session supports background publication with a separate SQLite connection;
each publisher freezes its outbox/history view before doing file I/O.

Application projection, exact immutable transaction bytes, causal history and
outbox commit together in one authoritative main database. A separate WAL-mode
outbox database cannot provide that atomicity. Direct changes to synchronized
rows outside this integration are detected by adapter verification and are not
converted into guessed outgoing operations. Installation-local fields may still
be maintained independently under the profile's rules.

Protocol numbers use exact string encodings. `SyncValue::Integer` and `Decimal`
retain arbitrary values within the documented digit/exponent bounds without
requiring the `exact-numbers` Cargo feature. Structured register values are
replaced atomically; text is a register rather than a collaborative character
sequence.

## Publish, receive and apply

The application schedules background exchange work:

```rust,ignore
session.publish_pending(&connection, &exchange)?;
let scan = session.receive_exchange(&mut connection, &exchange)?;
let applied = session.apply_ready(&mut connection, &adapter)?;
```

`publish_pending` retries exact committed bytes, including earlier incarnations.
It publishes descriptors, resource bytes and sealed segments with local
no-clobber operations. It verifies an existing identical publication before
accepting a retry. Completed outbox rows remain retained; `repair_publications` explicitly republishes
them if a local exchange file was lost. Normal background publishing processes
queued rows without rehashing every old publication. It never holds a SQLite
write transaction while waiting for
cloud transfer. No final exchange file is reopened for writing.

`receive_exchange` checks the pinned root and scans bounded canonical records.
It imports complete objects and durably queues transactions. `apply_ready`
advances only after the preceding sequence, exact causal dependencies and every
referenced resource are available. Each accepted group and its projection commit
atomically. Independent ready chains can progress while another chain waits.

A cloud client can expose partial files and deliver them out of order despite a
local atomic rename. The scanner verifies complete length/hash/content. Incomplete
or changed files stay pending. Noncanonical filenames are excluded from
application; bounded verified conflict-copy inspection detects identical
redundancy or a divergent logical identity. Symlinks and path traversal are
never followed as protocol inputs.

`ExchangeScan::diagnostics` reports pending bytes, unknown files, unsupported
records and missing replica descriptors. `SyncSession::pending` reports missing
causal tips/resources and whether a group is ready for semantic validation.
`queued_count` reports outgoing transactions not yet published locally.
Publishing locally does not certify cloud upload or receipt by every computer.

`publish_receipt` writes an immutable advisory frontier. `verified_receipts`
checks known peer receipt coverage against verified history. Receipts never
permit resource/history deletion. Unknown/offline devices cannot be declared
fully synchronized by a folder scan.

## Conflicts, checkpoints and recovery

| Concurrent activity | Result |
| --- | --- |
| Different fields | Both updates survive |
| Same register field | Deterministic displayed candidate; all maximal alternatives retained |
| Set add versus unobserved remove | The concurrent add survives |
| Record delete versus edit | Record stays deleted; hidden edit remains in history |
| Restore deleted record | Explicit create with a new ID |
| Concurrent moves | Deterministic immutable-anchor traversal; competing placements retained |

Wall-clock time never decides a winner. A later assignment resolves only
alternatives the author has observed. `RegisterField::conflicted` and candidate
dots support the application's conflict UI; `LogicalState::ordered_records`
provides the prescribed order for one position field/sequence/owner.

A `SyncSnapshot` retains deleted-resource bytes and causal metadata as well as the
visible projection. `publish` stores its exact package bytes before publishing its
external descriptor. `SyncSnapshot::fetch` checks that descriptor against the
frozen, verified package. `select_snapshot` chooses by verified causal coverage,
with deterministic ties, and rejects divergent histories. Filesystem timestamps
have no freshness meaning.

Ordinary `darkbox verify` checks complete sealed checkpoint core replay/state and
historical object closure, while reporting application projection as unchecked
unless an application profile validator is registered. A `working` sync descriptor
is application-owned runtime state, even after its SQLite connections close;
generic opening/packing reports NotQuiescent and never reconstructs the journal.
Use a complete sealed checkpoint for portable backup and transfer.

A crash before commit leaves the earlier application state and no outgoing
transaction. A crash after commit leaves exact retryable outgoing bytes. Received
input remains durable until it can be applied. Reopening starts a new incarnation.
A different complete transaction at an existing replica/sequence is a hard fork:
the SDK retains evidence, stops ordinary writes and requires explicit recovery
into a new domain. It never chooses a branch using filenames or timestamps.

## Version 1 bounds and security

The mode is explicitly **trusted-folder plaintext**. The operator trusts all
writers and the cloud provider with those bytes. SHA-256 is integrity checking,
not author authentication. Sync v1 refuses protected libraries and never removes
protection to make attachment succeed. Authenticated/encrypted sync requires a
separately defined compatible mode.

The application profile, data-format version and mapping stay fixed per domain.
Version 1 does not perform distributed migrations, automatic garbage collection,
replica retirement or tombstone pruning. Every writing session adds an incarnation
frontier entry. Full checkpoints include history and historical resources, so
storage can grow substantially. Format migration/compaction needs explicit
reconciliation and rebootstrap into a new domain; an offline old computer is not
silently migrated.

`SyncLimits` bounds history bytes, transaction count, folder scan entries and
ordinary I/O through `Limits`. Wire limits also bound individual transactions,
segments, values and exact-number representations. Operational limits return
errors; they never authorize truncation, skipping a causal gap or deleting old
history. A transport must eventually deliver and preserve complete published
files for convergence to progress. Actual cloud-client configuration and availability
remain application deployment responsibilities.
