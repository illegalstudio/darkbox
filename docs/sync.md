# Synchronizing local libraries

Software 1.6.1 provides the `darkbox::sync` SDK for the official
`studio.illegal.darkbox.sync` extension 1.0.0 and common Darkbox 1.5.0.
Each computer uses its own local live library. An existing cloud client copies a
separate repository containing immutable transactions, resources and independently
complete checkpoint generations. Retention is independent of device membership. Darkbox requires no additional sync executable, server or CRDT runtime.

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
competing values. It then publishes compact generations, prunes expired data, prepares a private
recovery package for a stale peer and rebuilds a third local library. This demonstrates folder transport locally; a cloud client can copy the
exchange folder between actual computers. The example includes an immutable
attachment, so it also exercises object publication.

An optional second argument selects a new exchange directory on a mounted
filesystem while keeping the working libraries and private stores local:

```sh
cargo run --example sync_notes -- /local/new-demo /mounted/new-exchange
```

Both paths must be unused and application-controlled.

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

Use three distinct locations. For bounded retention, open the shared location through `SyncRepository` and obtain its current generation `Exchange`:

| Location | Contents | Owner |
| --- | --- | --- |
| Local working library | Authoritative SQLite database, live WAL and working metadata | Application holding `DirectoryLibrary` |
| Private `ObjectStore` | Complete immutable resource bytes, addressed by hash and length | Application/SDK |
| Shared `SyncRepository` | Immutable policy, generation exchanges, checkpoints and retirement proofs | SDK plus the selected cloud client |

The working library and private store must remain outside the selected exchange.
The SDK rejects overlap between those paths. The application must also ensure
its local live database is outside any other cloud-synchronized directory.
Local OS locks coordinate processes on one computer; they never coordinate peers.

Create a repository with `SyncRepository::create(path, &domain, policy, limits)` and publish a verified initial checkpoint with `publish_initial`. Join with `SyncRepository::open(path, pinned_repository_hash, limits)`. Obtain an exchange with `repository.exchange(&repository.current()?)`. Standalone `Exchange::create` and `open` retain their per-domain behavior for integrations that manage generations themselves. Obtain/pin the intended
root identity through the application's library-selection flow; a root file
changing under the same domain is a conflict, not a migration.

## Filesystem requirements

Keep live SQLite libraries and private object stores on suitable local storage.
The shared repository needs regular-file reads, directory synchronization and
atomic rename within each destination directory. Native atomic no-clobber
publication is preferred. Software 1.6.1 also supports Unix mounts, including
rclone FUSE with VFS full caching, that reject no-replace rename and hard links
but support parent-directory advisory `flock` and atomic ordinary rename.

Every local SDK sync publisher first takes that directory lock where supported,
including publishers using the native path. If native publication is unsupported,
the SDK rechecks that the destination is absent while holding the lock and
atomically renames the complete, flushed candidate. An existing file, directory
or dangling symlink is never replaced by this fallback. It creates no persistent
lock files and never copies directly into a final filename. Lock contention is
bounded by the operation's `Limits::timeout`. Without a usable directory lock,
the SDK retains native no-clobber publication and refuses the rename fallback.

Directory locks coordinate cooperating local SDK publishers only. They are not
distributed locks and cannot exclude another computer, a cloud client or tools
that ignore them. Reserve protocol filenames for the SDK; older SDK versions
without this locking protocol must not publish concurrently on the same mount.
Cloud copies can still arrive partially or under conflict names, so all existing
length, hash, canonical-content and fork checks remain required. Qualify the
actual mount and cloud-client configuration used by the application; support for
these operations cannot be inferred from the FUSE name alone.

A metadata change during a guarded record read discards that attempt's bytes.
The SDK retries a complete read up to three times to allow VFS attributes to
settle, preserving every path, descriptor and stability check. Continued change
returns `sync.pending_bytes` for a later retry rather than accepting unstable
input. Arbitrary blocking filesystem calls remain subject to the cooperative
I/O-limit contract.

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
profile, exact root/mapping, a pinned compact baseline when present, subsequent transaction history, logical
state and every object referenced by that retained baseline/history. Additional declared profile files or cache
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
It does not translate existing rows into sync operations. The built-in working
session, attachment and bootstrap adapters support sync as the only required
extension; they refuse additional required namespaces without modifying the
source. Custom required extensions need an integration that owns all their writer
capabilities. Generic checkpoint reading can still use registered verifiers.

Open the authoritative database with persistent journaling and durable commits:

```rust,ignore
connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")?;
let session = repository.open_session(
    &mut library,
    &mut connection,
    objects,
    SessionOptions::new(persisted_device_id, "My computer"),
    &adapter,
)?;
```

The repository persists the newest observed generation as a high-water witness in the journal. Returning sessions reopen their locally pinned domain, even when its cloud generation has expired, so private recovery remains available. Their old-generation exchanges still refuse publication. Open the local session before using a freshly opened repository handle for maintenance; `open` alone has no access to an existing local journal. The main database must be exactly the domain's declared database inside that
working library. `SyncSession` borrows the library guard exclusively. It creates
a fresh replica incarnation on every opening, including after crash, backup
restore or copied installation. A persistent device ID/label is display metadata,
not operation identity. Previously committed outgoing bytes remain publishable;
new transactions never append to an old incarnation.

Software 1.6.0 can also keep the guard inside the session, so a long-lived
application does not need a self-referential holder:

```rust,ignore
let session = repository.open_owned_session(
    library,
    &mut connection,
    objects,
    SessionOptions::new(persisted_device_id, "My computer"),
    &adapter,
)?;
// edit, publish_pending, receive_exchange, apply_ready and rebase checks work
// exactly as with a borrowed session.
let library = session.close();
```

`OwnedSyncSession::open` supplies the equivalent per-domain API. Both owning
constructors return `OwnedSessionError` on failure; `into_parts()` recovers the
error and still-guarded `DirectoryLibrary`. Successful `close()` also returns the
guard without sealing the library or closing the application's SQLite handles.
Close/checkpoint those handles before sealing. `OwnedSyncSession` is `Send + Sync`
and works with `prepare_rebase` and `check_prepared_rebase` without adapters or
additional dependencies. `Dot` and `Counter` implement `Hash` as well as equality
and ordering.

## Local edits and immutable resources

Stage resources into the private `ObjectStore` before referring to them. `put`
streams, hashes, flushes and publishes a complete object without overwriting an
existing different file. `put_expected` also requires an exact expected digest
and length. The caller must retain these objects unchanged. Do not edit files
under the store directly or synchronize it as a writable cloud database.

### Object verification policy

Ordinary `ObjectStore::open` fully hashes each object checked by `contains` or
`with_blob`. Applications that independently guarantee all store bytes remain
immutable can explicitly select bounded witness reuse:

```rust,ignore
let objects = ObjectStore::open(private_path, limits)?
    .with_trusted_immutable_cache(10_000);
let session_objects = objects.clone();
```

The first access hashes the complete object. Later accesses can reuse that result
while file identity, size and modification metadata match; Unix change metadata
also invalidates cached witnesses. Access still refuses symlinks and checks for
changes during the read. At most `capacity` verification witnesses are cached,
with oldest insertions evicted first; no object is deleted by cache eviction.
Capacity zero keeps full hashing. Clones share witnesses;
independently opened handles have independent policies and caches.

This is an explicit application trust policy. Matching metadata cannot prove
unchanged content against an external writer. Keep the store private, control
hard-linked resources and prevent content modification by every application
component. `clear_verification_cache()` invalidates all shared witnesses;
`verify(&blob)` always reads and hashes the complete file regardless of policy.
Changed or missing files invalidate their witnesses. An empty or reopened cache
requires fresh verification. A complete checkpoint still receives full byte
verification and makes no metadata-only integrity claim.

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

The application schedules background exchange work. Repository exchanges check the current generation before scanning or publishing:

```rust,ignore
let generation = repository.current()?;
let exchange = repository.exchange(&generation)?;
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
If a transaction fails semantic validation, `apply_ready` leaves it pending and
returns the offending replica and sequence after applying other ready chains.

In software 1.6.0, receipt checks every known identity against exact durable bytes
and retains conflict-copy evidence before skipping object imports for already
applied transactions. Each pending object is imported at most once per scan, and
pending transactions are revisited on later scans so media delivered after their
transaction can still unblock it. Applications should use `receive_exchange`
rather than reading private journal tables or filtering a plain `Exchange::scan`;
those shortcuts can discard fork evidence or strand pending media.

Normal receipt does not revalidate all media in committed history. Strict
`ObjectStore::verify` or complete checkpoint verification can diagnose independent
local damage. For an explicit missing-object repair pass, retain the scan returned
by `receive_exchange` and call `session.objects().import(&exchange, &blob)` for
its transactions' blob references. This preserves the SDK's identity/evidence
checks. Damaged existing objects are refused rather than overwritten; quarantining
or removing damaged local bytes requires the application's explicit repair policy.

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
visible projection within its generation. `publish` stores its exact package bytes before publishing its
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

The application profile, data-format version and mapping stay fixed across a repository's generations. `History::compact` produces a fresh domain with a root-bound baseline and no tail transactions. The baseline preserves live record IDs, unresolved register/placement alternatives and visible ordering. It removes superseded transactions, inactive set tags, obsolete ordering anchors and unreferenced deleted records. Resource closure follows the retained seed and current-generation history.

Baseline trust is explicit. Its exact bytes are pinned by the root and structurally checked, then the verifier replays all subsequent history and checks state/resource closure. Removed pre-generation edits are outside that verification claim. Generic verification continues to leave application projection to its registered adapter.

`SyncLimits` bounds history bytes, transaction count, folder scan entries and
ordinary I/O through `Limits`. Wire limits also bound individual transactions,
segments, values and exact-number representations. Operational limits return
errors; they never authorize truncation, skipping a causal gap or deleting old
history. A transport must eventually deliver and preserve complete published
files for convergence to progress. Actual cloud-client configuration and availability
remain application deployment responsibilities.


## Compaction and bounded retention

`RetentionPolicy::default()` uses a 30-day grace window, at least two checkpoints, a seven-day checkpoint interval with nonempty history, 10,000 transactions or 16 MiB of tail history. The policy is immutable in the pinned repository root. Applications can choose different positive thresholds and a checkpoint count of at least two when creating a repository. `compaction_due(&history, now)` reports whether the application's background scheduler should capture a complete current checkpoint. There is no external daemon.

Build a private current `SyncSnapshot` under the application's capture barrier, then call `repository.compact(&snapshot, &objects, &adapter, now, &options)`. The snapshot's current domain must be the repository head. Additional profile resources and secondary closed databases survive compaction. A new syncId, exact seed/root and independently complete package are published before the generation record. An old generation is never mutated into a new one.

`repository.prune(now, &adapter, &options)` fully verifies the current checkpoint and its projection, checks predecessor grace periods and preserves the configured recent generations. Before deleting data it publishes a self-contained retirement proof. Domain paths include their ordinal, so a cloud client resurrecting old files cannot make an expired generation current or prevent later cleanup. Retirement proofs themselves are compacted after a higher verified cutoff is published. The SDK uses explicit UTC seconds supplied by the application, not filesystem timestamps. Clock rollback or a retirement proof ahead of the local maintenance clock postpones deletion.

Pruning touches only expired reserved domain namespaces and their control records. Symlinks and special files stop cleanup. Interruptions leave a verified cutoff and retryable remaining work. In a healthy repository the retained state consists of current data/conflicts, recent generation checkpoints, tail history within the configured window and a current retirement proof. Real live data, unresolved conflicts, ongoing writes and deliberately retained private recovery packages still consume space. Operational scan/byte limits always fail rather than silently omit input.

## Rebase and recovery of a stale installation

A repository exchange returns `sync.generation_changed` when its base is superseded. Old offline edits remain local or in their old ordinal namespace. `base_status(domain, now)` distinguishes current, superseded-with-grace and expired bases. Retention does not enumerate or retire devices.

Use the repository's `open_session` for local durable high-water tracking. On a base change, call `prepare_rebase` with a `RebaseTarget` containing an absent private working-library path, a private object store and an optional absent recovery-package path. A fresh private store lets the application discard obsolete local media when adoption is complete. If the exact captured source boundary cannot be certified, or outgoing/pending rows exist, omitting recovery_path returns `sync.recovery_required` before building the replacement. This conservative recovery rule also applies to concurrent edits on a recently superseded base.

The complete private recovery `.darkbox` package includes the old seed/history, objects and deterministic projection. `extensions/studio.illegal.darkbox.sync/recovery/journal.json` preserves exact outgoing and incoming transaction records and identifies missing pending media. Available pending-only media is included as well. `RecoveryJournal` exposes the source revision and captured frontier. Application-local columns are preserved by the adapter's `copy_local(source, destination_transaction, domain)` hook, in both the recovery archive and fresh local library. The default refuses this operation when the mapping declares local columns and the adapter has no implementation.

`prepare_rebase` returns `PreparedRebase` with a guarded fresh library, its generation, the source revision and any recovery path. Under the application's write barrier, call `check_prepared_rebase(&session, &connection, &prepared, &adapter)` to durably recopy the latest local-only columns and recheck the source revision and generation, then atomically update the application's own active-library configuration before closing the old session. The source working library and object store remain intact until the application completes adoption and applies its local cleanup/recovery retention policy. The SDK cannot change an application's external configuration pointer. Incoming pending changes invalidate the preparation just like local edits.

No old operation is automatically converted into a new-generation write. The application can open the recovery package for comparison and offer selective import as ordinary current-generation operations. Stable retained record IDs let a selected value be applied to an existing record. A recovered deleted or previously unknown record requires the profile's new-record/import flow. An old title therefore cannot silently replace a newer accepted title.

## Concurrent checkpoint publication

Distinct complete records at the greatest ordinal produce `sync.generation_conflict`. Unreconciled retained branches also stop pruning. The SDK retains their bytes. Inspect `generations()` and the retained checkpoints, then construct the desired reconciled source checkpoint through the application's conflict UI.

`resolve_with_checkpoint` requires an explicitly selected branch and `ResolutionTarget` with a private recovery directory. It exports complete recovery packages for every observed branch, including ready exchange history and resources, before publishing the selected compact state. Missing or invalid branch input blocks resolution. A changed observed branch set requires retry and leaves the exported archives available. The resolution record names its parent and replaced branches. Their cloud data still follows grace and retirement proofs. This operation requires an application decision and never picks a branch by wall-clock time.
