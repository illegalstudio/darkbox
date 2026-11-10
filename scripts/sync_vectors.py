#!/usr/bin/env python3
"""Generate sync vectors with an independent set-based Python materializer."""
import argparse
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def dot_key(dot):
    actor, seq, index = dot.split(":")
    return actor, int(seq), int(index)


def event_dot(tx, i):
    return f'{tx["replicaId"]}:{tx["sequence"]}:{i}'


def observed(tx, i, dot):
    actor, seq, index = dot_key(dot)
    return ((actor == tx["replicaId"] and seq == int(tx["sequence"]) and index < i)
            or any(t["replicaId"] == actor and int(t["sequence"]) >= seq for t in tx["dependencies"]))


def frontier(transactions):
    tips = {}
    for tx in transactions:
        actor = tx["replicaId"]
        if actor not in tips or int(tips[actor]["sequence"]) < int(tx["sequence"]):
            tips[actor] = {"replicaId": actor, "sequence": tx["sequence"], "sha256": digest(tx)}
    return [tips[k] for k in sorted(tips)]


def materialize(root, transactions):
    # Compute from sets of events, independently of the Rust incremental merge.
    events = [(tx, i, op) for tx in transactions for i, op in enumerate(tx["operations"])]
    creates = {event_dot(tx, i): op["collection"] for tx, i, op in events if op["op"] == "create"}
    records = []
    nodes = []
    def maxima(events):
        return [(tx, i, op) for tx, i, op in events if not any(
            observed(other, j, event_dot(tx, i)) for other, j, _ in events if (other, j) != (tx, i))]
    def sorted_events(events):
        return sorted(events, key=lambda e: dot_key(event_dot(e[0], e[1])))
    for record, collection in sorted(creates.items(), key=lambda pair: dot_key(pair[0])):
        own = [(tx, i, op) for tx, i, op in events if op.get("record") == record]
        fields = sorted({op["field"] for _, _, op in own if "field" in op})
        row = {"id": record, "collection": collection, "deletedBy": sorted(
            [event_dot(tx, i) for tx, i, op in own if op["op"] == "delete"], key=dot_key), "registers": [], "sets": [], "positions": []}
        for field in fields:
            assignments = [(tx, i, op) for tx, i, op in own if op.get("field") == field and op["op"] == "assign"]
            if assignments:
                candidates = []
                for tx, i, op in sorted_events(maxima(assignments)):
                    c = {"dot": event_dot(tx, i), "lamport": tx["lamport"], "present": op["present"]}
                    if op["present"]: c["value"] = op["value"]
                    candidates.append(c)
                row["registers"].append({"field": field, "candidates": candidates})
            adds = [(tx, i, op) for tx, i, op in own if op.get("field") == field and op["op"] == "set_add"]
            removes = [(tx, i, op) for tx, i, op in own if op.get("field") == field and op["op"] == "set_remove"]
            if adds or removes:
                row["sets"].append({"field": field, "adds": [{"dot": event_dot(tx, i), "value": op["value"]} for tx, i, op in sorted_events(adds)], "removed": sorted({tag for _, _, op in removes for tag in op["tags"]}, key=dot_key)})
            placements = [(tx, i, op) for tx, i, op in own if op.get("field") == field and op["op"] in ("place", "unplace")]
            if placements:
                candidates = []
                for tx, i, op in sorted_events(maxima(placements)):
                    c = {"dot": event_dot(tx, i), "lamport": tx["lamport"], "present": op["op"] == "place"}
                    if c["present"]: c["node"] = event_dot(tx, i)
                    candidates.append(c)
                row["positions"].append({"field": field, "candidates": candidates})
            for tx, i, op in placements:
                if op["op"] == "place":
                    nodes.append({"id": event_dot(tx, i), "record": record, "field": field, "sequence": op["sequence"], "owner": op["owner"], "after": op["after"], "lamport": tx["lamport"]})
        records.append(row)
    return {"kind": "darkbox-sync-state", "protocolVersion": "1.0.0", "syncId": root["syncId"], "rootSha256": digest(root), "frontier": frontier(transactions), "records": records, "nodes": sorted(nodes, key=lambda n: dot_key(n["id"]))}


def sequence(state):
    nodes = state["nodes"]
    children = {}
    for node in nodes: children.setdefault(node["after"], []).append(node)
    selected = {}
    for record in state["records"]:
        if record["deletedBy"]: continue
        for field in record["positions"]:
            c = max(field["candidates"], key=lambda c: (int(c["lamport"]), dot_key(c["dot"])))
            if c["present"]: selected[c["node"]] = record["id"]
    result = []
    def visit(anchor):
        for node in sorted(children.get(anchor, []), key=lambda n: (int(n["lamport"]), dot_key(n["id"])), reverse=True):
            if node["id"] in selected: result.append(selected[node["id"]])
            visit(node["id"])
    visit(None)
    return result


def generate():
    app = {"profile": "org.example.sync-notes", "formatVersion": "1"}
    def field(name, kind, types): return {"name": name, "kind": kind, "columns": [name], "codec": "typed", "valueTypes": types}
    position = field("position", "position", [])
    position.update(sequences=["items"], ownerCollections=[], allowRootOwner=True)
    mapping = {"kind": "darkbox-sync-mapping", "mappingVersion": "1.0.0", "application": app,
        "storage": {"mode": "single-database", "databasePath": "data/project.sqlite", "reservedPrefix": "_darkbox_sync_"},
        "collections": [{"name": "items", "table": "items", "idColumn": "id", "localColumns": ["local_note"],
            "fields": [field("asset", "register", ["blob"]), field("data", "register", ["decimal", "integer", "list", "map", "text"]), position, field("tags", "set", ["text"]), field("title", "register", ["text"])]}],
        "projection": {"id": "org.example.sync-notes.projection", "version": "1", "conflictPolicy": "quarantine", "documentationPath": "profile/profile.md"}}
    profile = """# Example synchronized notes profile 1

Profile identifier: org.example.sync-notes. Application format version: 1.
This fictional profile uses the sync 1.0.0 typed-value codecs. The items collection
is stored in items(id TEXT PRIMARY KEY, asset TEXT, data TEXT, position TEXT,
tags TEXT, title TEXT, local_note TEXT). IDs are create-operation dots. Synchronized
columns asset, data and title contain the canonical selected typed value, or SQL
NULL when absent. tags contains the canonical array of visible typed set values;
position contains the canonical PositionField object, or SQL NULL when absent.
The item_conflicts(id TEXT PRIMARY KEY, payload BLOB NOT NULL) table contains the
canonical complete RecordState JSON for every record, including deleted records.
Its BLOB bytes are UTF-8 JSON, not encrypted data. This retains competing values,
set tags and deletion markers independently of the displayed items rows.
local_note is installation-local and is retained on rebuild.
A deterministic conflict view retains all concurrent candidates and hidden records;
record deletion never erases history. There are no cross-record constraints.
No value or file is executable. Resources are immutable byte objects selected by
SHA-256 and size through the complete checkpoint object index. Missing keys are
not applicable because this profile uses the trusted-folder plaintext sync mode.
The _darkbox_sync_ tables are reserved for the causal journal, pending input,
outbox, immutable domain/session metadata and retained fork evidence. Their exact
protocol interpretation is in the included Darkbox synchronization reference.
"""
    root = {"kind": "darkbox-sync-domain", "protocolVersion": "1.0.0", "syncId": "0" * 31 + "1", "packageId": "0" * 31 + "2", "commonVersion": "1.5.0", "application": app,
        "profile": {"path": "profile/profile.md", "size": str(len(profile.encode())), "sha256": hashlib.sha256(profile.encode()).hexdigest()},
        "mapping": {"path": "profile/mapping.json", "size": str(len(canonical(mapping))), "sha256": digest(mapping)}, "encoding": "jcs-strings-v1", "merge": "causal-records-v1", "security": "trusted-folder-plaintext"}
    actors = {name: f'{i:032x}' for i, name in enumerate("gabcde", 16)}
    def transaction(actor, known, ops):
        deps = frontier(known)
        own = next((tip for tip in deps if tip["replicaId"] == actors[actor]), None)
        return {"kind": "darkbox-sync-transaction", "protocolVersion": "1.0.0", "syncId": root["syncId"], "rootSha256": digest(root), "replicaId": actors[actor], "sequence": str(int(own["sequence"]) + 1 if own else 1), "previous": own["sha256"] if own else None, "dependencies": deps, "lamport": str(1 + max([int(tx["lamport"]) for tx in known] or [0])), "operations": ops}
    def text(s): return {"type": "text", "value": s}
    def assign(record, value, field="title"): return {"op": "assign", "record": record, "field": field, "present": True, "value": value}
    def place(record, after): return {"op": "place", "record": record, "field": "position", "sequence": "items", "owner": None, "after": after}
    x, y, z = [f'{actors["g"]}:1:{i}' for i in range(3)]
    gx, gy, gz = [f'{actors["g"]}:1:{i}' for i in [4, 5, 6]]
    g = transaction("g", [], [{"op": "create", "collection": "items"} for _ in range(3)] + [assign(x, text("initial")), place(x, None), place(y, gx), place(z, gy)])
    payload = b"Darkbox media\x00\xff"
    blob = {"type": "blob", "sha256": hashlib.sha256(payload).hexdigest(), "size": str(len(payload))}
    a1 = transaction("a", [g], [assign(x, text("left")), {"op": "set_add", "record": x, "field": "tags", "value": text("red")}, place(x, gy), assign(x, blob, "asset")])
    b1 = transaction("b", [g], [assign(x, text("right")), {"op": "set_add", "record": x, "field": "tags", "value": text("red")}, place(y, gx)])
    a2 = transaction("a", [g, a1], [{"op": "set_remove", "record": x, "field": "tags", "value": text("red"), "tags": [event_dot(a1, 1)]}])
    c1 = transaction("c", [g, a1, b1, a2], [assign(x, text("resolved")), place(z, event_dot(a1, 2))])
    b2 = transaction("b", [g, b1], [{"op": "delete", "record": x}])
    new = f'{actors["d"]}:1:0'
    d1 = transaction("d", [g, a1, b1, a2, c1, b2], [{"op": "create", "collection": "items"}, assign(new, text("restored")), place(new, event_dot(c1, 1))])
    exact = transaction("e", [g], [assign(z, {"type": "map", "entries": [{"key": "big", "value": {"type": "integer", "value": "18446744073709551616"}}, {"key": "decimal", "value": {"type": "decimal", "coefficient": "123456789012345678901", "exponent": "-21"}}, {"key": "text", "value": text("A\u000f\n\u20ac\U0001f642")}]}, "data")])
    unset = transaction("a", [g, a1, b1, a2, c1, b2, d1, exact], [{"op": "unplace", "record": y, "field": "position"}, {"op": "assign", "record": z, "field": "data", "present": False}])
    cases = [("concurrent-values-and-moves", [g, a1, b1]), ("observed-remove-concurrent-add", [g, a1, b1, a2]), ("causal-resolution", [g, a1, b1, a2, c1]), ("delete-wins", [g, a1, b1, a2, c1, b2]), ("explicit-new-id-restore", [g, a1, b1, a2, c1, b2, d1]), ("exact-values", [g, exact]), ("clear-and-unplace", [g, a1, b1, a2, c1, b2, d1, exact, unset])]
    vectors = []
    for name, transactions in cases:
        state = materialize(root, transactions)
        vectors.append({"name": name, "transactions": transactions, "state": state, "stateSha256": digest(state), "order": sequence(state)})
    rejects = []
    bad = copy.deepcopy(a2); bad["operations"][0]["tags"] = [event_dot(b1, 1)]
    rejects.append({"name": "remove-unobserved-tag", "transactions": [g, a1, b1, bad]})
    bad = copy.deepcopy(c1); bad["dependencies"] = [tip for tip in bad["dependencies"] if tip["replicaId"] != actors["g"]]
    rejects.append({"name": "nonclosed-frontier", "transactions": [g, a1, b1, a2, bad]})
    bad = copy.deepcopy(a1); bad["lamport"] = "999"
    rejects.append({"name": "unjustified-clock", "transactions": [g, bad]})
    bad = copy.deepcopy(a1); bad["operations"][0]["value"] = text("fork")
    rejects.append({"name": "same-id-fork", "transactions": [g, a1, bad]})
    later = transaction("a", [g, a1, b1, a2, c1, b2, d1], [assign(x, text("resurrection"))])
    rejects.append({"name": "edit-known-deleted-id", "transactions": [g, a1, b1, a2, c1, b2, d1, later]})
    bad = copy.deepcopy(a1); bad["operations"][2]["after"] = event_dot(b1, 2)
    rejects.append({"name": "anchor-only-known-to-receiver", "transactions": [g, b1, bad]})
    return {"extension": "studio.illegal.darkbox.sync", "version": "1.0.0", "generator": "Independent Python set-based materializer; no Rust output is used", "profile": profile, "mapping": mapping, "root": root, "rootSha256": digest(root), "objects": [{"sha256": blob["sha256"], "size": blob["size"], "hex": payload.hex()}], "vectors": vectors, "rejections": rejects, "canonicalExample": {"transaction": a1, "utf8": canonical(a1).decode(), "sha256": digest(a1)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = ROOT / "archive/1.5.0/docs/darkbox/sync/1.0.0.vectors.json"
    expected = (json.dumps(generate(), ensure_ascii=True, indent=2) + "\n").encode()
    if path.exists() and path.read_bytes() == expected:
        print("sync 1.0.0: independent vectors match")
        return
    if args.check: raise SystemExit("Sync vectors differ from independent generator")
    released = next(v["released"] for v in json.loads((ROOT / "versions.json").read_text())["versions"] if v["version"] == "1.5.0")
    if released: raise SystemExit("Published canonical vectors cannot be rewritten")
    path.write_bytes(expected)
    print("sync 1.0.0: independent vectors generated")


if __name__ == "__main__":
    main()
