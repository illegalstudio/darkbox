#!/usr/bin/env python3
"""Reproduce the independently versioned sync JSON Schema without network access."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = "extensions/studio.illegal.darkbox.sync"


def build_schema():
    defs = {}
    def ref(name): return {"$ref": "#/$defs/" + name}
    def arr(item, **kw): return {"type": "array", "items": item, **kw}
    def obj(properties, optional=()):
        return {"type": "object", "required": [k for k in properties if k not in optional], "additionalProperties": False, "properties": properties}
    def enum(*values): return {"enum": list(values)}
    text = {"type": "string"}
    boolean = {"type": "boolean"}
    null = {"type": "null"}
    defs["counter"] = {"type": "string", "pattern": "^(?:0|[1-9][0-9]{0,19})$", "$comment": "Additionally enforce unsigned 64-bit maximum 18446744073709551615."}
    defs["id"] = {"type": "string", "pattern": "^[0-9a-f]{32}$"}
    defs["hash"] = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    defs["name"] = {"type": "string", "pattern": "^[A-Za-z][A-Za-z0-9_]{0,63}$"}
    defs["dot"] = {"type": "string", "pattern": "^[0-9a-f]{32}:[1-9][0-9]{0,19}:(?:0|[1-9][0-9]{0,3})$", "$comment": "Sequence is unsigned 64-bit and positive; index is at most 4095."}
    defs["path"] = {"type": "string", "minLength": 1, "pattern": "^[A-Za-z0-9._/-]+$", "$comment": "Also enforce common path identity, reserved paths, ancestors and no dot traversal."}
    defs["integer"] = {"type": "string", "pattern": "^(?:0|-?[1-9][0-9]*)$", "maxLength": 4097, "$comment": "At most 4096 digits, excluding sign."}
    def nullable(name): return {"anyOf": [ref(name), null]}
    def record(kind, properties):
        return obj({"kind": {"const": "darkbox-sync-" + kind}, "protocolVersion": {"const": "1.0.0"}, "syncId": ref("id"), "rootSha256": ref("hash"), **properties})
    defs["application"] = obj({"profile": {"type": "string", "minLength": 1}, "formatVersion": {"type": "string", "minLength": 1}})
    defs["file"] = obj({"path": ref("path"), "size": ref("counter"), "sha256": ref("hash")})
    defs["tip"] = obj({"replicaId": ref("id"), "sequence": ref("counter"), "sha256": ref("hash")})
    defs["frontier"] = arr(ref("tip"), uniqueItems=True)
    values = []
    def value(kind, properties): return obj({"type": {"const": kind}, **properties})
    values.append(value("null", {}))
    values.append(value("bool", {"value": boolean}))
    values.append(value("text", {"value": text}))
    values.append(value("integer", {"value": ref("integer")}))
    values.append(value("decimal", {"coefficient": ref("integer"), "exponent": ref("integer")}))
    values.append(value("list", {"values": arr(ref("value"))}))
    values.append(value("map", {"entries": arr(obj({"key": text, "value": ref("value")}))}))
    values.append(value("record", {"collection": ref("name"), "id": ref("dot")}))
    values.append(value("blob", {"sha256": ref("hash"), "size": ref("counter")}))
    defs["value"] = {"oneOf": values, "$comment": "Typed-value depth at most 64; exact decimal normalization and exponent bounds are semantic checks."}
    def operation(name, properties): return obj({"op": {"const": name}, **properties})
    target = {"record": ref("dot"), "field": ref("name")}
    assign = operation("assign", {**target, "present": boolean, "value": ref("value")})
    assign["required"].remove("value")
    assign["allOf"] = [{"if": {"properties": {"present": {"const": True}}}, "then": {"required": ["value"]}, "else": {"not": {"required": ["value"]}}}]
    defs["operation"] = {"oneOf": [
        operation("create", {"collection": ref("name")}), assign,
        operation("set_add", {**target, "value": ref("value")}),
        operation("set_remove", {**target, "value": ref("value"), "tags": arr(ref("dot"), uniqueItems=True)}),
        operation("delete", {"record": ref("dot")}),
        operation("place", {**target, "sequence": ref("name"), "owner": nullable("dot"), "after": nullable("dot")}),
        operation("unplace", target),
    ]}
    defs["transaction"] = record("transaction", {"replicaId": ref("id"), "sequence": ref("counter"), "previous": nullable("hash"), "dependencies": ref("frontier"), "lamport": ref("counter"), "operations": arr(ref("operation"), minItems=1, maxItems=4096)})
    defs["segment"] = record("segment", {"replicaId": ref("id"), "first": ref("counter"), "last": ref("counter"), "transactions": arr(ref("transaction"), minItems=1, maxItems=256)})
    defs["replica"] = record("replica", {"replicaId": ref("id"), "deviceId": ref("id"), "label": {"type": "string", "maxLength": 1024, "$comment": "1024 UTF-8 bytes, not just characters."}})
    defs["receipt"] = record("receipt", {"replicaId": ref("id"), "serial": ref("counter"), "frontier": ref("frontier")})
    defs["domain"] = obj({"kind": {"const": "darkbox-sync-domain"}, "protocolVersion": {"const": "1.0.0"}, "syncId": ref("id"), "packageId": ref("id"), "commonVersion": {"const": "1.5.0"}, "application": ref("application"), "profile": ref("file"), "mapping": ref("file"), "encoding": {"const": "jcs-strings-v1"}, "merge": {"const": "causal-records-v1"}, "security": {"const": "trusted-folder-plaintext"}})
    kinds = enum("null", "bool", "text", "integer", "decimal", "list", "map", "record", "blob")
    sql_name = {"type": "string", "minLength": 1, "maxLength": 255, "$comment": "Also UTF-8 byte length <=255 and no NUL."}
    base_field = {"name": ref("name"), "kind": enum("register", "set"), "columns": arr(sql_name, minItems=1, uniqueItems=True), "codec": ref("name"), "valueTypes": arr(kinds, minItems=1, uniqueItems=True)}
    position = {**base_field, "kind": {"const": "position"}, "valueTypes": {"const": []}, "sequences": arr(ref("name"), minItems=1, uniqueItems=True), "ownerCollections": arr(ref("name"), uniqueItems=True), "allowRootOwner": boolean}
    defs["field"] = {"oneOf": [obj(base_field), obj(position)]}
    defs["mapping"] = obj({"kind": {"const": "darkbox-sync-mapping"}, "mappingVersion": {"const": "1.0.0"}, "application": ref("application"),
        "storage": obj({"mode": enum("single-database", "journal-with-caches"), "databasePath": ref("path"), "reservedPrefix": {"const": "_darkbox_sync_"}}),
        "collections": arr(obj({"name": ref("name"), "table": sql_name, "idColumn": sql_name, "fields": arr(ref("field")), "localColumns": arr(sql_name, uniqueItems=True)})),
        "projection": obj({"id": {"type": "string", "minLength": 1}, "version": {"type": "string", "minLength": 1}, "conflictPolicy": {"const": "quarantine"}, "documentationPath": {"const": "profile/profile.md"}})})
    candidate = obj({"dot": ref("dot"), "lamport": ref("counter"), "present": boolean, "value": ref("value")}, optional=("value",))
    candidate["allOf"] = [{"if": {"properties": {"present": {"const": True}}}, "then": {"required": ["value"]}, "else": {"not": {"required": ["value"]}}}]
    pos_candidate = obj({"dot": ref("dot"), "lamport": ref("counter"), "present": boolean, "node": ref("dot")}, optional=("node",))
    pos_candidate["allOf"] = [{"if": {"properties": {"present": {"const": True}}}, "then": {"required": ["node"]}, "else": {"not": {"required": ["node"]}}}]
    defs["recordState"] = obj({"id": ref("dot"), "collection": ref("name"), "deletedBy": arr(ref("dot"), uniqueItems=True),
        "registers": arr(obj({"field": ref("name"), "candidates": arr(candidate, minItems=1)})),
        "sets": arr(obj({"field": ref("name"), "adds": arr(obj({"dot": ref("dot"), "value": ref("value")})), "removed": arr(ref("dot"), uniqueItems=True)})),
        "positions": arr(obj({"field": ref("name"), "candidates": arr(pos_candidate, minItems=1)}))})
    defs["node"] = obj({"id": ref("dot"), "record": ref("dot"), "field": ref("name"), "sequence": ref("name"), "owner": nullable("dot"), "after": nullable("dot"), "lamport": ref("counter")})
    defs["state"] = record("state", {"frontier": ref("frontier"), "records": arr(ref("recordState")), "nodes": arr(ref("node"))})
    defs["checkpoint"] = record("checkpoint", {"frontier": ref("frontier"), "history": ref("file"), "state": ref("file"), "objects": arr(obj({"sha256": ref("hash"), "size": ref("counter"), "path": ref("path")}))})
    defs["snapshot"] = record("snapshot", {"replicaId": ref("id"), "package": ref("file"), "frontier": ref("frontier"), "stateSha256": ref("hash")})
    common_data = {"syncId": ref("id"), "rootSha256": ref("hash"), "rootPath": {"const": NS + "/root.json"}, "mappingPath": {"const": NS + "/mapping.json"}}
    working = obj({"mode": {"const": "working"}, **common_data, "journalDatabase": ref("path"), "journalSchemaVersion": {"const": "1.0.0"}})
    sealed = obj({"mode": {"const": "sealed"}, **common_data, "checkpointPath": {"const": NS + "/checkpoint.json"}})
    defs["extension"] = obj({"version": {"const": "1.0.0"}, "required": {"const": True}, "data": {"oneOf": [working, sealed]}})
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:darkbox:sync-schema:1.0.0", "title": "Darkbox synchronization extension 1.0.0", "$comment": "Structural validation only. Canonical bytes, identity, counters, causal closure, author-context operation validity, hash/length, sorted uniqueness, complete resource closure and projection require additional checks.", "oneOf": [ref(name) for name in ["domain", "mapping", "replica", "transaction", "segment", "receipt", "state", "checkpoint", "snapshot", "extension"]], "$defs": defs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = ROOT / "archive/1.5.0/docs/darkbox/sync/1.0.0.schema.json"
    expected = (json.dumps(build_schema(), indent=2, ensure_ascii=True) + "\n").encode()
    if path.exists() and path.read_bytes() == expected:
        print("sync 1.0.0: schema matches generator")
        return
    if args.check:
        raise SystemExit("Sync schema differs from generator")
    released = next(v["released"] for v in json.loads((ROOT / "versions.json").read_text())["versions"] if v["version"] == "1.5.0")
    if released:
        raise SystemExit("Published canonical schemas cannot be rewritten")
    path.write_bytes(expected)
    print("sync 1.0.0: schema generated")


if __name__ == "__main__":
    main()
