import hashlib
import json
import os
import shutil
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from fortress.storage import ensure_parent_dir, load_json, save_json


DEFAULT_SCHEMA_VERSION = "1"
LOCK_FILENAME = "migrations.lock"
VERSIONS_FILENAME = "versions.json"
LEDGER_FILENAME = "ledger.jsonl"


@dataclass
class MigrationPlanEntry:
    store: str
    from_schema: Optional[str]
    to_schema: str
    actions: List[str]


def _sha256_bytes(payload: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(payload)
    return digest.hexdigest()


def _sha256_file(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        return _sha256_bytes(fh.read())


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _build_patch_id() -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"patch-{stamp}"


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _acquire_lock(lock_path: str) -> int:
    ensure_parent_dir(lock_path)
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        return fd
    except FileExistsError:
        raise RuntimeError("Migration lock already held")


def _release_lock(lock_path: str, fd: Optional[int]) -> None:
    try:
        if fd is not None:
            os.close(fd)
        if os.path.exists(lock_path):
            os.unlink(lock_path)
    except OSError:
        pass


def load_schema_registry(schema_dir: str) -> Dict[str, Dict[str, Any]]:
    registry: Dict[str, Dict[str, Any]] = {}
    if not os.path.isdir(schema_dir):
        return registry
    for filename in sorted(os.listdir(schema_dir)):
        if not filename.endswith(".json"):
            continue
        path = os.path.join(schema_dir, filename)
        try:
            with open(path, "r") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        store = payload.get("store") or filename[: -len(".json")]
        registry[store] = payload
    return registry


def _schema_hash(schema: Dict[str, Any]) -> str:
    encoded = json.dumps(schema, sort_keys=True).encode()
    return _sha256_bytes(encoded)


def _load_versions(migrations_dir: str) -> Dict[str, str]:
    path = os.path.join(migrations_dir, VERSIONS_FILENAME)
    return load_json(path, {}, label="Migration versions")


def _save_versions(migrations_dir: str, versions: Dict[str, str]) -> None:
    path = os.path.join(migrations_dir, VERSIONS_FILENAME)
    save_json(path, versions)


def _append_ledger(migrations_dir: str, entry: Dict[str, Any]) -> None:
    ensure_parent_dir(os.path.join(migrations_dir, LEDGER_FILENAME))
    path = os.path.join(migrations_dir, LEDGER_FILENAME)
    with open(path, "a") as fh:
        fh.write(json.dumps(entry))
        fh.write("\n")


def load_ledger_entries(migrations_dir: str) -> List[Dict[str, Any]]:
    path = os.path.join(migrations_dir, LEDGER_FILENAME)
    if not os.path.exists(path):
        return []
    entries: List[Dict[str, Any]] = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def _known_fields(schema: Dict[str, Any]) -> List[str]:
    fields = schema.get("fields")
    if isinstance(fields, list) and fields:
        return [str(value) for value in fields]
    defaults = schema.get("defaults", {})
    if isinstance(defaults, dict):
        return list(defaults.keys())
    return []


def _apply_aliases(record: Dict[str, Any], aliases: Dict[str, str]) -> Tuple[Dict[str, Any], List[str]]:
    actions: List[str] = []
    updated = dict(record)
    legacy: Dict[str, Any] = dict(updated.get("_legacy", {})) if isinstance(updated.get("_legacy"), dict) else {}
    for alias, target in aliases.items():
        if alias not in updated:
            continue
        if target in updated:
            legacy[alias] = updated.pop(alias)
            actions.append(f"alias:{alias}->legacy")
        else:
            updated[target] = updated.pop(alias)
            actions.append(f"alias:{alias}->{target}")
    if legacy:
        updated["_legacy"] = legacy
    return updated, actions


def _apply_defaults(record: Dict[str, Any], defaults: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    actions: List[str] = []
    updated = dict(record)
    for key, value in defaults.items():
        if key not in updated or updated[key] is None:
            updated[key] = value
            actions.append(f"default:{key}")
    return updated, actions


def _preserve_unknown_fields(record: Dict[str, Any], allowed: List[str], prune_unknown: bool) -> Tuple[Dict[str, Any], List[str]]:
    actions: List[str] = []
    if not allowed:
        return record, actions
    updated = dict(record)
    allowed_set = set(allowed) | {"_legacy"}
    unknown = {key: value for key, value in updated.items() if key not in allowed_set}
    if not unknown:
        return updated, actions
    for key in unknown:
        updated.pop(key, None)
    if not prune_unknown:
        legacy = updated.get("_legacy")
        if not isinstance(legacy, dict):
            legacy = {}
        legacy.update(unknown)
        updated["_legacy"] = legacy
        actions.append(f"legacy:{len(unknown)}")
    else:
        actions.append(f"prune:{len(unknown)}")
    return updated, actions


def migrate_record(record: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    actions: List[str] = []
    updated = dict(record)
    aliases = schema.get("aliases") or {}
    if isinstance(aliases, dict):
        updated, alias_actions = _apply_aliases(updated, aliases)
        actions.extend(alias_actions)
    defaults = schema.get("defaults") or {}
    if isinstance(defaults, dict):
        updated, default_actions = _apply_defaults(updated, defaults)
        actions.extend(default_actions)
    prune_unknown = bool(schema.get("prune_unknown", False))
    updated, legacy_actions = _preserve_unknown_fields(updated, _known_fields(schema), prune_unknown)
    actions.extend(legacy_actions)
    return updated, actions


def migrate_store_payload(
    payload: Any,
    schema: Dict[str, Any],
) -> Tuple[Any, List[str], int]:
    actions: List[str] = []
    changed_records = 0
    record_type = schema.get("record_type", "mapping")
    if record_type == "list" and isinstance(payload, list):
        updated_list = []
        for record in payload:
            if not isinstance(record, dict):
                updated_list.append(record)
                continue
            migrated, changes = migrate_record(record, schema)
            if changes:
                changed_records += 1
                actions.extend(changes)
            updated_list.append(migrated)
        return updated_list, actions, changed_records
    if isinstance(payload, dict):
        updated_map = dict(payload)
        for key, record in payload.items():
            if not isinstance(record, dict):
                continue
            migrated, changes = migrate_record(record, schema)
            if changes:
                changed_records += 1
                actions.extend(changes)
            updated_map[key] = migrated
        return updated_map, actions, changed_records
    return payload, actions, changed_records


def _summarize_actions(actions: List[str], changed_records: int) -> List[str]:
    summary: Dict[str, int] = {}
    for action in actions:
        summary[action] = summary.get(action, 0) + 1
    rendered = [f"{key}={value}" for key, value in sorted(summary.items())]
    rendered.append(f"records_changed={changed_records}")
    return rendered


class MigrationEngine:
    def __init__(self, schema_dir: str, migrations_dir: str, store_paths: Dict[str, str]):
        self.schema_dir = schema_dir
        self.migrations_dir = migrations_dir
        self.store_paths = store_paths

    def _schemas(self) -> Dict[str, Dict[str, Any]]:
        return load_schema_registry(self.schema_dir)

    def _default_payload(self, schema: Dict[str, Any]) -> Any:
        if schema.get("record_type") == "list":
            return []
        return {}

    def status(self) -> Dict[str, Any]:
        schemas = self._schemas()
        versions = _load_versions(self.migrations_dir)
        stores_status = []
        pending = False
        for store, schema in schemas.items():
            target_schema = str(schema.get("schema_version", DEFAULT_SCHEMA_VERSION))
            current_schema = versions.get(store)
            store_pending = current_schema != target_schema
            if current_schema is None:
                store_pending = True
            pending = pending or store_pending
            stores_status.append(
                {
                    "store": store,
                    "current_schema": current_schema,
                    "target_schema": target_schema,
                    "pending": store_pending,
                    "schema_hash": _schema_hash(schema),
                }
            )
        latest_patch = None
        entries = load_ledger_entries(self.migrations_dir)
        if entries:
            latest_patch = entries[-1].get("patch_id")
        return {
            "current_version": versions.get("_global"),
            "pending": pending,
            "latest_patch": latest_patch,
            "stores": stores_status,
        }

    def plan(self, stores: Optional[List[str]] = None) -> List[MigrationPlanEntry]:
        schemas = self._schemas()
        versions = _load_versions(self.migrations_dir)
        planned: List[MigrationPlanEntry] = []
        for store, schema in schemas.items():
            if stores and store not in stores:
                continue
            target_schema = str(schema.get("schema_version", DEFAULT_SCHEMA_VERSION))
            current_schema = versions.get(store)
            if current_schema == target_schema:
                continue
            payload = load_json(self.store_paths.get(store, ""), self._default_payload(schema), label=store)
            migrated, actions, changed_records = migrate_store_payload(payload, schema)
            summary = _summarize_actions(actions, changed_records)
            if migrated == payload and not summary:
                summary = ["noop"]
            planned.append(
                MigrationPlanEntry(
                    store=store,
                    from_schema=current_schema,
                    to_schema=target_schema,
                    actions=summary,
                )
            )
        return planned

    def apply(self, stores: Optional[List[str]] = None, dry_run: bool = False, backup: bool = True) -> Dict[str, Any]:
        schemas = self._schemas()
        versions = _load_versions(self.migrations_dir)
        lock_path = os.path.join(self.migrations_dir, LOCK_FILENAME)
        lock_fd = None
        if not dry_run:
            _ensure_dir(self.migrations_dir)
            lock_fd = _acquire_lock(lock_path)
        patch_id = _build_patch_id()
        applied: List[str] = []
        backups: List[str] = []
        try:
            for store, schema in schemas.items():
                if stores and store not in stores:
                    continue
                target_schema = str(schema.get("schema_version", DEFAULT_SCHEMA_VERSION))
                current_schema = versions.get(store)
                if current_schema == target_schema:
                    continue
                path = self.store_paths.get(store)
                payload = load_json(path or "", self._default_payload(schema), label=store)
                migrated, actions, changed_records = migrate_store_payload(payload, schema)
                summary = _summarize_actions(actions, changed_records)
                backup_path = None
                checksum_before = _sha256_file(path) if path else None
                checksum_after = checksum_before
                if not dry_run:
                    if backup and path and os.path.exists(path):
                        backup_path = os.path.join(self.migrations_dir, f"{store}-{patch_id}.bak")
                        ensure_parent_dir(backup_path)
                        shutil.copy2(path, backup_path)
                        backups.append(backup_path)
                    if path and migrated != payload:
                        save_json(path, migrated)
                        checksum_after = _sha256_file(path)
                    versions[store] = target_schema
                    versions["_global"] = patch_id
                    _save_versions(self.migrations_dir, versions)
                    entry = {
                        "patch_id": patch_id,
                        "store": store,
                        "from_schema": current_schema,
                        "to_schema": target_schema,
                        "actions": summary,
                        "checksum_before": checksum_before,
                        "checksum_after": checksum_after,
                        "backup_path": backup_path,
                        "applied_at": _now_iso(),
                    }
                    _append_ledger(self.migrations_dir, entry)
                applied.append(store)
        finally:
            if not dry_run:
                _release_lock(lock_path, lock_fd)
        return {"message": "Migration apply complete", "patch_id": patch_id, "applied": applied, "backups": backups}

    def rollback(self, patch_id: str, dry_run: bool = False) -> Dict[str, Any]:
        entries = [entry for entry in load_ledger_entries(self.migrations_dir) if entry.get("patch_id") == patch_id]
        if not entries:
            raise RuntimeError("Patch id not found in ledger")
        lock_path = os.path.join(self.migrations_dir, LOCK_FILENAME)
        lock_fd = None
        if not dry_run:
            _ensure_dir(self.migrations_dir)
            lock_fd = _acquire_lock(lock_path)
        restored: List[str] = []
        missing_backups: List[str] = []
        checksum_mismatches: List[str] = []
        try:
            versions = _load_versions(self.migrations_dir)
            for entry in entries:
                backup_path = entry.get("backup_path")
                store = entry.get("store")
                if not store:
                    continue
                expected = entry.get("checksum_before")
                if not backup_path or not os.path.exists(backup_path):
                    if expected:
                        missing_backups.append(store)
                    continue
                if expected:
                    backup_checksum = _sha256_file(backup_path)
                    if backup_checksum != expected:
                        checksum_mismatches.append(store)
            if missing_backups or checksum_mismatches:
                if dry_run:
                    return {
                        "message": "Rollback dry-run",
                        "restored": restored,
                        "missing_backups": sorted(set(missing_backups)),
                        "checksum_mismatch": sorted(set(checksum_mismatches)),
                    }
                missing = ", ".join(sorted(set(missing_backups))) if missing_backups else ""
                mismatched = ", ".join(sorted(set(checksum_mismatches))) if checksum_mismatches else ""
                raise RuntimeError(f"Rollback blocked (missing_backups={missing} checksum_mismatch={mismatched})")
            for entry in entries:
                backup_path = entry.get("backup_path")
                store = entry.get("store")
                if not backup_path or not store:
                    continue
                target_path = self.store_paths.get(store)
                if not target_path:
                    continue
                if not dry_run:
                    ensure_parent_dir(target_path)
                    shutil.copy2(backup_path, target_path)
                    expected = entry.get("checksum_before")
                    if expected:
                        restored_checksum = _sha256_file(target_path)
                        if restored_checksum != expected:
                            raise RuntimeError(f"Checksum mismatch after restore for {store}")
                    versions[store] = entry.get("from_schema")
                    versions["_global"] = f"rollback-{patch_id}"
                    _save_versions(self.migrations_dir, versions)
                    _append_ledger(
                        self.migrations_dir,
                        {
                            "patch_id": f"rollback-{patch_id}",
                            "store": store,
                            "from_schema": entry.get("to_schema"),
                            "to_schema": entry.get("from_schema"),
                            "actions": ["rollback"],
                            "backup_path": backup_path,
                            "applied_at": _now_iso(),
                        },
                    )
                restored.append(store)
        finally:
            if not dry_run:
                _release_lock(lock_path, lock_fd)
        return {"message": "Rollback complete", "restored": restored}
