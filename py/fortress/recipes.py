import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

from fortress.storage import load_json_dict, save_json

RECIPE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
RECIPE_BUNDLE_FORMAT = "fortress.recipe-bundle.v1"
RECIPE_BUNDLE_CHECKSUM_ALGORITHM = "sha256"
RECIPE_BUNDLE_SIGNATURE_ALGORITHM = "hmac-sha256"
RECIPE_VERSION_BUMPS = {"major", "minor", "patch", "none"}
RECIPE_MUTABLE_FIELDS = {
    "description",
    "dependencies",
    "packages",
    "commands",
    "parameters",
    "required_parameters",
}

APACHE_CONFIG_CHECK = (
    "if command -v apache2ctl >/dev/null 2>&1; then apache2ctl -t;"
    " elif command -v httpd >/dev/null 2>&1; then httpd -t;"
    ' else echo "apache binary not found"; exit 2; fi'
)
NGINX_CONFIG_CHECK = (
    "if command -v nginx >/dev/null 2>&1; then nginx -t;"
    ' else echo "nginx binary not found"; exit 2; fi'
)
PHP_RUNTIME_CHECK = (
    "if command -v php >/dev/null 2>&1; then php -v >/dev/null 2>&1;"
    ' else echo "php runtime not found"; exit 2; fi'
)
MYSQL_CONFIG_CHECK = (
    "if command -v mysqld >/dev/null 2>&1; then mysqld --verbose --help >/dev/null 2>&1;"
    " elif command -v mariadbd >/dev/null 2>&1; then mariadbd --verbose --help >/dev/null 2>&1;"
    " elif command -v mysql >/dev/null 2>&1; then mysql --help >/dev/null 2>&1;"
    ' else echo "mysql binaries not found"; exit 2; fi'
)
FILEMANAGER_CONFIG_CHECK = (
    "if [ ! -f /var/www/html/filemanager/index.php ]; then"
    ' echo "tinyfilemanager index.php not found"; exit 2;'
    " fi;"
    " if command -v php >/dev/null 2>&1; then"
    " php -l /var/www/html/filemanager/index.php >/dev/null 2>&1;"
    ' else echo "php runtime not found"; exit 2; fi'
)

LAMP_STACK_EXPANSION = ["lamp-apache", "lamp-mysql", "lamp-ftp", "lamp-filemanager"]

LAMP_RECIPE_TARGETS: Dict[str, Dict[str, Any]] = {
    "lamp-apache": {
        "service_keys": ["apache"],
        "service_processes": {"apache": ["apache2", "httpd"]},
        "ports": [80],
        "config_checks": [
            {"id": "apache-config", "name": "Apache config syntax", "command": APACHE_CONFIG_CHECK},
            {"id": "php-runtime", "name": "PHP runtime available", "command": PHP_RUNTIME_CHECK},
        ],
    },
    "lamp-nginx": {
        "service_keys": ["nginx"],
        "service_processes": {"nginx": ["nginx"]},
        "ports": [80],
        "config_checks": [
            {"id": "nginx-config", "name": "Nginx config syntax", "command": NGINX_CONFIG_CHECK},
            {"id": "php-runtime", "name": "PHP runtime available", "command": PHP_RUNTIME_CHECK},
        ],
    },
    "lamp-mysql": {
        "service_keys": ["mysql"],
        "service_processes": {"mysql": ["mysqld", "mariadbd"]},
        "ports": [3306],
        "config_checks": [
            {"id": "mysql-config", "name": "MySQL/MariaDB configuration", "command": MYSQL_CONFIG_CHECK},
        ],
    },
    "lamp-ftp": {
        "service_keys": ["ftp"],
        "service_processes": {"ftp": ["vsftpd"]},
        "ports": [21],
        "config_checks": [],
    },
    "lamp-filemanager": {
        "service_keys": ["filemanager"],
        "service_processes": {},
        "ports": [],
        "config_checks": [
            {"id": "filemanager-php-lint", "name": "Tiny File Manager PHP lint", "command": FILEMANAGER_CONFIG_CHECK},
        ],
    },
}


class RecipeDefinition(BaseModel):
    name: str
    description: Optional[str] = None
    dependencies: List[str] = Field(default_factory=list)
    packages: List[str] = Field(default_factory=list)
    commands: List[str] = Field(default_factory=list)
    parameters: Dict[str, str] = Field(default_factory=dict)
    required_parameters: List[str] = Field(default_factory=list)


class RecipeUpdate(BaseModel):
    description: Optional[str] = None
    dependencies: Optional[List[str]] = None
    packages: Optional[List[str]] = None
    commands: Optional[List[str]] = None
    parameters: Optional[Dict[str, str]] = None
    required_parameters: Optional[List[str]] = None
    version_bump: Optional[Literal["major", "minor", "patch", "none"]] = "patch"
    change_note: Optional[str] = None


class RecipeApplyRequest(BaseModel):
    recipe_name: str
    container_name: Optional[str] = None
    parameters: Optional[Dict[str, str]] = None
    include_dependencies: bool = True
    update_index: bool = True
    dry_run: bool = False
    probe_services: bool = True


class RecipeExportRequest(BaseModel):
    names: Optional[List[str]] = None
    include_history: bool = True
    include_signature: bool = True


class RecipeImportRequest(BaseModel):
    bundle: Dict[str, Any]
    overwrite: bool = False
    preserve_history: bool = True
    require_signature: bool = True


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_iso_timestamp(value: Optional[Any], fallback: Optional[str] = None) -> str:
    if isinstance(value, str):
        raw = value.strip()
        if raw:
            candidate = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
            try:
                parsed = datetime.fromisoformat(candidate)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            except ValueError:
                pass
    return fallback or _utc_now()


def _normalize_string_list(values: Any, unique: bool = False) -> List[str]:
    if not isinstance(values, list):
        return []
    normalized: List[str] = []
    seen: set[str] = set()
    for item in values:
        value = str(item).strip()
        if not value:
            continue
        if unique:
            if value in seen:
                continue
            seen.add(value)
        normalized.append(value)
    return normalized


def _normalize_string_dict(values: Any) -> Dict[str, str]:
    if not isinstance(values, dict):
        return {}
    normalized: Dict[str, str] = {}
    for key, value in values.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        normalized[key_str] = "" if value is None else str(value)
    return normalized


def normalize_semver(version: Optional[Any], default: str = "1.0.0") -> str:
    candidate = default if version is None else str(version).strip()
    if not candidate:
        candidate = default
    if not SEMVER_PATTERN.match(candidate):
        raise ValueError("Version must follow semantic versioning (major.minor.patch)")
    return candidate


def bump_semver(version: str, bump: str = "patch") -> str:
    base = normalize_semver(version)
    operation = (bump or "patch").strip().lower()
    if operation not in RECIPE_VERSION_BUMPS:
        raise ValueError("version_bump must be one of: major, minor, patch, none")
    major, minor, patch = [int(part) for part in base.split(".")]
    if operation == "major":
        return f"{major + 1}.0.0"
    if operation == "minor":
        return f"{major}.{minor + 1}.0"
    if operation == "patch":
        return f"{major}.{minor}.{patch + 1}"
    return base


def build_recipe_history_entry(
    action: str,
    to_version: str,
    from_version: Optional[str] = None,
    changed_fields: Optional[List[str]] = None,
    note: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "timestamp": _normalize_iso_timestamp(timestamp),
        "action": str(action or "update").strip() or "update",
        "to_version": normalize_semver(to_version),
    }
    if from_version:
        try:
            entry["from_version"] = normalize_semver(from_version)
        except ValueError:
            pass
    normalized_fields = _normalize_string_list(changed_fields or [], unique=True)
    if normalized_fields:
        entry["changed_fields"] = sorted(normalized_fields)
    if note is not None:
        note_text = str(note).strip()
        if note_text:
            entry["note"] = note_text
    return entry


def normalize_recipe_history(history: Any) -> List[Dict[str, Any]]:
    if not isinstance(history, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for item in history:
        if not isinstance(item, dict):
            continue
        to_version_raw = item.get("to_version") or item.get("version")
        if to_version_raw is None:
            continue
        try:
            to_version = normalize_semver(to_version_raw)
        except ValueError:
            continue
        from_version = item.get("from_version")
        from_version_normalized: Optional[str] = None
        if from_version is not None:
            try:
                from_version_normalized = normalize_semver(from_version)
            except ValueError:
                from_version_normalized = None
        entry: Dict[str, Any] = {
            "timestamp": _normalize_iso_timestamp(item.get("timestamp")),
            "action": str(item.get("action") or "update").strip() or "update",
            "to_version": to_version,
        }
        if from_version_normalized:
            entry["from_version"] = from_version_normalized
        fields = _normalize_string_list(item.get("changed_fields"), unique=True)
        if fields:
            entry["changed_fields"] = sorted(fields)
        note = item.get("note")
        if isinstance(note, str) and note.strip():
            entry["note"] = note.strip()
        normalized.append(entry)
    normalized.sort(key=lambda entry: entry.get("timestamp", ""))
    return normalized


def merge_recipe_histories(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen: set[Tuple[Any, ...]] = set()
    for entry in existing + incoming:
        key = (
            entry.get("timestamp"),
            entry.get("action"),
            entry.get("from_version"),
            entry.get("to_version"),
            tuple(entry.get("changed_fields", [])),
            entry.get("note"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(entry)
    merged.sort(key=lambda item: item.get("timestamp", ""))
    return merged


def normalize_recipe_record(
    name: str,
    recipe: Dict[str, Any],
    init_history_action: Optional[str] = None,
    init_history_note: Optional[str] = None,
) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {
        "name": name,
        "description": str(recipe.get("description")) if recipe.get("description") is not None else None,
        "dependencies": _normalize_string_list(recipe.get("dependencies"), unique=True),
        "packages": _normalize_string_list(recipe.get("packages")),
        "commands": _normalize_string_list(recipe.get("commands")),
        "parameters": _normalize_string_dict(recipe.get("parameters")),
        "required_parameters": _normalize_string_list(recipe.get("required_parameters"), unique=True),
    }
    try:
        version = normalize_semver(recipe.get("version"), default="1.0.0")
    except ValueError:
        version = "1.0.0"
    created_at = _normalize_iso_timestamp(recipe.get("created_at"))
    updated_at = _normalize_iso_timestamp(recipe.get("updated_at"), fallback=created_at)
    history = normalize_recipe_history(recipe.get("history"))
    if not history and init_history_action:
        history = [build_recipe_history_entry(init_history_action, to_version=version, note=init_history_note, timestamp=updated_at)]
    normalized["version"] = version
    normalized["created_at"] = created_at
    normalized["updated_at"] = updated_at
    normalized["history"] = history
    return normalized


def create_recipe_record(
    recipe: Dict[str, Any],
    action: str = "create",
    note: Optional[str] = None,
) -> Dict[str, Any]:
    name = str(recipe.get("name", "")).strip()
    validate_recipe_name(name)
    return normalize_recipe_record(name, recipe, init_history_action=action, init_history_note=note)


def update_recipe_record(
    name: str,
    existing: Dict[str, Any],
    updates: Dict[str, Any],
    version_bump: str = "patch",
    action: str = "update",
    note: Optional[str] = None,
) -> Tuple[Dict[str, Any], List[str]]:
    current = normalize_recipe_record(
        name,
        existing,
        init_history_action="metadata_initialized",
        init_history_note="Recipe metadata was backfilled",
    )
    candidate = dict(current)
    changed_fields: List[str] = []
    for field, value in updates.items():
        if field not in RECIPE_MUTABLE_FIELDS:
            continue
        if field == "description":
            normalized_value = str(value) if value is not None else None
        elif field in {"dependencies", "required_parameters"}:
            normalized_value = _normalize_string_list(value, unique=True)
        elif field in {"packages", "commands"}:
            normalized_value = _normalize_string_list(value)
        elif field == "parameters":
            normalized_value = _normalize_string_dict(value)
        else:
            normalized_value = value
        if candidate.get(field) != normalized_value:
            changed_fields.append(field)
            candidate[field] = normalized_value
    if not changed_fields and not note:
        return candidate, []

    previous_version = current["version"]
    next_version = previous_version
    if changed_fields:
        next_version = bump_semver(previous_version, version_bump)
    timestamp = _utc_now()
    history = list(current.get("history", []))
    history.append(
        build_recipe_history_entry(
            action=action,
            from_version=previous_version,
            to_version=next_version,
            changed_fields=changed_fields,
            note=note,
            timestamp=timestamp,
        )
    )
    candidate["version"] = next_version
    candidate["created_at"] = current.get("created_at", timestamp)
    candidate["updated_at"] = timestamp
    candidate["history"] = history
    return candidate, sorted(changed_fields)


def strip_recipe_history(record: Dict[str, Any]) -> Dict[str, Any]:
    stripped = dict(record)
    stripped["history"] = []
    return stripped


def _bundle_payload_for_digest(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "format": bundle.get("format"),
        "exported_at": bundle.get("exported_at"),
        "count": bundle.get("count"),
        "recipes": bundle.get("recipes", []),
    }


def _bundle_checksum(bundle: Dict[str, Any]) -> str:
    payload = _bundle_payload_for_digest(bundle)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _bundle_signature(checksum: str, signing_key: str) -> str:
    return hmac.new(signing_key.encode(), checksum.encode(), hashlib.sha256).hexdigest()


def build_recipe_export_bundle(
    recipes: Dict[str, Dict[str, Any]],
    names: Optional[List[str]] = None,
    include_history: bool = True,
    signing_key: Optional[str] = None,
) -> Dict[str, Any]:
    if names:
        selected_names = sorted({str(name).strip() for name in names if str(name).strip()})
    else:
        selected_names = sorted(recipes.keys())
    exported: List[Dict[str, Any]] = []
    for name in selected_names:
        record = recipes.get(name)
        if not record:
            raise ValueError(f"Recipe '{name}' not found")
        normalized = normalize_recipe_record(
            name,
            record,
            init_history_action="metadata_initialized",
            init_history_note="Recipe metadata was backfilled",
        )
        if not include_history:
            normalized = strip_recipe_history(normalized)
        exported.append(normalized)
    bundle = {
        "format": RECIPE_BUNDLE_FORMAT,
        "exported_at": _utc_now(),
        "count": len(exported),
        "recipes": exported,
        "checksum_algorithm": RECIPE_BUNDLE_CHECKSUM_ALGORITHM,
    }
    bundle["checksum"] = _bundle_checksum(bundle)
    if signing_key:
        bundle["signature_algorithm"] = RECIPE_BUNDLE_SIGNATURE_ALGORITHM
        bundle["signature"] = _bundle_signature(bundle["checksum"], signing_key)
    return bundle


def verify_recipe_bundle(
    bundle: Dict[str, Any],
    signing_key: Optional[str] = None,
    require_signature: bool = True,
) -> Dict[str, Any]:
    if not isinstance(bundle, dict):
        raise ValueError("Bundle must be an object")
    checksum_algorithm = str(bundle.get("checksum_algorithm") or RECIPE_BUNDLE_CHECKSUM_ALGORITHM).strip().lower()
    if checksum_algorithm != RECIPE_BUNDLE_CHECKSUM_ALGORITHM:
        raise ValueError(f"Unsupported checksum algorithm '{checksum_algorithm}'")
    checksum = str(bundle.get("checksum", "")).strip()
    if not checksum:
        raise ValueError("Bundle checksum is missing")
    expected_checksum = _bundle_checksum(bundle)
    if not hmac.compare_digest(checksum, expected_checksum):
        raise ValueError("Bundle checksum mismatch")

    signature = str(bundle.get("signature", "")).strip()
    signature_algorithm = str(bundle.get("signature_algorithm") or RECIPE_BUNDLE_SIGNATURE_ALGORITHM).strip().lower()
    if signature and signature_algorithm != RECIPE_BUNDLE_SIGNATURE_ALGORITHM:
        raise ValueError(f"Unsupported signature algorithm '{signature_algorithm}'")
    if require_signature and not signature:
        raise ValueError("Bundle signature required")
    if signature:
        if not signing_key:
            raise ValueError("Recipe bundle signing key is not configured on this server")
        expected_signature = _bundle_signature(expected_checksum, signing_key)
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Bundle signature verification failed")
    return {"checksum": expected_checksum, "signed": bool(signature)}


def extract_recipe_bundle(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(bundle, dict):
        raise ValueError("Bundle must be an object")
    bundle_format = bundle.get("format")
    if bundle_format and bundle_format != RECIPE_BUNDLE_FORMAT:
        raise ValueError(f"Unsupported bundle format '{bundle_format}'")
    raw_recipes = bundle.get("recipes")
    records: Dict[str, Dict[str, Any]] = {}
    if isinstance(raw_recipes, dict):
        iterator = []
        for recipe_name, record in raw_recipes.items():
            if not isinstance(record, dict):
                raise ValueError(f"Recipe '{recipe_name}' payload must be an object")
            payload = dict(record)
            payload.setdefault("name", str(recipe_name))
            iterator.append(payload)
    elif isinstance(raw_recipes, list):
        iterator = []
        for item in raw_recipes:
            if not isinstance(item, dict):
                raise ValueError("Recipe bundle entries must be objects")
            iterator.append(dict(item))
    else:
        raise ValueError("Bundle must include 'recipes' as an array or object")

    count_value = bundle.get("count")
    if count_value is not None:
        try:
            expected_count = int(count_value)
        except (TypeError, ValueError):
            raise ValueError("Bundle count must be an integer")
        if expected_count != len(iterator):
            raise ValueError("Bundle count does not match recipe entries")

    for item in iterator:
        name = str(item.get("name", "")).strip()
        validate_recipe_name(name)
        records[name] = item
    return records


def prepare_import_recipe_record(
    name: str,
    incoming: Dict[str, Any],
    existing: Optional[Dict[str, Any]] = None,
    preserve_history: bool = True,
) -> Dict[str, Any]:
    normalized_incoming = normalize_recipe_record(
        name,
        incoming,
        init_history_action="import",
        init_history_note="Imported from recipe bundle",
    )
    now = _utc_now()
    history: List[Dict[str, Any]]
    if existing:
        normalized_existing = normalize_recipe_record(
            name,
            existing,
            init_history_action="metadata_initialized",
            init_history_note="Recipe metadata was backfilled",
        )
        base_history = list(normalized_existing.get("history", []))
        incoming_history = list(normalized_incoming.get("history", [])) if preserve_history else []
        history = merge_recipe_histories(base_history, incoming_history)
        from_version = normalized_existing.get("version")
        created_at = normalized_existing.get("created_at", now)
        action = "import_overwrite"
    else:
        history = list(normalized_incoming.get("history", [])) if preserve_history else []
        from_version = None
        created_at = normalized_incoming.get("created_at", now)
        action = "import"
    history.append(
        build_recipe_history_entry(
            action=action,
            from_version=from_version,
            to_version=normalized_incoming.get("version", "1.0.0"),
            note="Imported from recipe bundle",
            timestamp=now,
        )
    )
    normalized_incoming["created_at"] = created_at
    normalized_incoming["updated_at"] = now
    normalized_incoming["history"] = history
    if not preserve_history:
        normalized_incoming["history"] = history[-1:]
    return normalized_incoming


def collect_lamp_health_targets(recipe_names: List[str]) -> Dict[str, Any]:
    normalized: List[str] = []
    for recipe in recipe_names:
        candidate = str(recipe or "").strip().lower()
        if candidate in LAMP_RECIPE_TARGETS and candidate not in normalized:
            normalized.append(candidate)
        if candidate == "lamp-stack":
            for expanded in LAMP_STACK_EXPANSION:
                if expanded not in normalized:
                    normalized.append(expanded)
    if not normalized:
        return {
            "detected": False,
            "recipes": [],
            "service_keys": [],
            "service_processes": [],
            "ports": [],
            "config_checks": [],
        }

    service_keys: List[str] = []
    service_processes: Dict[str, List[str]] = {}
    ports: List[int] = []
    config_checks: List[Dict[str, str]] = []
    check_ids: set[str] = set()
    for recipe in normalized:
        target = LAMP_RECIPE_TARGETS[recipe]
        for key in target.get("service_keys", []):
            if key not in service_keys:
                service_keys.append(key)
        for key, processes in target.get("service_processes", {}).items():
            current = service_processes.setdefault(key, [])
            for process in processes:
                if process not in current:
                    current.append(process)
        for port in target.get("ports", []):
            if port not in ports:
                ports.append(port)
        for check in target.get("config_checks", []):
            check_id = check.get("id")
            if not check_id or check_id in check_ids:
                continue
            check_ids.add(check_id)
            config_checks.append(
                {
                    "id": str(check_id),
                    "name": str(check.get("name", check_id)),
                    "command": str(check.get("command", "")),
                }
            )
    serialized_processes = [
        {"service": key, "processes": value}
        for key, value in service_processes.items()
    ]
    return {
        "detected": True,
        "recipes": normalized,
        "service_keys": service_keys,
        "service_processes": serialized_processes,
        "ports": ports,
        "config_checks": config_checks,
    }


def validate_recipe_name(name: str) -> None:
    if not name or not RECIPE_NAME_PATTERN.match(name):
        raise ValueError("Recipe name must be 1-64 chars using letters, digits, ., _, or -")


def load_recipes(path: str) -> Dict[str, Dict[str, Any]]:
    return load_json_dict(path, label="Recipe")


def save_recipes(path: str, recipes: Dict[str, Dict[str, Any]]) -> None:
    save_json(path, recipes)


def resolve_recipe_plan(
    recipe_name: str,
    recipes: Dict[str, Dict[str, Any]],
    include_dependencies: bool = True,
) -> List[str]:
    if recipe_name not in recipes:
        raise ValueError(f"Recipe '{recipe_name}' not found")
    if not include_dependencies:
        return [recipe_name]
    resolved: List[str] = []
    visiting: set[str] = set()

    def visit(name: str) -> None:
        if name in resolved:
            return
        if name in visiting:
            raise ValueError(f"Circular recipe dependency detected at '{name}'")
        recipe = recipes.get(name)
        if not recipe:
            raise ValueError(f"Missing recipe dependency '{name}'")
        visiting.add(name)
        for dep in recipe.get("dependencies", []):
            visit(dep)
        visiting.remove(name)
        resolved.append(name)

    visit(recipe_name)
    return resolved


def normalize_parameters(params: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not params:
        return {}
    normalized: Dict[str, str] = {}
    for key, value in params.items():
        if value is None:
            normalized[key] = ""
        else:
            normalized[key] = str(value)
    return normalized


def merge_parameters(
    defaults: Dict[str, Any],
    overrides: Dict[str, Any],
    required: List[str],
) -> Dict[str, str]:
    merged = normalize_parameters(defaults)
    merged.update(normalize_parameters(overrides))
    missing = [name for name in required if not merged.get(name)]
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise ValueError(f"Missing required parameters: {missing_list}")
    return merged


def render_template(value: str, params: Dict[str, str], recipe_name: str) -> str:
    def replace(match: re.Match) -> str:
        key = match.group(1)
        if key not in params:
            raise ValueError(f"Missing parameter '{key}' for recipe '{recipe_name}'")
        return params[key]

    return PLACEHOLDER_PATTERN.sub(replace, value)


def build_recipe_execution(
    recipe_name: str,
    recipes: Dict[str, Dict[str, Any]],
    include_dependencies: bool = True,
    overrides: Optional[Dict[str, Any]] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    plan = resolve_recipe_plan(recipe_name, recipes, include_dependencies=include_dependencies)
    override_params = normalize_parameters(overrides)
    steps: List[Dict[str, Any]] = []
    for name in plan:
        recipe = recipes.get(name)
        if not recipe:
            raise ValueError(f"Missing recipe dependency '{name}'")
        params = merge_parameters(recipe.get("parameters", {}), override_params, recipe.get("required_parameters", []))
        packages: List[str] = []
        for package in recipe.get("packages", []):
            rendered = render_template(package, params, name)
            if rendered:
                packages.append(rendered)
        commands: List[str] = []
        for command in recipe.get("commands", []):
            rendered = render_template(command, params, name)
            if rendered:
                commands.append(rendered)
        steps.append({"name": name, "parameters": params, "packages": packages, "commands": commands})
    return plan, steps
