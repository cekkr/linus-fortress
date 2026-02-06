import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from fortress.storage import load_json_dict, save_json

RECIPE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")

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


class RecipeApplyRequest(BaseModel):
    recipe_name: str
    container_name: Optional[str] = None
    parameters: Optional[Dict[str, str]] = None
    include_dependencies: bool = True
    update_index: bool = True
    dry_run: bool = False
    probe_services: bool = True


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
