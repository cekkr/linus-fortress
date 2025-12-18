import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


RECIPE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


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


def validate_recipe_name(name: str) -> None:
    if not name or not RECIPE_NAME_PATTERN.match(name):
        raise ValueError("Recipe name must be 1-64 chars using letters, digits, ., _, or -")


def ensure_parent_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def load_recipes(path: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
        logging.error("Recipe store at %s is not a dict; resetting.", path)
    except (json.JSONDecodeError, OSError) as exc:
        logging.error("Failed to load recipe store %s: %s", path, exc)
    return {}


def save_recipes(path: str, recipes: Dict[str, Dict[str, Any]]) -> None:
    ensure_parent_dir(path)
    with open(path, "w") as fh:
        json.dump(recipes, fh, indent=2)


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
