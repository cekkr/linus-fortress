import json
import logging
import os
from typing import Any, Dict, Optional


def ensure_parent_dir(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def load_json(path: str, default: Any, label: Optional[str] = None) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        if label:
            logging.error("Failed to load %s from %s: %s", label, path, exc)
        else:
            logging.error("Failed to load data from %s: %s", path, exc)
    return default


def load_json_dict(path: str, label: str, error_message: Optional[str] = None) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
        logging.error("%s store at %s is not a dict; resetting.", label, path)
    except (json.JSONDecodeError, OSError) as exc:
        if error_message:
            logging.error(error_message)
        else:
            logging.error("Failed to load %s store %s: %s", label, path, exc)
    return {}


def save_json(path: str, payload: Any, indent: int = 2) -> None:
    ensure_parent_dir(path)
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=indent)
