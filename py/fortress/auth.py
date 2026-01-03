import logging
from typing import Any, Callable, Dict, List, Optional

from fastapi import HTTPException


DEFAULT_API_SECRET = "CHANGE_THIS_TO_A_VERY_LONG_RANDOM_STRING"


def resolve_master_key(api_secret_key: Optional[str], default_secret: str = DEFAULT_API_SECRET) -> Optional[str]:
    if not api_secret_key:
        return None
    key = api_secret_key.strip()
    if not key or key == default_secret:
        return None
    return key


def mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}...{token[-4:]}"


def verify_token(
    x_api_key: Optional[str],
    x_user_token: Optional[str] = None,
    required_permission: Optional[str] = None,
    *,
    master_key: Optional[str],
    load_users: Callable[[], Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    """Validate access either via master API key or delegated user token."""
    if master_key and x_api_key and x_api_key == master_key:
        return {"actor": "admin", "permissions": ["*"], "allowed_containers": None}

    if x_user_token:
        users = load_users()
        record = users.get(x_user_token)
        if not record:
            logging.warning("Unknown API user token attempted.")
            raise HTTPException(status_code=403, detail="Invalid API token")

        permissions = record.get("permissions", [])
        if required_permission and required_permission not in permissions and "*" not in permissions:
            logging.warning("API user lacks permission %s", required_permission)
            raise HTTPException(status_code=403, detail="Permission denied for this API user")

        return {
            "actor": record.get("username", "api-user"),
            "permissions": permissions,
            "allowed_containers": record.get("allowed_containers"),
        }

    logging.warning("Unauthorized access attempt.")
    raise HTTPException(status_code=403, detail="Invalid authentication headers")


def enforce_container_scope(auth_context: Dict[str, Any], container_name: str) -> None:
    allowed = auth_context.get("allowed_containers")
    if allowed and container_name not in allowed:
        logging.warning(
            "User %s attempted to access container %s without scope.",
            auth_context.get("actor"),
            container_name,
        )
        raise HTTPException(status_code=403, detail=f"Container {container_name} not in allowed scope")


def enforce_container_scopes(auth_context: Dict[str, Any], containers: List[str]) -> None:
    for container in containers:
        enforce_container_scope(auth_context, container)
