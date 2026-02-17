import hashlib
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException


DEFAULT_API_SECRET = "CHANGE_THIS_TO_A_VERY_LONG_RANDOM_STRING"
TOKEN_TYPE_ALIASES = {
    "api-key": "api-key",
    "api_key": "api-key",
    "master-key": "api-key",
    "master_key": "api-key",
    "master": "api-key",
    "user-token": "user-token",
    "user_token": "user-token",
    "user": "user-token",
    "delegated": "user-token",
}


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


def parse_prefixed_token(raw: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not raw:
        return None, None
    value = raw.strip()
    if not value:
        return None, None
    if ":" not in value:
        return None, value
    prefix, token = value.split(":", 1)
    prefix = prefix.strip().lower()
    token = token.strip()
    if not token:
        return None, value
    token_type = TOKEN_TYPE_ALIASES.get(prefix)
    if not token_type:
        return None, value
    return token_type, token


def normalize_auth_headers(
    x_api_key: Optional[str],
    x_user_token: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    api_kind, api_token = parse_prefixed_token(x_api_key)
    if api_kind:
        if api_kind == "api-key":
            return api_token, None
        return None, api_token
    user_kind, user_token = parse_prefixed_token(x_user_token)
    if user_kind:
        if user_kind == "api-key":
            return user_token, None
        return None, user_token
    return x_api_key, x_user_token


def token_fingerprint(token: Optional[str]) -> str:
    if not token:
        return "none"
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return digest[:16]


def verify_token(
    x_api_key: Optional[str],
    x_user_token: Optional[str] = None,
    required_permission: Optional[str] = None,
    *,
    master_key: Optional[str],
    load_users: Callable[[], Dict[str, Dict[str, Any]]],
) -> Dict[str, Any]:
    """Validate access either via master API key or delegated user token (typed tokens supported)."""
    x_api_key, x_user_token = normalize_auth_headers(x_api_key, x_user_token)
    if master_key and x_api_key and x_api_key == master_key:
        return {
            "actor": "admin",
            "permissions": ["*"],
            "allowed_containers": None,
            "is_master": True,
            "subject_id": "master",
            "user_record": None,
        }

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
            "is_master": False,
            "subject_id": f"user:{token_fingerprint(x_user_token)}",
            "user_record": record,
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
