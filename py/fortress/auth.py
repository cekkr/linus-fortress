import hashlib
import hmac
import logging
from datetime import datetime, timezone
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


AUTH_CHALLENGE_HEADERS = {"WWW-Authenticate": 'ApiKey header="X-API-Key", UserToken header="X-User-Token"'}


def _unauthenticated(detail: str) -> HTTPException:
    """401: the caller did not present a valid, unexpired credential."""
    return HTTPException(status_code=401, detail=detail, headers=dict(AUTH_CHALLENGE_HEADERS))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_expiry(value: Any) -> Optional[datetime]:
    """Parse a stored ``expires_at`` (ISO-8601) into an aware UTC datetime.

    ``None``/empty means "never expires". Naive timestamps are treated as UTC.
    Raises ``ValueError`` on anything unparseable so a corrupt record fails closed.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError(f"unsupported expires_at value: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_expiry(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_token_expired(record: Dict[str, Any], now: Optional[datetime] = None) -> bool:
    try:
        expires_at = parse_expiry(record.get("expires_at"))
    except (TypeError, ValueError):
        return True
    if expires_at is None:
        return False
    return (now or _utcnow()) >= expires_at


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
    now: Optional[Callable[[], datetime]] = None,
) -> Dict[str, Any]:
    """Validate access either via master API key or delegated user token (typed tokens supported).

    Status codes: **401** when no credential, an unknown credential, or an expired token is presented;
    **403** when the credential is valid but lacks the required permission (or container scope).
    """
    x_api_key, x_user_token = normalize_auth_headers(x_api_key, x_user_token)
    if master_key and x_api_key and hmac.compare_digest(x_api_key.encode("utf-8"), master_key.encode("utf-8")):
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
            raise _unauthenticated("Invalid API token")
        if is_token_expired(record, (now or _utcnow)()):
            logging.warning("Expired API user token attempted (%s).", token_fingerprint(x_user_token))
            raise _unauthenticated("API token expired")

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
    if x_api_key:
        raise _unauthenticated("Invalid API key")
    raise _unauthenticated("Authentication required")


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
