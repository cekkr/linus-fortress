import contextlib
import copy
import fcntl
import json
import logging
import os
import tempfile
import threading
from typing import Any, Callable, Dict, Iterator, Optional

# New stores are created owner-only; existing files keep their current mode.
DEFAULT_STORE_MODE = 0o600

_THREAD_LOCKS: Dict[str, threading.RLock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


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


def _lock_path(path: str) -> str:
    directory, name = os.path.split(os.path.abspath(path))
    return os.path.join(directory, f".{name}.lock")


def _thread_lock(path: str) -> threading.RLock:
    key = os.path.abspath(path)
    with _THREAD_LOCKS_GUARD:
        lock = _THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _THREAD_LOCKS[key] = lock
        return lock


@contextlib.contextmanager
def json_store_lock(path: str) -> Iterator[None]:
    """Exclusive lock for a JSON store across threads and processes.

    Uses an in-process RLock (re-entrant, so ``update_json`` can call
    ``save_json``) plus an ``flock`` on a hidden sidecar ``.<name>.lock`` file.
    """
    ensure_parent_dir(path)
    thread_lock = _thread_lock(path)
    with thread_lock:
        fd = os.open(_lock_path(path), os.O_RDWR | os.O_CREAT, DEFAULT_STORE_MODE)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _atomic_write_json(path: str, payload: Any, indent: int) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    try:
        mode = os.stat(path).st_mode & 0o7777
    except FileNotFoundError:
        mode = DEFAULT_STORE_MODE
    fd, tmp_path = tempfile.mkstemp(prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=indent)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.remove(tmp_path)
        raise
    with contextlib.suppress(OSError):
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def save_json(path: str, payload: Any, indent: int = 2) -> None:
    """Atomically replace ``path`` with ``payload`` (temp file + fsync + rename) under the store lock.

    Readers never observe a truncated/partial file, and a crash mid-write leaves the previous content intact.
    """
    ensure_parent_dir(path)
    with json_store_lock(path):
        _atomic_write_json(path, payload, indent)


def update_json(path: str, default: Any, mutate: Callable[[Any], Any], label: Optional[str] = None, indent: int = 2) -> Any:
    """Locked read-modify-write. ``mutate`` receives the current data and returns the new payload
    (or ``None`` to keep the mutated object). Prevents lost updates between concurrent writers."""
    with json_store_lock(path):
        current = load_json(path, copy.deepcopy(default), label=label)
        result = mutate(current)
        payload = current if result is None else result
        _atomic_write_json(path, payload, indent)
        return payload
