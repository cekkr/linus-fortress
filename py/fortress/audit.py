import json
import os
import sqlite3
import threading
import logging
from contextlib import closing
from pathlib import Path
from typing import Optional, Dict, Any, List


class CommandLogger:
    """Recording layer for API and container activity into SQLite."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_database()

    def _ensure_database(self):
        directory = os.path.dirname(self.db_path)
        try:
            if directory:
                os.makedirs(directory, exist_ok=True)
            # Open existing databases without truncating their history, including on upgrade.
            fd = os.open(self.db_path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            with closing(sqlite3.connect(self.db_path)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS command_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        actor TEXT,
                        endpoint TEXT,
                        category TEXT,
                        action TEXT,
                        target TEXT,
                        details TEXT,
                        status TEXT,
                        request_id TEXT
                    )
                    """
                )
                columns = {column[1] for column in conn.execute("PRAGMA table_info(command_log)")}
                if "request_id" not in columns:
                    conn.execute("ALTER TABLE command_log ADD COLUMN request_id TEXT")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS command_log_request_id ON command_log (request_id)"
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS command_log_tls_renewal_target ON command_log (target, id DESC)
                    WHERE category = 'api' AND action = 'tls_renew' AND target IS NOT NULL
                    """
                )
        except (OSError, sqlite3.Error) as exc:
            logging.error("Unable to initialize command log database: %s", exc)

    def tls_renewal_history(self, cert_name: str) -> Optional[List[Dict[str, Any]]]:
        """Return recent named renewal outcomes, or None if the register is unavailable."""
        try:
            uri = Path(self.db_path).absolute().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as conn:
                rows = conn.execute(
                    """
                    SELECT strftime('%Y-%m-%dT%H:%M:%SZ', timestamp), status, details, request_id
                    FROM command_log
                    WHERE category = 'api' AND action = 'tls_renew' AND target = ?
                    ORDER BY id DESC LIMIT 10
                    """,
                    (cert_name,),
                ).fetchall()
        except sqlite3.Error as exc:
            logging.error("Unable to read TLS renewal history: %s", exc)
            return None

        history = []
        for timestamp, status, details, request_id in rows:
            try:
                metadata = json.loads(details or "{}")
            except ValueError:
                metadata = {}
            history.append({
                "timestamp": timestamp,
                "status": status,
                "dry_run": isinstance(metadata, dict) and metadata.get("dry_run") is True,
                "request_id": request_id,
            })
        return history

    def log(
        self,
        actor: str,
        endpoint: str,
        category: str,
        action: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
        request_id: Optional[str] = None,
    ):
        payload = json.dumps(details, default=str) if details is not None else None
        try:
            with self._lock:
                with closing(sqlite3.connect(self.db_path)) as conn, conn:
                    conn.execute(
                        """
                        INSERT INTO command_log (actor, endpoint, category, action, target, details, status, request_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (actor, endpoint, category, action, target, payload, status, request_id),
                    )
        except (OSError, sqlite3.Error) as exc:
            logging.error("Failed to persist audit log entry: %s", exc)
