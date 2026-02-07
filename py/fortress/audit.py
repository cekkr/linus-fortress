import json
import os
import sqlite3
import threading
import logging
from typing import Optional, Dict, Any


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
            with sqlite3.connect(self.db_path) as conn:
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
                        status TEXT
                    )
                    """
                )
        except (OSError, sqlite3.Error) as exc:
            logging.error("Unable to initialize command log database: %s", exc)

    def log(
        self,
        actor: str,
        endpoint: str,
        category: str,
        action: str,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success",
    ):
        payload = json.dumps(details, default=str) if details is not None else None
        try:
            with self._lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute(
                        """
                        INSERT INTO command_log (actor, endpoint, category, action, target, details, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (actor, endpoint, category, action, target, payload, status),
                    )
        except (OSError, sqlite3.Error) as exc:
            logging.error("Failed to persist audit log entry: %s", exc)
