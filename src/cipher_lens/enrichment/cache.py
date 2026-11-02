# DECISION: Cache entries use SQLite with an explicit expires_at epoch timestamp to support TTL eviction and persistent offline queries.
"""SQLite-backed key-value cache with TTL expiration."""

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class SqliteTtlCache:
    """Persistent SQLite cache with automatic TTL expiration."""

    def __init__(self, db_path: Path | str = "local_data/enrichment_cache.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS kv_cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def get(self, key: str) -> dict[str, Any] | None:
        """Retrieves a cached dictionary value if it has not expired."""
        now = time.time()
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value, expires_at FROM kv_cache WHERE key = ?",
                (key,),
            )
            row = cursor.fetchone()
            if row is None:
                return None

            val_text, expires_at = row
            if now > expires_at:
                cursor.execute("DELETE FROM kv_cache WHERE key = ?", (key,))
                conn.commit()
                return None

            try:
                return json.loads(val_text)
            except Exception:
                return None

    def set(self, key: str, value: dict[str, Any], ttl_seconds: float = 86400.0) -> None:
        """Stores a JSON-serializable dictionary with an expiration TTL."""
        now = time.time()
        expires_at = now + ttl_seconds
        val_text = json.dumps(value)
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO kv_cache (key, value, expires_at, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    expires_at = excluded.expires_at,
                    created_at = excluded.created_at
                """,
                (key, val_text, expires_at, now),
            )
            conn.commit()

    def delete(self, key: str) -> None:
        """Deletes a key from the cache."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM kv_cache WHERE key = ?", (key,))
            conn.commit()

    def clear(self) -> None:
        """Clears all entries from the cache."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM kv_cache")
            conn.commit()
