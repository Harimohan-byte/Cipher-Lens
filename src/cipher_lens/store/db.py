"""Database connection and lifecycle management for Cipher-Lens."""

import os
import sqlite3
from pathlib import Path

from cipher_lens.store.tables import SCHEMA_STATEMENTS


def default_db_path() -> Path:
    """Returns the default SQLite database path from DB_PATH env var or local_data."""
    return Path(os.environ.get("DB_PATH", "local_data/cipher_lens.db"))


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Opens a SQLite connection with WAL mode and manual transaction control.

    Note: Each thread must establish and use its own connection. SQLite connections
    must not be shared across threads to avoid locking and concurrency conflicts.
    """
    resolved_path = Path(db_path) if db_path is not None else default_db_path()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(resolved_path),
        isolation_level=None,  # Manual transactions
        check_same_thread=True,
    )
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Initializes all schema tables and triggers idempotently."""
    cursor = conn.cursor()
    for statement in SCHEMA_STATEMENTS:
        cursor.execute(statement)
