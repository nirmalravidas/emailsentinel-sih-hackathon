"""Tiny SQLite layer. Stores only basic case metadata, not full email content."""
import sqlite3
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

from app import config


@contextmanager
def _connect():
    config.DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                analysis_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                subject TEXT,
                sender TEXT,
                classification TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                probable_origin_ip TEXT
            )
            """
        )


def save_case(record: Dict[str, Any]) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO cases
            (analysis_id, created_at, subject, sender, classification, risk_score, risk_level, probable_origin_ip)
            VALUES (:analysis_id, :created_at, :subject, :sender, :classification, :risk_score, :risk_level, :probable_origin_ip)
            """,
            record,
        )


def list_cases(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
        return [dict(r) for r in rows]


def count_cases() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
