from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SentinelDB:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    seen_at TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    host TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    is_new INTEGER NOT NULL DEFAULT 0,
                    suspicious_port INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recorded_at TEXT NOT NULL,
                    path TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT,
                    skipped_large INTEGER NOT NULL DEFAULT 0,
                    is_apk INTEGER NOT NULL DEFAULT 0,
                    double_ext INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL
                )
                """
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_conn_seen_at ON connections(seen_at)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_file_events_at ON file_events(recorded_at)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_at ON alerts(created_at)"
            )

    def record_connection(
        self,
        ip: str,
        port: int,
        host: str,
        state: str,
        is_new: bool,
        suspicious_port: bool,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO connections (
                    seen_at, ip, port, host, state, is_new, suspicious_port
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now_iso(),
                    ip,
                    port,
                    host,
                    state,
                    1 if is_new else 0,
                    1 if suspicious_port else 0,
                ),
            )

    def record_file_event(
        self,
        path: str,
        filename: str,
        event_type: str,
        size_bytes: int,
        sha256: str | None,
        skipped_large: bool,
        is_apk: bool,
        double_ext: bool,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO file_events (
                    recorded_at, path, filename, event_type,
                    size_bytes, sha256, skipped_large, is_apk, double_ext
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _now_iso(),
                    path,
                    filename,
                    event_type,
                    size_bytes,
                    sha256,
                    1 if skipped_large else 0,
                    1 if is_apk else 0,
                    1 if double_ext else 0,
                ),
            )

    def record_alert(
        self,
        severity: str,
        category: str,
        title: str,
        message: str,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO alerts (created_at, severity, category, title, message)
                VALUES (?, ?, ?, ?, ?)
                """,
                (_now_iso(), severity, category, title, message),
            )

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass
