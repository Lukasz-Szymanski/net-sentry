"""SQLite database manager for security alerts and blocklists."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from netsentry.config import get_data_dir


class Database:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = get_data_dir() / "sentry.db"
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    process_name TEXT,
                    pid INTEGER,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER,
                    details TEXT,
                    blocked INTEGER DEFAULT 0
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_remote_ip ON alerts (remote_ip)"
            )
            conn.commit()

    def record_alert(
        self,
        severity: str,
        threat_type: str,
        score: int,
        remote_ip: str,
        remote_port: Optional[int] = None,
        process_name: Optional[str] = None,
        pid: Optional[int] = None,
        details: Optional[str] = None,
        blocked: bool = False,
    ) -> int:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (
                    timestamp, severity, threat_type, score,
                    process_name, pid, remote_ip, remote_port, details, blocked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    severity.upper(),
                    threat_type,
                    score,
                    process_name,
                    pid,
                    remote_ip,
                    remote_port,
                    details,
                    1 if blocked else 0,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def get_recent_alerts(
        self, limit: int = 50, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if severity:
                cursor.execute(
                    """
                    SELECT * FROM alerts
                    WHERE severity = ?
                    ORDER BY id DESC LIMIT ?
                    """,
                    (severity.upper(), limit),
                )
            else:
                cursor.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
                )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def add_blocked_ip(self, ip: str, reason: str = "Manually blocked") -> None:
        timestamp = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO blocked_ips (ip, reason, timestamp)
                VALUES (?, ?, ?)
                """,
                (ip, reason, timestamp),
            )
            conn.commit()

    def remove_blocked_ip(self, ip: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
            conn.commit()
            return cursor.rowcount > 0

    def is_blocked(self, ip: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
            return cursor.fetchone() is not None

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blocked_ips ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]

    def get_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE blocked = 1")
            total_blocked_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM blocked_ips")
            active_blocked_ips = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
                """
            )
            severity_counts = {row["severity"]: row["count"] for row in cursor.fetchall()}

            return {
                "total_alerts": total_alerts,
                "total_blocked_events": total_blocked_events,
                "active_blocked_ips": active_blocked_ips,
                "severity_counts": severity_counts,
            }
