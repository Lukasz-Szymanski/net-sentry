import tempfile
from pathlib import Path
from netsentry.core.database import Database


def test_database_crud():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        db = Database(db_path=db_path)

        # 1. Alert recording
        alert_id = db.record_alert(
            severity="CRITICAL",
            threat_type="Reverse Shell",
            score=95,
            remote_ip="198.51.100.22",
            remote_port=4444,
            process_name="bash",
            pid=1234,
            details="Shell connecting outbound",
            blocked=True,
        )
        assert alert_id > 0

        alerts = db.get_recent_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "CRITICAL"
        assert alerts[0]["remote_ip"] == "198.51.100.22"

        # 2. Blocked IP tracking
        db.add_blocked_ip("198.51.100.22", reason="Malicious C2")
        assert db.is_blocked("198.51.100.22") is True
        assert db.is_blocked("8.8.8.8") is False

        blocked_list = db.get_blocked_ips()
        assert len(blocked_list) == 1
        assert blocked_list[0]["ip"] == "198.51.100.22"

        # 3. Unblock
        removed = db.remove_blocked_ip("198.51.100.22")
        assert removed is True
        assert db.is_blocked("198.51.100.22") is False

        # 4. Stats
        stats = db.get_stats()
        assert stats["total_alerts"] == 1
        assert stats["total_blocked_events"] == 1
        assert stats["active_blocked_ips"] == 0
