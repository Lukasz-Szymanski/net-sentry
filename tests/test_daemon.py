import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from netsentry.config import Config
from netsentry.core.monitor import ConnectionInfo
from netsentry.daemon import SentryDaemon


def test_daemon_step_auto_unblock_and_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = Config(
            auto_block_threats=True,
            auto_block_duration_minutes=30,
            auto_kill_threats=False,
            desktop_notifications=False,
        )
        daemon = SentryDaemon(config=cfg)
        daemon.data_dir = Path(tmpdir)
        daemon.pid_file = Path(tmpdir) / "test.pid"
        daemon.db.db_path = Path(tmpdir) / "test.db"
        daemon.db._init_db()

        # Seed an expired temporary ban
        daemon.db.add_blocked_ip("198.51.100.50", reason="Old quarantine", duration_minutes=1)
        with daemon.db._get_connection() as conn:
            conn.cursor().execute(
                "UPDATE blocked_ips SET expires_at = '2000-01-01T00:00:00' WHERE ip = '198.51.100.50'"
            )
            conn.commit()

        # Mock firewall unblock
        with patch.object(daemon.firewall, "unblock_ip", return_value=(True, "Unblocked")) as mock_unblock:
            # Mock established connections: one benign connection
            c_benign = ConnectionInfo(
                protocol="TCP",
                local_ip="192.168.1.10",
                local_port=54321,
                remote_ip="8.8.8.8",
                remote_port=53,
                status="ESTABLISHED",
                pid=1000,
                process_name="resolved",
            )
            with patch.object(daemon.monitor, "get_established_connections", return_value=[c_benign]):
                threats = daemon.step()
                assert len(threats) == 0

            # Verify the expired ban was removed and unblocked
            mock_unblock.assert_called_once_with("198.51.100.50")
            assert daemon.db.is_blocked("198.51.100.50") is False
