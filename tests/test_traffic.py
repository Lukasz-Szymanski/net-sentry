import time
from unittest.mock import MagicMock, patch

from netsentry.config import Config
from netsentry.core.traffic import TrafficAnomaly, TrafficMonitor


def test_traffic_monitor_sampling():
    cfg = Config(
        exfiltration_detection_enabled=True,
        exfiltration_rate_threshold_kb_s=100.0,
        exfiltration_total_threshold_mb=10.0,
    )
    monitor = TrafficMonitor(config=cfg)

    # Mock psutil.Process
    with patch("psutil.Process") as mock_proc:
        instance = MagicMock()
        mock_proc.return_value = instance

        # First sample: initialize baseline
        io_1 = MagicMock()
        io_1.write_chars = 1000
        io_1.read_chars = 500
        io_1.write_bytes = 1000
        io_1.read_bytes = 500
        instance.io_counters.return_value = io_1
        instance.name.return_value = "exfil_test"

        rate, mb, anomaly = monitor.sample_process(pid=9999, remote_ip="198.51.100.99")
        assert rate == 0.0
        assert mb == 0.0
        assert anomaly is None

        # Second sample after time advance: simulate 500 KB written in 1 second (500 KB/s > 100 KB/s threshold)
        io_2 = MagicMock()
        io_2.write_chars = 1000 + (500 * 1024)
        io_2.read_chars = 1000
        io_2.write_bytes = io_2.write_chars
        io_2.read_bytes = io_2.read_chars
        instance.io_counters.return_value = io_2

        with patch("time.time", side_effect=[time.time() + 1.0, time.time() + 1.0]):
            rate2, mb2, anomaly2 = monitor.sample_process(
                pid=9999,
                remote_ip="198.51.100.99",
                remote_port=443,
                process_name="exfil_test",
            )
            assert rate2 > 100.0
            assert anomaly2 is not None
            assert anomaly2.pid == 9999
            assert "High outbound transfer rate" in anomaly2.reason


def test_traffic_monitor_system_totals():
    with patch("psutil.net_io_counters") as mock_net:
        counters = MagicMock()
        counters.bytes_sent = 10485760  # 10 MB
        counters.bytes_recv = 20971520  # 20 MB
        counters.packets_sent = 5000
        counters.packets_recv = 8000
        mock_net.return_value = counters

        res = TrafficMonitor.get_system_totals()
        assert res["mb_sent"] == 10.0
        assert res["mb_recv"] == 20.0
        assert res["packets_sent"] == 5000
