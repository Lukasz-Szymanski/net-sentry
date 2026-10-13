"""Tests for CLI helper utilities, commands, and packaged resources."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from netsentry.cli import _find_data_dir, main


def test_find_data_dir_extension():
    ext_dir = _find_data_dir("extension")
    assert ext_dir is not None
    assert (ext_dir / "metadata.json").is_file()
    assert (ext_dir / "extension.js").is_file()
    assert (ext_dir / "stylesheet.css").is_file()


def test_find_data_dir_systemd():
    sysd_dir = _find_data_dir("systemd")
    assert sysd_dir is not None
    service_file = sysd_dir / "netsentry.service"
    assert service_file.is_file()
    content = service_file.read_text(encoding="utf-8")
    assert "ExecStart" in content


def test_cli_status_and_bpf():
    with patch("netsentry.cli.console.print") as mock_print:
        main(["status"])
        assert mock_print.called

    with patch("netsentry.cli.console.print") as mock_print:
        main(["bpf-status"])
        assert mock_print.called


def test_cli_block_with_duration_and_blocked():
    with patch("netsentry.core.firewall.Firewall.block_ip", return_value=(True, "Blocked")):
        main(["block", "198.51.100.100", "-d", "30", "-r", "Test Quarantine"])

    with patch("netsentry.cli.console.print") as mock_print:
        main(["blocked"])
        assert mock_print.called


def test_cli_traffic():
    with patch("netsentry.core.monitor.NetworkMonitor.get_established_connections", return_value=[]):
        with patch("netsentry.cli.console.print") as mock_print:
            main(["traffic"])
            assert mock_print.called
