from unittest.mock import MagicMock, patch

from netsentry.core.bpf import BPFProbe


def test_bpf_status_reporting_fallback():
    probe = BPFProbe()
    probe.bcc_module = None
    probe.is_root = False

    status = probe.check_status()
    assert status["available"] is False
    assert status["bcc_installed"] is False
    assert status["is_root"] is False
    assert "Fallback mode" in status["status_description"]
    assert status["recommendation"] is not None

    # Start should gracefully return False without raising exception
    success, msg = probe.start()
    assert success is False
    assert "eBPF not available" in msg


def test_bpf_status_mocked_available():
    probe = BPFProbe()
    probe.is_linux = True
    probe.is_root = True
    mock_bcc = MagicMock()
    probe.bcc_module = mock_bcc

    with patch("pathlib.Path.exists", return_value=True):
        status = probe.check_status()
        assert status["available"] is True
        assert "Zero-latency" in status["status_description"]

        # Test start
        mock_bpf_instance = MagicMock()
        mock_bcc.BPF.return_value = mock_bpf_instance

        success, msg = probe.start()
        assert success is True
        mock_bpf_instance.attach_kprobe.assert_called_once()

        # Test stop
        probe.stop()
        mock_bpf_instance.cleanup.assert_called_once()
