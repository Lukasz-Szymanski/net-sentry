from unittest.mock import MagicMock, patch
from netsentry.core.firewall import Firewall


def test_firewall_safety_guards():
    fw = Firewall()
    # Unsafe IPs to block
    assert fw.is_safe_to_block("127.0.0.1") is False
    assert fw.is_safe_to_block("0.0.0.0") is False
    assert fw.is_safe_to_block("::1") is False
    assert fw.is_safe_to_block("224.0.0.1") is False  # multicast
    assert fw.is_safe_to_block("invalid-ip") is False

    # Safe public IP
    assert fw.is_safe_to_block("198.51.100.4") is True
    assert fw.is_safe_to_block("2001:db8::1") is True


def test_firewall_backend_detection():
    with patch("shutil.which") as mock_which:
        # Case 1: nft available -> nftables chosen in auto mode
        mock_which.side_effect = lambda bin: "/usr/bin/nft" if bin == "nft" else None
        fw = Firewall(backend="auto")
        assert fw.get_backend() == "nftables"

        # Case 2: only ufw available -> ufw chosen
        mock_which.side_effect = lambda bin: "/usr/bin/ufw" if bin == "ufw" else None
        fw_ufw = Firewall(backend="auto")
        assert fw_ufw.get_backend() == "ufw"

        # Case 3: only iptables available -> iptables chosen
        mock_which.side_effect = lambda bin: "/usr/bin/iptables" if bin == "iptables" else None
        fw_ip = Firewall(backend="auto")
        assert fw_ip.get_backend() == "iptables"

        # Case 4: none available
        mock_which.side_effect = lambda bin: None
        fw_none = Firewall(backend="auto")
        assert fw_none.get_backend() == "none"


def test_firewall_nftables_block_and_unblock():
    fw = Firewall(backend="nftables")
    fw.nft_path = "/usr/bin/nft"
    fw.active_backend = "nftables"

    with patch.object(fw, "_run_cmd") as mock_run:
        mock_run.return_value = (0, "", "")

        success, msg = fw.block_ip("203.0.113.5")
        assert success is True
        assert "nftables" in msg

        # Verify add element was called
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert any("add" in c and "element" in c for c in calls)

        # Unblock
        mock_run.reset_mock()
        mock_run.return_value = (0, "", "")
        unblock_success, unblock_msg = fw.unblock_ip("203.0.113.5")
        assert unblock_success is True
        assert "Unblocked" in unblock_msg


def test_firewall_ufw_block_and_unblock():
    fw = Firewall(backend="ufw")
    fw.ufw_path = "/usr/bin/ufw"
    fw.active_backend = "ufw"

    with patch.object(fw, "_run_cmd") as mock_run:
        mock_run.return_value = (0, "", "")

        success, msg = fw.block_ip("203.0.113.6")
        assert success is True
        assert "ufw" in msg

        unblock_success, unblock_msg = fw.unblock_ip("203.0.113.6")
        assert unblock_success is True
        assert "Unblocked" in unblock_msg


def test_firewall_iptables_block():
    fw = Firewall(backend="iptables")
    fw.iptables_path = "/usr/bin/iptables"
    fw.active_backend = "iptables"

    with patch.object(fw, "_run_cmd") as mock_run:
        mock_run.return_value = (0, "", "")
        success, msg = fw.block_ip("203.0.113.7")
        assert success is True
        assert "iptables" in msg
