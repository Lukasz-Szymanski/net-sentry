from netsentry.core.firewall import Firewall


def test_firewall_safety_guards():
    fw = Firewall()
    # Unsafe IPs to block
    assert fw.is_safe_to_block("127.0.0.1") is False
    assert fw.is_safe_to_block("0.0.0.0") is False
    assert fw.is_safe_to_block("::1") is False
    assert fw.is_safe_to_block("invalid-ip") is False

    # Safe public IP
    assert fw.is_safe_to_block("198.51.100.4") is True
