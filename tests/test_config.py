from netsentry.config import Config, get_config_dir, get_data_dir


def test_default_config():
    cfg = Config()
    assert cfg.scan_interval_seconds == 2.0
    assert cfg.desktop_notifications is True
    assert 4444 in cfg.suspicious_ports
    assert "127.0.0.1" in cfg.whitelist_ips


def test_paths():
    c_dir = get_config_dir()
    d_dir = get_data_dir()
    assert c_dir.exists()
    assert d_dir.exists()
