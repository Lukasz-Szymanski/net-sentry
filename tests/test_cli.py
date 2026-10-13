"""Tests for CLI helper utilities and packaged resources."""

from pathlib import Path
from netsentry.cli import _find_data_dir


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
