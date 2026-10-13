"""Tests for forensics and file hashing module."""

import os
from pathlib import Path
from netsentry.core.forensics import compute_file_hash, get_process_forensics


def test_compute_file_hash(tmp_path: Path):
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"NetSentry security test")

    import hashlib
    expected_sha256 = hashlib.sha256(b"NetSentry security test").hexdigest()

    h = compute_file_hash(test_file)
    assert h == expected_sha256


def test_compute_file_hash_nonexistent():
    assert compute_file_hash("/path/that/does/not/exist/surely.bin") is None


def test_get_process_forensics():
    pid = os.getpid()
    forensics = get_process_forensics(pid)

    assert forensics["pid"] == pid
    assert forensics["name"] is not None
    assert forensics["status"] is not None
