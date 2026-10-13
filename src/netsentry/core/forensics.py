"""Forensic utilities for binary inspection and process analysis."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import psutil

logger = logging.getLogger(__name__)


def compute_file_hash(path: str | Path, algorithm: str = "sha256", max_size_bytes: int = 100 * 1024 * 1024) -> Optional[str]:
    """Safely compute hash of an executable or binary file.

    Returns hex digest string or None if unreadable / exceeds max size.
    """
    try:
        file_path = Path(path)
        if not file_path.is_file():
            return None

        # Guard against gigantic files
        if file_path.stat().st_size > max_size_bytes:
            return None

        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as e:
        logger.debug("Cannot compute hash for %s: %s", path, e)
        return None


def get_process_forensics(pid: int) -> Dict[str, Any]:
    """Extract forensic metadata for a given process PID."""
    data: Dict[str, Any] = {
        "pid": pid,
        "name": None,
        "exe": None,
        "cmdline": None,
        "username": None,
        "cwd": None,
        "created_at": None,
        "file_hash_sha256": None,
        "open_files_count": 0,
        "status": None,
    }

    try:
        p = psutil.Process(pid)
        data["name"] = p.name()
        data["status"] = p.status()

        try:
            data["exe"] = p.exe()
            if data["exe"]:
                data["file_hash_sha256"] = compute_file_hash(data["exe"])
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            cmd = p.cmdline()
            data["cmdline"] = " ".join(cmd) if cmd else None
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            data["username"] = p.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            data["cwd"] = p.cwd()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            data["created_at"] = p.create_time()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        try:
            open_files = p.open_files()
            data["open_files_count"] = len(open_files)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

    return data
