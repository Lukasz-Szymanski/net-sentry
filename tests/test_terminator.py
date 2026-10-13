"""Tests for active process termination and containment."""

import subprocess
import sys
import time
from netsentry.core.terminator import kill_process


def test_kill_protected_pid():
    success, msg = kill_process(1)
    assert success is False
    assert "critical system PID 1" in msg


def test_kill_nonexistent_pid():
    success, msg = kill_process(99999999)
    assert "does not exist" in msg or "already exited" in msg


def test_kill_spawned_process():
    # Spawn a sleeping background process
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
    pid = proc.pid

    try:
        success, msg = kill_process(pid, force=True)
        assert success is True
        # Verify process is indeed gone
        time.sleep(0.2)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()
