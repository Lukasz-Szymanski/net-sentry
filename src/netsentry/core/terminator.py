"""Active process termination and threat containment."""

from __future__ import annotations

import logging
import os
import signal
import time
from typing import Optional, Tuple

import psutil

logger = logging.getLogger(__name__)

# Essential system PIDs that must never be terminated
PROTECTED_PIDS = {0, 1, 2}


def kill_process(pid: int, force: bool = False, timeout_seconds: float = 1.5) -> Tuple[bool, str]:
    """Terminate or kill a process by PID.

    Attempts graceful SIGTERM first, followed by SIGKILL if still running.
    """
    if pid in PROTECTED_PIDS or pid <= 0:
        return False, f"Refusing to terminate critical system PID {pid}"

    if pid == os.getpid():
        return False, "Refusing to terminate self"

    try:
        if not psutil.pid_exists(pid):
            return False, f"Process {pid} does not exist"

        proc = psutil.Process(pid)
        proc_name = proc.name()

        if force:
            proc.send_signal(signal.SIGKILL)
            return True, f"Sent SIGKILL to process {pid} ({proc_name})"

        # 1. Attempt SIGTERM
        proc.send_signal(signal.SIGTERM)

        # 2. Wait up to timeout_seconds for graceful exit
        start = time.time()
        while time.time() - start < timeout_seconds:
            if not proc.is_running():
                return True, f"Process {pid} ({proc_name}) terminated cleanly via SIGTERM"
            time.sleep(0.1)

        # 3. Fallback to SIGKILL
        if proc.is_running():
            proc.send_signal(signal.SIGKILL)
            return True, f"Process {pid} ({proc_name}) killed via SIGKILL after timeout"

        return True, f"Process {pid} ({proc_name}) terminated"

    except psutil.NoSuchProcess:
        return True, f"Process {pid} already exited"
    except psutil.AccessDenied:
        # Fallback to sudo kill if possible
        try:
            import subprocess
            sig = "-9" if force else "-15"
            cmd = ["sudo", "-n", "kill", sig, str(pid)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0:
                return True, f"Terminated process {pid} using elevated privileges"
            return False, f"Permission denied terminating PID {pid} (try running with sudo)"
        except Exception as e:
            return False, f"Permission denied terminating PID {pid}: {e}"
    except Exception as e:
        return False, f"Failed to terminate PID {pid}: {e}"
