"""Desktop notification dispatcher for security alerts on Linux."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class Notifier:
    def __init__(self, cooldown_seconds: int = 30):
        self.cooldown_seconds = cooldown_seconds
        self.notify_send_path = shutil.which("notify-send")
        self._last_alert_time: Dict[str, float] = {}

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "HIGH",
        throttle_key: Optional[str] = None,
    ) -> bool:
        """Send a desktop notification with throttling support."""
        if not self.notify_send_path:
            logger.debug("notify-send binary not found; skipping desktop notification")
            return False

        now = time.time()
        if throttle_key:
            last = self._last_alert_time.get(throttle_key, 0.0)
            if now - last < self.cooldown_seconds:
                return False
            self._last_alert_time[throttle_key] = now

        urgency = "normal"
        if severity.upper() == "CRITICAL":
            urgency = "critical"
        elif severity.upper() == "LOW":
            urgency = "low"

        icon = "security-high"
        if severity.upper() == "CRITICAL":
            icon = "dialog-error"

        cmd = [
            self.notify_send_path,
            "-a",
            "NetSentry",
            "-u",
            urgency,
            "-i",
            icon,
            title,
            message,
        ]

        try:
            subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            return True
        except Exception as e:
            logger.debug("Failed to dispatch notify-send: %s", e)
            return False
