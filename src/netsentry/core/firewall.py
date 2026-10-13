"""Linux firewall integration (iptables / nftables)."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class Firewall:
    def __init__(self):
        self.iptables_path = shutil.which("iptables")
        self.is_root = os.geteuid() == 0

    def is_safe_to_block(self, ip: str) -> bool:
        """Prevent accidentally blocking loopback or local critical IPs."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_unspecified:
                return False
            return True
        except ValueError:
            return False

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        """Block incoming and outgoing traffic for a specific IP."""
        if not self.is_safe_to_block(ip):
            return False, f"Refusing to block unsafe/local IP: {ip}"

        if not self.iptables_path:
            return False, "iptables binary not found on system"

        commands = [
            [self.iptables_path, "-I", "INPUT", "-s", ip, "-j", "DROP"],
            [self.iptables_path, "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]

        if not self.is_root:
            commands = [["sudo", "-n"] + cmd for cmd in commands]

        try:
            for cmd in commands:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode != 0:
                    err = res.stderr.strip() or "Permission denied or rule error"
                    return False, f"Firewall command failed: {err} (Try running with sudo)"
            return True, f"Successfully blocked {ip} in firewall"
        except Exception as e:
            return False, f"Failed to execute firewall rule: {e}"

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Remove firewall DROP rules for a specific IP."""
        if not self.iptables_path:
            return False, "iptables binary not found on system"

        commands = [
            [self.iptables_path, "-D", "INPUT", "-s", ip, "-j", "DROP"],
            [self.iptables_path, "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]

        if not self.is_root:
            commands = [["sudo", "-n"] + cmd for cmd in commands]

        success = True
        errors = []
        for cmd in commands:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode != 0 and "Bad rule" not in res.stderr:
                    errors.append(res.stderr.strip())
                    success = False
            except Exception as e:
                errors.append(str(e))
                success = False

        if success:
            return True, f"Unblocked {ip}"
        return False, f"Errors unblocking {ip}: {'; '.join(errors)}"
