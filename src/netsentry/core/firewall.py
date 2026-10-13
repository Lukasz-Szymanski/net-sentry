"""Linux firewall integration (nftables / ufw / iptables)."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class Firewall:
    def __init__(self, backend: str = "auto"):
        self.requested_backend = backend.lower()
        self.nft_path = shutil.which("nft")
        self.ufw_path = shutil.which("ufw")
        self.iptables_path = shutil.which("iptables")
        self.ip6tables_path = shutil.which("ip6tables")
        self.is_root = os.geteuid() == 0

        self.active_backend = self._determine_backend()

    def _determine_backend(self) -> str:
        if self.requested_backend in ("nft", "nftables"):
            return "nftables" if self.nft_path else "none"
        elif self.requested_backend == "ufw":
            return "ufw" if self.ufw_path else "none"
        elif self.requested_backend in ("iptables", "iptable"):
            return "iptables" if self.iptables_path else "none"
        elif self.requested_backend == "auto":
            if self.nft_path:
                return "nftables"
            elif self.ufw_path:
                return "ufw"
            elif self.iptables_path:
                return "iptables"
            return "none"
        return "none"

    def get_backend(self) -> str:
        """Return the name of the currently active firewall backend."""
        return self.active_backend

    def is_safe_to_block(self, ip: str) -> bool:
        """Prevent accidentally blocking loopback or local critical IPs."""
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                return False
            return True
        except ValueError:
            return False

    def _is_ipv6(self, ip: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def _run_cmd(self, cmd: List[str]) -> Tuple[int, str, str]:
        """Execute command with sudo if running unprivileged."""
        final_cmd = cmd
        if not self.is_root:
            final_cmd = ["sudo", "-n"] + cmd

        try:
            res = subprocess.run(
                final_cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except Exception as e:
            return 1, "", str(e)

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        """Block incoming and outgoing traffic for a specific IP."""
        if not self.is_safe_to_block(ip):
            return False, f"Refusing to block unsafe/local IP: {ip}"

        backend = self.active_backend
        if backend == "nftables":
            return self._block_nftables(ip)
        elif backend == "ufw":
            return self._block_ufw(ip)
        elif backend == "iptables":
            return self._block_iptables(ip)
        else:
            return False, "No supported firewall tool found (nftables, ufw, or iptables)"

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        """Remove firewall DROP rules for a specific IP."""
        backend = self.active_backend
        if backend == "nftables":
            return self._unblock_nftables(ip)
        elif backend == "ufw":
            return self._unblock_ufw(ip)
        elif backend == "iptables":
            return self._unblock_iptables(ip)
        else:
            return False, "No supported firewall tool found (nftables, ufw, or iptables)"

    # --- nftables Backend ---
    def _block_nftables(self, ip: str) -> Tuple[bool, str]:
        if not self.nft_path:
            return False, "nft binary not found on system"

        is_v6 = self._is_ipv6(ip)
        set_name = "blocklist_v6" if is_v6 else "blocklist_v4"
        addr_type = "ipv6_addr" if is_v6 else "ipv4_addr"
        saddr_kw = "ip6" if is_v6 else "ip"

        # Ensure table, sets, and chains exist
        init_cmds = [
            [self.nft_path, "add", "table", "inet", "netsentry"],
            [self.nft_path, "add", "set", "inet", "netsentry", set_name, "{", "type", f"{addr_type};", "}"],
            [self.nft_path, "add", "chain", "inet", "netsentry", "input", "{", "type", "filter", "hook", "input", "priority", "-10;", "policy", "accept;", "}"],
            [self.nft_path, "add", "chain", "inet", "netsentry", "output", "{", "type", "filter", "hook", "output", "priority", "-10;", "policy", "accept;", "}"],
        ]
        for cmd in init_cmds:
            self._run_cmd(cmd)

        # Ensure rules exist to drop traffic referencing the set
        rule_in = [self.nft_path, "add", "rule", "inet", "netsentry", "input", saddr_kw, "saddr", f"@{set_name}", "drop"]
        rule_out = [self.nft_path, "add", "rule", "inet", "netsentry", "output", saddr_kw, "daddr", f"@{set_name}", "drop"]
        self._run_cmd(rule_in)
        self._run_cmd(rule_out)

        # Add IP to the blocklist set
        elem_cmd = [self.nft_path, "add", "element", "inet", "netsentry", set_name, "{", ip, "}"]
        code, out, err = self._run_cmd(elem_cmd)
        if code == 0:
            return True, f"Successfully blocked {ip} in nftables"
        if "File exists" in err or "already exists" in err:
            return True, f"IP {ip} is already blocked in nftables"
        return False, f"nftables command failed: {err or 'Permission denied'} (Try running with sudo)"

    def _unblock_nftables(self, ip: str) -> Tuple[bool, str]:
        if not self.nft_path:
            return False, "nft binary not found on system"

        is_v6 = self._is_ipv6(ip)
        set_name = "blocklist_v6" if is_v6 else "blocklist_v4"
        elem_cmd = [self.nft_path, "delete", "element", "inet", "netsentry", set_name, "{", ip, "}"]
        code, out, err = self._run_cmd(elem_cmd)
        if code == 0 or "No such file or directory" in err or "does not exist" in err:
            return True, f"Unblocked {ip} in nftables"
        return False, f"Errors unblocking {ip} in nftables: {err}"

    # --- ufw Backend ---
    def _block_ufw(self, ip: str) -> Tuple[bool, str]:
        if not self.ufw_path:
            return False, "ufw binary not found on system"

        commands = [
            [self.ufw_path, "insert", "1", "deny", "from", ip, "to", "any"],
            [self.ufw_path, "insert", "1", "deny", "out", "to", ip],
        ]
        for cmd in commands:
            code, out, err = self._run_cmd(cmd)
            if code != 0:
                return False, f"ufw command failed: {err or 'Permission denied'} (Try running with sudo)"
        return True, f"Successfully blocked {ip} in ufw"

    def _unblock_ufw(self, ip: str) -> Tuple[bool, str]:
        if not self.ufw_path:
            return False, "ufw binary not found on system"

        commands = [
            [self.ufw_path, "delete", "deny", "from", ip, "to", "any"],
            [self.ufw_path, "delete", "deny", "out", "to", ip],
        ]
        for cmd in commands:
            self._run_cmd(cmd)
        return True, f"Unblocked {ip} in ufw"

    # --- iptables Backend ---
    def _block_iptables(self, ip: str) -> Tuple[bool, str]:
        is_v6 = self._is_ipv6(ip)
        bin_path = self.ip6tables_path if is_v6 else self.iptables_path
        if not bin_path:
            return False, f"{'ip6tables' if is_v6 else 'iptables'} binary not found on system"

        commands = [
            [bin_path, "-I", "INPUT", "-s", ip, "-j", "DROP"],
            [bin_path, "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]
        for cmd in commands:
            code, out, err = self._run_cmd(cmd)
            if code != 0:
                return False, f"iptables command failed: {err or 'Permission denied'} (Try running with sudo)"
        return True, f"Successfully blocked {ip} in iptables"

    def _unblock_iptables(self, ip: str) -> Tuple[bool, str]:
        is_v6 = self._is_ipv6(ip)
        bin_path = self.ip6tables_path if is_v6 else self.iptables_path
        if not bin_path:
            return False, f"{'ip6tables' if is_v6 else 'iptables'} binary not found on system"

        commands = [
            [bin_path, "-D", "INPUT", "-s", ip, "-j", "DROP"],
            [bin_path, "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]
        errors = []
        for cmd in commands:
            code, out, err = self._run_cmd(cmd)
            if code != 0 and "Bad rule" not in err:
                errors.append(err)

        if not errors:
            return True, f"Unblocked {ip} in iptables"
        return False, f"Errors unblocking {ip}: {'; '.join(errors)}"
