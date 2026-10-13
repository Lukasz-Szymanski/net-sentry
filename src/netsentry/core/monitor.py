"""Linux network connection and process monitor."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    protocol: str  # TCP / UDP
    local_ip: str
    local_port: int
    remote_ip: Optional[str]
    remote_port: Optional[int]
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None


class NetworkMonitor:
    def __init__(self):
        self._proc_cache: Dict[int, Dict[str, Optional[str]]] = {}

    def _get_process_meta(self, pid: Optional[int]) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        if not pid or pid <= 0:
            return None, None, None, None

        if pid in self._proc_cache:
            info = self._proc_cache[pid]
            return info.get("name"), info.get("exe"), info.get("cmdline"), info.get("username")

        name = None
        exe = None
        cmd = None
        user = None

        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = None
            try:
                cmd_list = p.cmdline()
                cmd = " ".join(cmd_list) if cmd_list else None
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmd = None
            try:
                user = p.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                user = None

            self._proc_cache[pid] = {
                "name": name,
                "exe": exe,
                "cmdline": cmd,
                "username": user,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return name, exe, cmd, user

    def get_connections(self, kind: str = "inet") -> List[ConnectionInfo]:
        """Fetch all current network connections mapped to processes."""
        results: List[ConnectionInfo] = []

        try:
            conns = psutil.net_connections(kind=kind)
        except (psutil.AccessDenied, PermissionError) as e:
            logger.warning("Limited permission to read network connections: %s", e)
            return results

        for c in conns:
            proto = "TCP" if c.type == 1 else "UDP"
            local_ip = c.laddr.ip if c.laddr else ""
            local_port = c.laddr.port if c.laddr else 0
            remote_ip = c.raddr.ip if c.raddr else None
            remote_port = c.raddr.port if c.raddr else None

            p_name, p_exe, p_cmd, p_user = self._get_process_meta(c.pid)

            results.append(
                ConnectionInfo(
                    protocol=proto,
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    status=c.status,
                    pid=c.pid,
                    process_name=p_name,
                    exe_path=p_exe,
                    cmdline=p_cmd,
                    username=p_user,
                )
            )

        return results

    def get_listening_services(self) -> List[ConnectionInfo]:
        """Return all listening sockets."""
        return [c for c in self.get_connections() if c.status == "LISTEN"]

    def get_established_connections(self) -> List[ConnectionInfo]:
        """Return all active established outbound/inbound connections."""
        return [c for c in self.get_connections() if c.status == "ESTABLISHED" and c.remote_ip]
