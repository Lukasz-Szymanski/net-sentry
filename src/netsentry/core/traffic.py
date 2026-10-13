"""Traffic and data exfiltration monitoring engine."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import psutil

from netsentry.config import Config

logger = logging.getLogger(__name__)


@dataclass
class TrafficAnomaly:
    pid: int
    process_name: Optional[str]
    remote_ip: str
    remote_port: Optional[int]
    rate_kb_s: float
    cumulative_mb: float
    reason: str


class TrafficMonitor:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        # pid -> {"timestamp": float, "write_bytes": int, "read_bytes": int, "cumulative_out": int, "rate_kb_s": float}
        self._proc_stats: Dict[int, Dict[str, Any]] = {}

    def sample_process(
        self,
        pid: Optional[int],
        remote_ip: Optional[str] = None,
        remote_port: Optional[int] = None,
        process_name: Optional[str] = None,
    ) -> Tuple[float, float, Optional[TrafficAnomaly]]:
        """Sample I/O for a PID. Returns (rate_kb_s, cumulative_mb, anomaly_if_detected)."""
        if not pid or pid <= 0:
            return 0.0, 0.0, None

        now = time.time()
        try:
            p = psutil.Process(pid)
            io = p.io_counters()
            # On Linux, write_bytes counts actual disk write, write_chars counts all write syscalls (including sockets)
            current_write = getattr(io, "write_chars", io.write_bytes)
            current_read = getattr(io, "read_chars", io.read_bytes)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError):
            return 0.0, 0.0, None

        if pid not in self._proc_stats:
            self._proc_stats[pid] = {
                "timestamp": now,
                "write_bytes": current_write,
                "read_bytes": current_read,
                "cumulative_out": 0,
                "rate_kb_s": 0.0,
                "process_name": process_name or (p.name() if hasattr(p, "name") else None),
            }
            return 0.0, 0.0, None

        prev = self._proc_stats[pid]
        delta_time = now - prev["timestamp"]
        delta_write = current_write - prev["write_bytes"]
        if delta_write < 0:
            # Counter rollover or process restarted
            delta_write = 0

        rate_kb_s = (delta_write / delta_time / 1024.0) if delta_time > 0 else 0.0
        cumulative_out = prev["cumulative_out"] + delta_write
        cumulative_mb = cumulative_out / (1024.0 * 1024.0)

        # Update cached state
        self._proc_stats[pid].update(
            {
                "timestamp": now,
                "write_bytes": current_write,
                "read_bytes": current_read,
                "cumulative_out": cumulative_out,
                "rate_kb_s": rate_kb_s,
                "process_name": process_name or prev.get("process_name"),
            }
        )

        anomaly: Optional[TrafficAnomaly] = None
        if self.config.exfiltration_detection_enabled and remote_ip:
            is_whitelisted = remote_ip in self.config.whitelist_ips or (
                process_name and process_name in self.config.whitelist_processes
            )
            if not is_whitelisted:
                rate_threshold = self.config.exfiltration_rate_threshold_kb_s
                vol_threshold = self.config.exfiltration_total_threshold_mb

                reasons = []
                if rate_threshold > 0 and rate_kb_s >= rate_threshold:
                    reasons.append(
                        f"High outbound transfer rate: {rate_kb_s:.1f} KB/s (threshold: {rate_threshold:.1f} KB/s)"
                    )
                if vol_threshold > 0 and cumulative_mb >= vol_threshold:
                    reasons.append(
                        f"High cumulative outbound volume: {cumulative_mb:.1f} MB (threshold: {vol_threshold:.1f} MB)"
                    )

                if reasons:
                    pname = process_name or prev.get("process_name") or f"PID {pid}"
                    anomaly = TrafficAnomaly(
                        pid=pid,
                        process_name=pname,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        rate_kb_s=rate_kb_s,
                        cumulative_mb=cumulative_mb,
                        reason="; ".join(reasons),
                    )

        return rate_kb_s, cumulative_mb, anomaly

    def cleanup_terminated(self) -> None:
        """Remove cached stats for processes that no longer exist."""
        alive_pids = set(psutil.pids())
        dead = [pid for pid in self._proc_stats if pid not in alive_pids]
        for pid in dead:
            del self._proc_stats[pid]

    def get_process_stats(self) -> List[Dict[str, Any]]:
        """Return list of active monitored process bandwidth stats."""
        results = []
        for pid, data in self._proc_stats.items():
            results.append(
                {
                    "pid": pid,
                    "process_name": data.get("process_name") or "unknown",
                    "rate_kb_s": round(data.get("rate_kb_s", 0.0), 1),
                    "cumulative_mb": round(data.get("cumulative_out", 0) / (1024.0 * 1024.0), 2),
                }
            )
        results.sort(key=lambda x: x["rate_kb_s"], reverse=True)
        return results

    @staticmethod
    def get_system_totals() -> Dict[str, Any]:
        """Return total network interface I/O counters."""
        try:
            counters = psutil.net_io_counters()
            return {
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
                "packets_sent": counters.packets_sent,
                "packets_recv": counters.packets_recv,
                "mb_sent": round(counters.bytes_sent / (1024.0 * 1024.0), 1),
                "mb_recv": round(counters.bytes_recv / (1024.0 * 1024.0), 1),
            }
        except Exception as e:
            logger.warning("Failed to read system net_io_counters: %s", e)
            return {
                "bytes_sent": 0,
                "bytes_recv": 0,
                "packets_sent": 0,
                "packets_recv": 0,
                "mb_sent": 0.0,
                "mb_recv": 0.0,
            }
