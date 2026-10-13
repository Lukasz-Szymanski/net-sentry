"""Background sentinel daemon for continuous network inspection."""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from netsentry.config import Config, get_data_dir, load_config
from netsentry.core.database import Database
from netsentry.core.detector import ThreatDetector, ThreatEvent
from netsentry.core.firewall import Firewall
from netsentry.core.forensics import compute_file_hash
from netsentry.core.monitor import NetworkMonitor
from netsentry.core.notifier import Notifier
from netsentry.core.terminator import kill_process
from netsentry.core.threat_intel import ThreatIntel
from netsentry.core.traffic import TrafficMonitor

logger = logging.getLogger(__name__)


class SentryDaemon:
    def __init__(self, config: Optional[Config] = None):
        self.config = config or load_config()
        self.data_dir = get_data_dir()
        self.pid_file = self.data_dir / "netsentry.pid"

        self.db = Database()
        self.threat_intel = ThreatIntel()
        self.detector = ThreatDetector(self.config, self.threat_intel)
        self.monitor = NetworkMonitor()
        self.notifier = Notifier(config=self.config)
        self.firewall = Firewall(backend=self.config.firewall_backend)
        self.traffic_monitor = TrafficMonitor(config=self.config)

        self._running = False
        self._seen_connections: set[str] = set()

    def _setup_signals(self) -> None:
        def _handler(signum, frame):
            logger.info("Signal %d received, stopping daemon gracefully...", signum)
            self._running = False

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

    def write_pid(self) -> None:
        self.pid_file.write_text(str(os.getpid()))

    def remove_pid(self) -> None:
        if self.pid_file.exists():
            try:
                self.pid_file.unlink()
            except OSError:
                pass

    @classmethod
    def get_running_pid(cls) -> Optional[int]:
        pid_file = get_data_dir() / "netsentry.pid"
        if not pid_file.exists():
            return None
        try:
            pid = int(pid_file.read_text().strip())
            # Check if process is actually running
            os.kill(pid, 0)
            return pid
        except (ValueError, OSError):
            return None

    def _process_expired_bans(self) -> None:
        """Check for temporary bans whose expiration time has passed and remove them."""
        expired = self.db.get_expired_blocked_ips()
        for item in expired:
            ip = item["ip"]
            self.firewall.unblock_ip(ip)
            self.db.remove_blocked_ip(ip)
            logger.info("Temporary ban expired for %s. Automatically unblocked.", ip)

    def _handle_threat(self, threat: ThreatEvent) -> None:
        """Execute automated response (firewall drop, process kill) and alerts."""
        blocked = False
        killed = False

        # Handle Auto-Block if configured
        if self.config.auto_block_threats:
            success, msg = self.firewall.block_ip(threat.remote_ip)
            if success:
                dur = self.config.auto_block_duration_minutes if self.config.auto_block_duration_minutes > 0 else None
                self.db.add_blocked_ip(threat.remote_ip, reason=threat.threat_type, duration_minutes=dur)
                blocked = True

        # Handle Auto-Kill if configured
        if self.config.auto_kill_threats and threat.pid:
            k_success, k_msg = kill_process(threat.pid)
            if k_success:
                killed = True
                logger.warning("Terminated threat process PID %d: %s", threat.pid, k_msg)

        # Record in Database
        self.db.record_alert(
            severity=threat.severity,
            threat_type=threat.threat_type,
            score=threat.score,
            remote_ip=threat.remote_ip,
            remote_port=threat.remote_port,
            process_name=threat.process_name,
            pid=threat.pid,
            details=threat.details,
            blocked=blocked,
            exe_path=threat.exe_path,
            file_hash=threat.file_hash,
            killed=killed,
        )

        # Send Multi-Channel Notification (Desktop, Telegram, Webhook)
        if (
            self.config.desktop_notifications
            or self.config.telegram_enabled
            or self.config.webhook_enabled
        ):
            title = f"🚨 NetSentry Alert [{threat.severity}]"
            action_notes = []
            if blocked:
                action_notes.append("🛡️ Firewall: IP Blocked")
            if killed:
                action_notes.append("🛑 Process Terminated")

            extra = f"\nAction: {', '.join(action_notes)}" if action_notes else ""
            msg = (
                f"Threat: {threat.threat_type}\n"
                f"Target: {threat.remote_ip}:{threat.remote_port}\n"
                f"Process: {threat.process_name} (PID: {threat.pid})\n"
                f"{threat.details}{extra}"
            )
            self.notifier.send_alert(
                title=title,
                message=msg,
                severity=threat.severity,
                throttle_key=threat.remote_ip,
            )

    def step(self) -> list[ThreatEvent]:
        """Perform a single monitoring pass and return detected threats."""
        # 1. Check expired bans and release them
        self._process_expired_bans()

        # 2. Monitor connections and examine threats
        conns = self.monitor.get_established_connections()
        threats_found: list[ThreatEvent] = []

        current_conn_keys = set()
        for c in conns:
            if not c.remote_ip:
                continue
            conn_key = f"{c.pid}:{c.local_port}->{c.remote_ip}:{c.remote_port}"
            current_conn_keys.add(conn_key)

            # Analyze for standard threats
            threat = self.detector.analyze_connection(
                remote_ip=c.remote_ip,
                remote_port=c.remote_port,
                process_name=c.process_name,
                pid=c.pid,
                exe_path=c.exe_path,
                cmdline=c.cmdline,
                status=c.status,
            )

            if threat:
                threats_found.append(threat)
                self._handle_threat(threat)

            # Check for traffic exfiltration anomalies
            if c.pid and self.config.exfiltration_detection_enabled:
                _, _, anomaly = self.traffic_monitor.sample_process(
                    pid=c.pid,
                    remote_ip=c.remote_ip,
                    remote_port=c.remote_port,
                    process_name=c.process_name,
                )
                if anomaly:
                    file_hash = compute_file_hash(c.exe_path) if c.exe_path else None
                    exfil_threat = ThreatEvent(
                        threat_found=True,
                        severity="HIGH",
                        score=85,
                        threat_type="Data Exfiltration",
                        details=anomaly.reason,
                        rule_name="DATA_EXFILTRATION",
                        remote_ip=anomaly.remote_ip,
                        remote_port=anomaly.remote_port,
                        process_name=anomaly.process_name,
                        pid=anomaly.pid,
                        exe_path=c.exe_path,
                        file_hash=file_hash,
                    )
                    threats_found.append(exfil_threat)
                    self._handle_threat(exfil_threat)

        self._seen_connections = current_conn_keys
        self.traffic_monitor.cleanup_terminated()
        return threats_found

    def run_forever(self) -> None:
        """Main loop for running as a daemon or foreground service."""
        self._setup_signals()
        self.write_pid()
        self._running = True

        logger.info("NetSentry Daemon started. Monitoring network traffic...")
        try:
            while self._running:
                try:
                    self.step()
                except Exception as e:
                    logger.error("Error during monitoring loop: %s", e)
                time.sleep(self.config.scan_interval_seconds)
        finally:
            self.remove_pid()
            logger.info("NetSentry Daemon stopped.")
