"""Anomaly and threat detection engine for network activity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from netsentry.config import Config
from netsentry.core.threat_intel import ThreatIntel

SUSPICIOUS_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh"}
SUSPICIOUS_NET_TOOLS = {"nc", "netcat", "ncat", "socat"}
SUSPICIOUS_PATH_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")


@dataclass
class ThreatEvent:
    threat_found: bool
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    score: int     # 0 - 100
    threat_type: str
    details: str
    rule_name: str
    remote_ip: str
    remote_port: Optional[int]
    process_name: Optional[str]
    pid: Optional[int]
    exe_path: Optional[str] = None


class ThreatDetector:
    def __init__(self, config: Config, threat_intel: ThreatIntel):
        self.config = config
        self.threat_intel = threat_intel

    def analyze_connection(
        self,
        remote_ip: str,
        remote_port: Optional[int],
        process_name: Optional[str],
        pid: Optional[int],
        exe_path: Optional[str] = None,
        cmdline: Optional[str] = None,
        status: str = "ESTABLISHED",
    ) -> Optional[ThreatEvent]:
        """Analyze a single connection and determine if it poses a threat."""
        if not remote_ip:
            return None

        # Check Whitelists
        if remote_ip in self.config.whitelist_ips:
            return None
        if process_name and process_name in self.config.whitelist_processes:
            return None

        score = 0
        reasons = []
        rule_name = "Clean"
        threat_type = "None"

        # 1. Threat Intel Check
        ti_match = self.threat_intel.check_ip(remote_ip)
        if ti_match:
            score += 85
            reasons.append(
                f"Known malicious IP ({ti_match.get('category')}, confidence: {ti_match.get('confidence')}%)"
            )
            threat_type = "Malicious IP / C2"
            rule_name = "THREAT_INTEL_MATCH"

        # 2. Suspicious Port
        if remote_port and remote_port in self.config.suspicious_ports:
            score += 60
            reasons.append(f"Connection to suspicious/backdoor port {remote_port}")
            if threat_type == "None":
                threat_type = "Suspicious Port / Backdoor"
                rule_name = "SUSPICIOUS_PORT"

        # 3. Reverse Shell Detection (Shells making outbound network connections)
        proc_lower = (process_name or "").lower()
        if proc_lower in SUSPICIOUS_SHELLS:
            score += 80
            reasons.append(
                f"Potential reverse shell: shell executable '{process_name}' connected to network"
            )
            threat_type = "Potential Reverse Shell"
            rule_name = "REVERSE_SHELL"

        if proc_lower in SUSPICIOUS_NET_TOOLS:
            score += 65
            reasons.append(
                f"Net tool '{process_name}' active socket to remote endpoint"
            )
            if threat_type == "None":
                threat_type = "Suspicious Network Utility"
                rule_name = "NETCAT_ACTIVITY"

        # 4. Binary running from temporary / untrusted directory
        if exe_path:
            for prefix in SUSPICIOUS_PATH_PREFIXES:
                if exe_path.startswith(prefix):
                    score += 90
                    reasons.append(f"Untrusted binary running from {prefix}: {exe_path}")
                    threat_type = "Suspicious Temp Binary"
                    rule_name = "UNTRUSTED_BINARY_PATH"
                    break

        # Check if score exceeds threshold
        score = min(score, 100)
        if score >= self.config.threat_score_threshold:
            severity = "MEDIUM"
            if score >= 90:
                severity = "CRITICAL"
            elif score >= 75:
                severity = "HIGH"

            return ThreatEvent(
                threat_found=True,
                severity=severity,
                score=score,
                threat_type=threat_type,
                details="; ".join(reasons),
                rule_name=rule_name,
                remote_ip=remote_ip,
                remote_port=remote_port,
                process_name=process_name,
                pid=pid,
                exe_path=exe_path,
            )

        return None
