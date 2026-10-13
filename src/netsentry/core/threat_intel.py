"""Threat intelligence feed manager and IP reputation engine."""

from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import urllib.request

from netsentry.config import get_data_dir

logger = logging.getLogger(__name__)

# Pre-seeded well-known malicious / scanner / testing ranges
SEED_MALICIOUS_IPS = {
    # Known scanner test IPs / Tor exits / sample malicious indicators
    "185.220.101.5": {"category": "Tor Exit Node", "confidence": 85},
    "185.220.101.6": {"category": "Tor Exit Node", "confidence": 85},
    "198.51.100.66": {"category": "Simulated C2 Server", "confidence": 100},
    "203.0.113.199": {"category": "Simulated Botnet Controller", "confidence": 100},
    "45.154.255.89": {"category": "Known Masscan / Brute Force", "confidence": 90},
    "194.26.29.112": {"category": "Known Malicious Scanner", "confidence": 90},
}


class ThreatIntel:
    def __init__(self, cache_file: Optional[Path] = None):
        if cache_file is None:
            cache_file = get_data_dir() / "threat_intel_cache.json"
        self.cache_file = cache_file
        self.malicious_ips: Dict[str, Dict[str, Any]] = dict(SEED_MALICIOUS_IPS)
        self.custom_blocked: Set[str] = set()
        self._load_cache()

    def _load_cache(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                loaded_ips = data.get("ips", {})
                self.malicious_ips.update(loaded_ips)
                logger.info("Loaded %d threat intelligence records from cache", len(self.malicious_ips))
        except Exception as e:
            logger.warning("Failed to load threat intel cache: %s", e)

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump({"ips": self.malicious_ips}, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save threat intel cache: %s", e)

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check if an IP is flagged as malicious."""
        if not ip:
            return None

        if ip in self.custom_blocked:
            return {"category": "Custom Blacklist", "confidence": 100, "source": "Manual"}

        if ip in self.malicious_ips:
            info = self.malicious_ips[ip]
            return {
                "category": info.get("category", "Threat Feed Match"),
                "confidence": info.get("confidence", 80),
                "source": info.get("source", "Threat Intelligence"),
            }

        # Ignore local / private / loopback addresses for external lookups
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_private or addr.is_multicast or addr.is_reserved:
                return None
        except ValueError:
            return None

        return None

    def add_bad_ip(self, ip: str, category: str = "Manual Entry", confidence: int = 100) -> None:
        self.malicious_ips[ip] = {
            "category": category,
            "confidence": confidence,
            "source": "Local Admin",
        }
        self._save_cache()

    def update_from_feed_url(self, url: str, timeout: int = 10) -> int:
        """Download plain-text IP list from a threat feed URL."""
        added = 0
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "NetSentry-Linux/0.1 (Cybersecurity Monitor)"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as response:
                content = response.read().decode("utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    ip = parts[0]
                    try:
                        ipaddress.ip_address(ip)
                        self.malicious_ips[ip] = {
                            "category": "External Threat Feed",
                            "confidence": 75,
                            "source": url,
                        }
                        added += 1
                    except ValueError:
                        continue

            if added > 0:
                self._save_cache()
                logger.info("Updated %d threat IPs from %s", added, url)
        except Exception as e:
            logger.error("Failed to update threat intel feed from %s: %s", url, e)
        return added

    def get_count(self) -> int:
        return len(self.malicious_ips)
