"""Configuration management for NetSentry."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List


@dataclass
class Config:
    scan_interval_seconds: float = 2.0
    desktop_notifications: bool = True
    notification_cooldown_seconds: int = 30
    auto_block_threats: bool = False
    auto_kill_threats: bool = False
    threat_score_threshold: int = 60
    suspicious_ports: List[int] = field(
        default_factory=lambda: [
            23,     # Telnet
            2323,   # Alt Telnet
            4444,   # Metasploit default listener
            5555,   # ADB / Freeciv / Trojan
            6667,   # IRC (often C2)
            9001,   # Tor relay
            9050,   # Tor SOCKS
            9051,   # Tor control
            1337,   # Elite / Trojan backdoors
            31337,  # Back Orifice
            44444,  # Rootkit default
        ]
    )
    whitelist_ips: List[str] = field(
        default_factory=lambda: [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
        ]
    )
    whitelist_processes: List[str] = field(
        default_factory=lambda: [
            "systemd-resolved",
            "chronyd",
            "ntpd",
            "NetworkManager",
        ]
    )
    threat_feed_urls: List[str] = field(
        default_factory=lambda: [
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
        ]
    )


def get_config_dir() -> Path:
    """Return the configuration directory path."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        base = Path(xdg_config)
    else:
        base = Path.home() / ".config"
    config_dir = base / "netsentry"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_data_dir() -> Path:
    """Return the runtime data directory path."""
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        base = Path(xdg_data)
    else:
        base = Path.home() / ".local" / "share"
    data_dir = base / "netsentry"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_config_path() -> Path:
    return get_config_dir() / "config.json"


def load_config() -> Config:
    """Load config from disk or create default."""
    config_file = get_config_path()
    if not config_file.exists():
        cfg = Config()
        save_config(cfg)
        return cfg

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            data: dict[str, Any] = json.load(f)
        return Config(**data)
    except Exception:
        # Fallback to defaults on corrupted file
        return Config()


def save_config(config: Config) -> None:
    """Save config to disk."""
    config_file = get_config_path()
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(asdict(config), f, indent=2)
