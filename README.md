# NetSentry

[![CI](https://github.com/Lukasz-Szymanski/net-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Lukasz-Szymanski/net-sentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/net-sentry.svg)](https://pypi.org/project/net-sentry/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Linux Daemon](https://img.shields.io/badge/platform-Linux-orange.svg)](https://kernel.org)

**NetSentry** is a lightweight, real-time Linux network monitor and threat sentinel. Running as a background daemon or interactively via an `htop`-style terminal dashboard (TUI), it correlates active network sockets with Linux processes, flags suspicious outbound connections (reverse shells, untrusted `/tmp` binaries, known botnet/C2 nodes), and dispatches alerts or applies firewall rules.

---

## Features

- **Process-Network Correlation**: Maps active sockets to their PID, executable path, SHA-256 hash, process name, and user.
- **Real-Time Threat Detection**:
  - **Reverse Shell Detection**: Flags shells (`bash`, `zsh`, `sh`) or network utilities (`nc`, `socat`) opening remote sockets.
  - **Untrusted Path Execution**: Detects binaries running from temporary directories (`/tmp/`, `/dev/shm/`, `/var/tmp/`).
  - **Suspicious Port Alerts**: Identifies traffic on common backdoor ports (4444, 1337, 31337, 6667, etc.).
  - **Threat Intelligence**: Built-in and downloadable IP reputation feeds (Tor exits, botnet C2s, scanner IPs).
  - **Data Exfiltration Detection**: Alerts when processes transmit outbound data above configured rate or volume thresholds.
- **Interactive Terminal Dashboard (TUI)**: `htop`-style interface with live hotkeys (`↑/↓` select, `b` block IP, `k` kill process, `i` process inspector, `?` help).
- **Alert Dispatcher**: Native Linux desktop notifications, Telegram Bot API, and Discord/Slack webhooks.
- **Multi-Backend Firewall Engine**: Supports `nftables`, `ufw`, and `iptables` with automatic backend detection, IPv6 support, and temporary quarantine timers.
- **Kernel Tracing & eBPF Support**: Socket event probing (`tcp_v4_connect`) with automatic fallback to `/proc` polling (`netsentry bpf-status`).
- **Systemd & GNOME Integration**: User service installer (`netsentry install-service`) and optional GNOME Shell top-panel indicator.

---

## Architecture

```text
                      ┌────────────────────────┐
                      │ Linux Kernel / Sockets │
                      └───────────┬────────────┘
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │    Network Monitor (psutil/proc)    │
               │  Maps sockets to PID & Binary Path  │
               └──────────────────┬──────────────────┘
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │         Threat Detector             │
               ├──────────────────┬──────────────────┤
               │ • Threat Intel   │ • Port Blacklist │
               │ • Shell Sockets  │ • Untrusted Path │
               └──────────────────┬──────────────────┘
                                  │
                  ┌───────────────┼───────────────┐
                  ▼               ▼               ▼
           ┌────────────┐  ┌─────────────┐  ┌────────────┐
           │   Alerts   │  │  SQLite DB  │  │  Firewall  │
           │  (notify)  │  │ (sentry.db) │  │ (nft/ufw)  │
           └────────────┘  └─────────────┘  └────────────┘
```

---

## Quick Start

### 1. Installation

#### Via `pipx` (Recommended)
```bash
pipx install net-sentry
```

#### Via `pip`
```bash
pip install net-sentry
```

#### From source
```bash
git clone https://github.com/Lukasz-Szymanski/net-sentry.git
cd net-sentry

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Interactive TUI Dashboard

```bash
netsentry tui
```

### 3. Background Monitoring Daemon

```bash
# Start background daemon
netsentry start

# Check running status
netsentry status
```

### 4. GNOME Top Panel Indicator (Optional)

```bash
netsentry install-extension
```

Log out and log back in (Wayland) or press `Alt + F2` -> `r` (X11) to enable the panel indicator.

---

## CLI Commands

| Command | Description |
| :--- | :--- |
| `netsentry tui` | Open the interactive real-time terminal dashboard |
| `netsentry start` | Start the background monitoring daemon |
| `netsentry start -f` | Run the monitoring daemon in foreground |
| `netsentry stop` | Stop the running daemon |
| `netsentry status` | Display daemon status, total alerts, and active connections |
| `netsentry status --json` | Output system metrics and alerts in JSON format |
| `netsentry scan` | Run an instant socket scan and print the security table |
| `netsentry alerts` | Display recent security events recorded in SQLite |
| `netsentry block <IP> [-d <min>]` | Block IP in firewall (with optional quarantine duration in minutes) |
| `netsentry blocked` | List currently blocked IPs and remaining quarantine time |
| `netsentry unblock <IP>` | Remove firewall rule for IP |
| `netsentry traffic` | Display per-process bandwidth usage and exfiltration metrics |
| `netsentry bpf-status` | Check eBPF kernel tracing readiness and diagnostics |
| `netsentry kill <PID>` | Terminate a suspicious process by PID |
| `netsentry lookup <IP>` | Look up reverse DNS, GeoIP, and threat feed status for an IP |
| `netsentry test-notify` | Test desktop, Telegram, and webhook notification channels |
| `netsentry update-intel` | Download updated threat intelligence feeds |
| `netsentry install-service` | Install and enable the systemd user service |
| `netsentry uninstall-service` | Stop and remove the systemd user service |
| `netsentry install-extension` | Install and enable the GNOME Shell top-panel extension |
| `netsentry uninstall-extension` | Remove the GNOME Shell extension |

---

## Configuration

Configuration is created automatically on first run at `~/.config/netsentry/config.json`:

```json
{
  "scan_interval_seconds": 2.0,
  "desktop_notifications": true,
  "notification_cooldown_seconds": 30,
  "auto_block_threats": false,
  "auto_kill_threats": false,
  "threat_score_threshold": 60,
  "telegram_enabled": false,
  "telegram_bot_token": "",
  "telegram_chat_id": "",
  "webhook_enabled": false,
  "webhook_url": "",
  "suspicious_ports": [23, 2323, 4444, 5555, 6667, 9001, 9050, 9051, 1337, 31337],
  "whitelist_ips": ["127.0.0.1", "::1", "0.0.0.0"],
  "whitelist_processes": ["systemd-resolved", "chronyd", "ntpd", "NetworkManager"]
}
```

---

## Testing

```bash
pytest -v
```

---

## License

Released under the [MIT License](LICENSE).
