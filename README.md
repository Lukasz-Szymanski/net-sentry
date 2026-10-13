# 🛡️ NetSentry

[![CI](https://github.com/Lukasz-Szymanski/net-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/Lukasz-Szymanski/net-sentry/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/net-sentry.svg)](https://pypi.org/project/net-sentry/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Linux Daemon](https://img.shields.io/badge/platform-Linux-orange.svg)](https://kernel.org)

**NetSentry** is a lightweight, real-time Linux network bodyguard and threat sentinel. Running silently in the background or interactively via an htop-style terminal dashboard (TUI), NetSentry correlates network sockets with Linux processes, flags suspicious outbound connections (reverse shells, untrusted `/tmp` binaries, known malicious botnets/C2 nodes), and dispatches desktop notifications or executes firewall countermeasures.

---

## ✨ Features

- 🕵️ **Process-Network Correlation**: Maps every active socket to its PID, executable path, process name, and user.
- 🚨 **Real-Time Threat Detection**:
  - **Reverse Shell Detection**: Detects shells (`bash`, `zsh`, `sh`) or net tools (`nc`, `socat`) opening remote sockets.
  - **Untrusted Path Execution**: Flags binaries running from temporary directories like `/tmp/`, `/dev/shm/`, or `/var/tmp/`.
  - **Suspicious Port Alerts**: Identifies connections on backdoor ports (4444, 1337, 31337, 6667, etc.).
  - **Threat Intelligence**: Built-in and downloadable IP reputation feeds (Tor exits, botnet C2s, scanner IPs).
- 🖥️ **Live Terminal Dashboard (TUI)**: Beautiful `htop`-style live monitoring dashboard built with Rich.
- 🔔 **Linux Desktop Notifications**: Native `notify-send` desktop popups with rate-limiting and urgency levels.
- 🧱 **Firewall Integration**: One-click or automated IP dropping via `iptables` / `nftables` with loopback protection.
- ⚙️ **Systemd Integration**: Single-command user service setup (`netsentry install-service`).

---

## 🏗️ Architecture

```
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
           │ Desktop UI │  │  SQLite DB  │  │  Firewall  │
           │ (notify)   │  │  (sentry.db)│  │ (iptables) │
           └────────────┘  └─────────────┘  └────────────┘
```

---

## 🚀 Quick Start

### 1. Installation

#### Via `pipx` (Recommended on Linux)
```bash
pipx install net-sentry
```

#### Via `pip`
```bash
pip install net-sentry
```

#### From source (for development)
```bash
git clone https://github.com/Lukasz-Szymanski/net-sentry.git
cd net-sentry

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Launch Interactive TUI Dashboard

```bash
netsentry tui
```

### 3. Start Background Monitoring Daemon

```bash
# Start background daemon
netsentry start

# Check running status
netsentry status
```

### 4. Install GNOME Top Panel Indicator (Optional)

To show the live shield status on the Linux top panel:

```bash
netsentry install-extension
```

Log out and log back in (Wayland) or press `Alt + F2` -> `r` (X11) to activate the shield in your top bar.

---

## 📖 CLI Commands

| Command | Description |
| :--- | :--- |
| `netsentry tui` | Open the interactive real-time terminal dashboard |
| `netsentry start` | Start the background monitoring daemon |
| `netsentry start -f` | Run the monitoring daemon in foreground |
| `netsentry stop` | Stop the running daemon |
| `netsentry status` | Display daemon status, total alerts, and active connections |
| `netsentry status --json` | Output system metrics and alerts in JSON format |
| `netsentry scan` | Run an instant socket scan and print security analysis table |
| `netsentry alerts` | Display recent security events recorded in SQLite |
| `netsentry block <IP>` | Add IP to blacklist and apply firewall DROP rule |
| `netsentry unblock <IP>` | Remove firewall DROP rule for IP |
| `netsentry update-intel` | Download updated threat intelligence feeds |
| `netsentry install-service` | Install and enable the background systemd user service |
| `netsentry uninstall-service` | Stop and remove the systemd user service |
| `netsentry install-extension` | Install and enable the GNOME Shell top panel extension |
| `netsentry uninstall-extension` | Remove the GNOME Shell extension |

---

## ⚙️ Configuration

Configuration is automatically generated on first run at:
`~/.config/netsentry/config.json`

```json
{
  "scan_interval_seconds": 2.0,
  "desktop_notifications": true,
  "notification_cooldown_seconds": 30,
  "auto_block_threats": false,
  "threat_score_threshold": 60,
  "suspicious_ports": [23, 2323, 4444, 5555, 6667, 9001, 9050, 9051, 1337, 31337],
  "whitelist_ips": ["127.0.0.1", "::1", "0.0.0.0"],
  "whitelist_processes": ["systemd-resolved", "chronyd", "ntpd", "NetworkManager"]
}
```

---

## 🐧 Systemd Service (Autostart)

To enable NetSentry as a systemd user service with a single command:

```bash
netsentry install-service
```

To stop and remove the service:

```bash
netsentry uninstall-service
```

---

## 🧪 Testing

```bash
pytest -v
```

---

## 📜 License

Released under the [MIT License](LICENSE).
