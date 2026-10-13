"""Command-line interface for NetSentry."""

from __future__ import annotations

import argparse
import importlib.resources
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netsentry import __version__
from netsentry.config import get_config_path, get_data_dir, load_config
from netsentry.core.database import Database
from netsentry.core.detector import ThreatDetector
from netsentry.core.firewall import Firewall
from netsentry.core.monitor import NetworkMonitor
from netsentry.core.threat_intel import ThreatIntel
from netsentry.daemon import SentryDaemon
from netsentry.tui.dashboard import Dashboard

console = Console()


def cmd_status(as_json: bool = False) -> None:
    pid = SentryDaemon.get_running_pid()
    db = Database()
    intel = ThreatIntel()
    stats = db.get_stats()

    if as_json:
        monitor = NetworkMonitor()
        conns = monitor.get_established_connections()
        recent = db.get_recent_alerts(limit=5)
        payload = {
            "version": __version__,
            "running": pid is not None,
            "pid": pid,
            "threat_records": intel.get_count(),
            "total_alerts": stats.get("total_alerts", 0),
            "active_blocked_ips": stats.get("active_blocked_ips", 0),
            "established_connections_count": len(conns),
            "recent_alerts": recent,
        }
        print(json.dumps(payload, indent=2))
        return

    table = Table(title="🛡️ NetSentry Status", box=None)
    table.add_column("Property", style="bold cyan")
    table.add_column("Value")

    table.add_row("Version", __version__)
    if pid:
        table.add_row("Daemon Status", f"[bold green]Running[/bold green] (PID {pid})")
    else:
        table.add_row("Daemon Status", "[bold yellow]Stopped[/bold yellow]")

    table.add_row("Threat Intel Records", str(intel.get_count()))
    table.add_row("Total Recorded Alerts", str(stats.get("total_alerts", 0)))
    table.add_row("Active Blocked IPs", str(stats.get("active_blocked_ips", 0)))
    table.add_row("Config File", str(get_config_path()))
    table.add_row("Data Directory", str(get_data_dir()))

    console.print(table)


def cmd_start(foreground: bool) -> None:
    pid = SentryDaemon.get_running_pid()
    if pid:
        rprint(f"[bold yellow]NetSentry daemon is already running (PID {pid}).[/bold yellow]")
        return

    if foreground:
        rprint("[bold green]Starting NetSentry daemon in foreground... Press Ctrl+C to stop.[/bold green]")
        daemon = SentryDaemon()
        daemon.run_forever()
    else:
        # Start in background using subprocess
        cmd = [sys.executable, "-m", "netsentry.cli", "start", "--foreground"]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.5)
        rprint(f"[bold green]✓ NetSentry daemon started in background (PID {proc.pid}).[/bold green]")
        rprint("Use [cyan]netsentry tui[/cyan] to view live activity or [cyan]netsentry status[/cyan] to check.")


def cmd_stop() -> None:
    pid = SentryDaemon.get_running_pid()
    if not pid:
        rprint("[yellow]NetSentry daemon is not currently running.[/yellow]")
        return

    try:
        os.kill(pid, signal.SIGTERM)
        rprint(f"[green]Sent termination signal to NetSentry daemon (PID {pid}).[/green]")
        for _ in range(10):
            time.sleep(0.2)
            try:
                os.kill(pid, 0)
            except OSError:
                rprint("[bold green]✓ NetSentry daemon stopped.[/bold green]")
                return
        os.kill(pid, signal.SIGKILL)
        rprint("[bold yellow]Force killed daemon.[/bold yellow]")
    except ProcessLookupError:
        rprint("[yellow]Daemon process already terminated.[/yellow]")
        daemon = SentryDaemon()
        daemon.remove_pid()


def cmd_scan() -> None:
    config = load_config()
    intel = ThreatIntel()
    detector = ThreatDetector(config, intel)
    monitor = NetworkMonitor()

    console.print("[bold cyan]Scanning active sockets and listening ports...[/bold cyan]")
    conns = monitor.get_connections()

    table = Table(title="Current Network Sockets")
    table.add_column("Proto", style="cyan")
    table.add_column("State")
    table.add_column("PID", style="magenta")
    table.add_column("Process", style="bold white")
    table.add_column("Local")
    table.add_column("Remote Endpoint", style="yellow")
    table.add_column("Analysis", justify="center")

    threats_count = 0
    for c in conns:
        threat = None
        if c.remote_ip:
            threat = detector.analyze_connection(
                remote_ip=c.remote_ip,
                remote_port=c.remote_port,
                process_name=c.process_name,
                pid=c.pid,
                exe_path=c.exe_path,
                cmdline=c.cmdline,
                status=c.status,
            )

        if threat:
            threats_count += 1
            analysis = f"[bold red]⚠️ {threat.severity}: {threat.threat_type}[/bold red]"
        else:
            analysis = "[green]✓ OK[/green]"

        local_addr = f"{c.local_ip}:{c.local_port}"
        remote_addr = f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else "-"

        table.add_row(
            c.protocol,
            c.status,
            str(c.pid or "-"),
            str(c.process_name or "-"),
            local_addr,
            remote_addr,
            analysis,
        )

    console.print(table)
    if threats_count > 0:
        console.print(f"\n[bold red]Found {threats_count} potential security threats![/bold red]")
    else:
        console.print("\n[bold green]✓ Scan clean. No obvious threats detected.[/bold green]")


def cmd_alerts(limit: int, severity: Optional[str]) -> None:
    db = Database()
    alerts = db.get_recent_alerts(limit=limit, severity=severity)

    if not alerts:
        rprint("[green]No alerts found in database.[/green]")
        return

    table = Table(title=f"Recent Security Alerts (Limit: {limit})", expand=True)
    table.add_column("ID", style="dim", width=6)
    table.add_column("Timestamp", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Threat", style="bold red", width=22)
    table.add_column("Process", style="magenta", width=14)
    table.add_column("Remote Target", style="yellow", width=22)
    table.add_column("Details")
    table.add_column("Blocked", width=8)

    for a in alerts:
        sev = a["severity"]
        sev_style = "bold red" if sev in ("HIGH", "CRITICAL") else "bold yellow"
        blocked_str = "[bold green]YES[/bold green]" if a["blocked"] else "[dim]NO[/dim]"

        table.add_row(
            str(a["id"]),
            a["timestamp"][:19],
            f"[{sev_style}]{sev}[/{sev_style}]",
            a["threat_type"],
            f"{a['process_name'] or '-'} ({a['pid'] or '-'})",
            f"{a['remote_ip']}:{a['remote_port'] or '-'}",
            a["details"] or "-",
            blocked_str,
        )

    console.print(table)


def cmd_block(ip: str, reason: str) -> None:
    fw = Firewall()
    db = Database()
    ti = ThreatIntel()

    success, msg = fw.block_ip(ip)
    if success:
        db.add_blocked_ip(ip, reason)
        ti.add_bad_ip(ip, category="Manual Block")
        rprint(f"[bold green]✓ {msg}[/bold green]")
    else:
        rprint(f"[bold red]✗ {msg}[/bold red]")


def cmd_unblock(ip: str) -> None:
    fw = Firewall()
    db = Database()

    success, msg = fw.unblock_ip(ip)
    db.remove_blocked_ip(ip)
    if success:
        rprint(f"[bold green]✓ {msg}[/bold green]")
    else:
        rprint(f"[yellow]{msg}[/yellow]")


def cmd_update_intel() -> None:
    config = load_config()
    intel = ThreatIntel()
    total_added = 0

    with console.status("[bold cyan]Downloading latest threat intelligence feeds...[/bold cyan]"):
        for url in config.threat_feed_urls:
            console.print(f"Fetching from [cyan]{url}[/cyan]...")
            added = intel.update_from_feed_url(url)
            total_added += added

    rprint(f"[bold green]✓ Threat intelligence updated. Added/refreshed {total_added} indicators.[/bold green]")
    rprint(f"Total threat database records: [bold cyan]{intel.get_count()}[/bold cyan]")


def cmd_tui() -> None:
    dashboard = Dashboard()
    dashboard.run()


def _find_data_dir(subpath: str) -> Optional[Path]:
    """Locate packaged data directory or fallback to project root."""
    try:
        bundled = importlib.resources.files("netsentry").joinpath("data", subpath)
        bundled_path = Path(str(bundled))
        if bundled_path.is_dir():
            return bundled_path
    except Exception:
        pass

    project_dir = Path(__file__).resolve().parent.parent.parent
    candidate = project_dir / subpath
    if candidate.is_dir():
        return candidate

    cwd_candidate = Path.cwd() / subpath
    if cwd_candidate.is_dir():
        return cwd_candidate

    return None


def cmd_install_extension() -> None:
    """Install and enable the GNOME Shell extension."""
    uuid = "netsentry@lukasz-szymanski.github.io"
    gnome_ext_dir = Path.home() / ".local" / "share" / "gnome-shell" / "extensions" / uuid

    ext_source = _find_data_dir("extension")
    if not ext_source or not ext_source.exists():
        rprint("[bold red]Extension source files not found in package.[/bold red]")
        return

    gnome_ext_dir.mkdir(parents=True, exist_ok=True)
    for item in ext_source.iterdir():
        if item.is_file():
            shutil.copy2(item, gnome_ext_dir / item.name)

    rprint(f"[bold green]✓ Copied extension files to {gnome_ext_dir}[/bold green]")

    # Symlink netsentry binary to ~/.local/bin/netsentry if not yet accessible
    local_bin = Path.home() / ".local" / "bin"
    local_bin.mkdir(parents=True, exist_ok=True)
    target_link = local_bin / "netsentry"
    current_bin = shutil.which("netsentry")
    if not current_bin:
        current_bin = str(Path(sys.executable).parent / "netsentry")

    if current_bin and Path(current_bin).exists() and not target_link.exists():
        try:
            target_link.symlink_to(current_bin)
            rprint(f"[bold green]✓ Symlinked {current_bin} -> {target_link}[/bold green]")
        except Exception as e:
            rprint(f"[yellow]Note on ~/.local/bin symlink: {e}[/yellow]")

    # Enable via gnome-extensions CLI
    gnome_ext = shutil.which("gnome-extensions")
    if gnome_ext:
        try:
            subprocess.run([gnome_ext, "enable", uuid], check=False)
            rprint(f"[bold green]✓ Enabled extension '{uuid}' via gnome-extensions.[/bold green]")
        except Exception as e:
            rprint(f"[yellow]Could not enable extension via CLI: {e}[/yellow]")

    rprint("\n[bold cyan]🎉 NetSentry indicator installed successfully![/bold cyan]")
    rprint("The shield icon will appear in the top panel.")
    rprint("[dim]If not visible immediately:[/dim]")
    rprint("  • Under Wayland: Log out and log back in, or restart session.")
    rprint("  • Under X11: Press [bold]Alt + F2[/bold], enter [bold]r[/bold], and press Enter.")


def cmd_uninstall_extension() -> None:
    uuid = "netsentry@lukasz-szymanski.github.io"
    gnome_ext = shutil.which("gnome-extensions")
    if gnome_ext:
        subprocess.run([gnome_ext, "disable", uuid], check=False)

    gnome_ext_dir = Path.home() / ".local" / "share" / "gnome-shell" / "extensions" / uuid
    if gnome_ext_dir.exists():
        shutil.rmtree(gnome_ext_dir)
        rprint(f"[bold green]✓ Uninstalled NetSentry extension from {gnome_ext_dir}[/bold green]")
    else:
        rprint("[yellow]Extension directory not found.[/yellow]")


def cmd_install_service() -> None:
    """Install and enable NetSentry as a systemd user service."""
    sysd_source = _find_data_dir("systemd")
    service_src = sysd_source / "netsentry.service" if sysd_source else None

    user_systemd_dir = Path.home() / ".config" / "systemd" / "user"
    user_systemd_dir.mkdir(parents=True, exist_ok=True)
    service_dest = user_systemd_dir / "netsentry.service"

    # Find the best binary path for netsentry
    netsentry_bin = shutil.which("netsentry")
    if not netsentry_bin:
        cand = Path(sys.executable).parent / "netsentry"
        if cand.exists():
            netsentry_bin = str(cand)
    if not netsentry_bin:
        local_cand = Path.home() / ".local" / "bin" / "netsentry"
        if local_cand.exists():
            netsentry_bin = str(local_cand)
        else:
            netsentry_bin = "/usr/local/bin/netsentry"

    if service_src and service_src.is_file():
        raw_text = service_src.read_text(encoding="utf-8")
        lines = []
        for line in raw_text.splitlines():
            if line.startswith("ExecStart="):
                lines.append(f"ExecStart={netsentry_bin} start --foreground")
            else:
                lines.append(line)
        content = "\n".join(lines) + "\n"
    else:
        content = f"""[Unit]
Description=NetSentry - Linux Network Sentinel and Threat Monitoring Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={netsentry_bin} start --foreground
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=false

[Install]
WantedBy=default.target
"""

    service_dest.write_text(content, encoding="utf-8")
    rprint(f"[bold green]✓ Installed systemd service unit to {service_dest}[/bold green]")

    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            subprocess.run([systemctl, "--user", "daemon-reload"], check=True)
            subprocess.run([systemctl, "--user", "enable", "--now", "netsentry"], check=True)
            rprint("[bold green]✓ Reloaded systemd daemon and enabled/started 'netsentry' user service.[/bold green]")
            rprint("[dim]Check status anytime with: [bold]systemctl --user status netsentry[/bold][/dim]")
        except Exception as e:
            rprint(f"[yellow]Could not automatically start service via systemctl: {e}[/yellow]")
            rprint("You can start it manually with: [bold]systemctl --user enable --now netsentry[/bold]")
    else:
        rprint("[yellow]systemctl not found in PATH; please enable the service manually.[/yellow]")


def cmd_uninstall_service() -> None:
    """Stop, disable, and remove the systemd user service."""
    systemctl = shutil.which("systemctl")
    if systemctl:
        subprocess.run([systemctl, "--user", "stop", "netsentry"], check=False)
        subprocess.run([systemctl, "--user", "disable", "netsentry"], check=False)

    service_dest = Path.home() / ".config" / "systemd" / "user" / "netsentry.service"
    if service_dest.exists():
        service_dest.unlink()
        rprint(f"[bold green]✓ Removed {service_dest}[/bold green]")
    else:
        rprint("[yellow]Systemd user service file not found.[/yellow]")

    if systemctl:
        subprocess.run([systemctl, "--user", "daemon-reload"], check=False)
        rprint("[bold green]✓ Reloaded systemd daemon.[/bold green]")


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description="🛡️ NetSentry — Linux Network Sentinel and Threat Monitoring Daemon",
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # tui
    subparsers.add_parser("tui", help="Launch interactive live terminal dashboard")

    # start
    p_start = subparsers.add_parser("start", help="Start the sentinel monitoring daemon")
    p_start.add_argument("-f", "--foreground", action="store_true", help="Run in foreground")

    # stop
    subparsers.add_parser("stop", help="Stop the running sentinel daemon")

    # status
    p_status = subparsers.add_parser("status", help="Show sentinel daemon status and metrics")
    p_status.add_argument("-j", "--json", action="store_true", help="Output status as JSON")

    # scan
    subparsers.add_parser("scan", help="Run a one-time network socket scan")

    # alerts
    p_alerts = subparsers.add_parser("alerts", help="Display recent security alerts")
    p_alerts.add_argument("-n", "--limit", type=int, default=20, help="Maximum number of alerts to show")
    p_alerts.add_argument("-s", "--severity", type=str, choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by severity")

    # block
    p_block = subparsers.add_parser("block", help="Block an IP address in the firewall")
    p_block.add_argument("ip", help="IP address to block")
    p_block.add_argument("-r", "--reason", default="Manual block via CLI", help="Reason for blocking")

    # unblock
    p_unblock = subparsers.add_parser("unblock", help="Unblock an IP address")
    p_unblock.add_argument("ip", help="IP address to unblock")

    # update-intel
    subparsers.add_parser("update-intel", help="Update threat intelligence feeds from web")

    # install-extension
    subparsers.add_parser("install-extension", help="Install and enable the GNOME Shell top panel extension")

    # uninstall-extension
    subparsers.add_parser("uninstall-extension", help="Uninstall the GNOME Shell top panel extension")

    # install-service
    subparsers.add_parser("install-service", help="Install and enable systemd background user service")

    # uninstall-service
    subparsers.add_parser("uninstall-service", help="Uninstall and stop systemd background user service")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "tui":
        cmd_tui()
    elif args.command == "start":
        cmd_start(foreground=args.foreground)
    elif args.command == "stop":
        cmd_stop()
    elif args.command == "status":
        cmd_status(as_json=args.json)
    elif args.command == "scan":
        cmd_scan()
    elif args.command == "alerts":
        cmd_alerts(limit=args.limit, severity=args.severity)
    elif args.command == "block":
        cmd_block(args.ip, args.reason)
    elif args.command == "unblock":
        cmd_unblock(args.ip)
    elif args.command == "update-intel":
        cmd_update_intel()
    elif args.command == "install-extension":
        cmd_install_extension()
    elif args.command == "uninstall-extension":
        cmd_uninstall_extension()
    elif args.command == "install-service":
        cmd_install_service()
    elif args.command == "uninstall-service":
        cmd_uninstall_service()


if __name__ == "__main__":
    main()
