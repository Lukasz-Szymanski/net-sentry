"""Interactive terminal dashboard for NetSentry using Rich."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from netsentry.config import load_config
from netsentry.core.database import Database
from netsentry.core.detector import ThreatDetector
from netsentry.core.monitor import NetworkMonitor
from netsentry.core.threat_intel import ThreatIntel
from netsentry.daemon import SentryDaemon


class Dashboard:
    def __init__(self):
        self.console = Console()
        self.config = load_config()
        self.db = Database()
        self.threat_intel = ThreatIntel()
        self.detector = ThreatDetector(self.config, self.threat_intel)
        self.monitor = NetworkMonitor()

    def generate_header(self) -> Panel:
        daemon_pid = SentryDaemon.get_running_pid()
        if daemon_pid:
            status_text = Text(f"● DAEMON RUNNING (PID {daemon_pid})", style="bold green")
        else:
            status_text = Text("○ DAEMON STOPPED", style="bold yellow")

        stats = self.db.get_stats()
        total_alerts = stats.get("total_alerts", 0)
        blocked_ips = stats.get("active_blocked_ips", 0)

        header_table = Table.grid(expand=True)
        header_table.add_column(justify="left", ratio=1)
        header_table.add_column(justify="right", ratio=1)

        title = Text("🛡️  NETSENTRY — Linux Network Security Sentinel", style="bold cyan")
        info = Text.assemble(
            status_text,
            "  │  Alerts: ",
            (str(total_alerts), "bold red" if total_alerts > 0 else "white"),
            "  │  Blocked IPs: ",
            (str(blocked_ips), "bold magenta"),
            "  │  Feed Rules: ",
            (str(self.threat_intel.get_count()), "bold blue"),
        )

        header_table.add_row(title, info)
        return Panel(header_table, style="cyan")

    def generate_connections_table(self) -> Panel:
        conns = self.monitor.get_established_connections()

        table = Table(expand=True, box=None)
        table.add_column("Proto", style="cyan", width=6)
        table.add_column("PID", style="magenta", width=8)
        table.add_column("Process", style="bold white", width=16)
        table.add_column("Local", style="dim", width=22)
        table.add_column("Remote Endpoint", style="yellow", width=24)
        table.add_column("Security Status", justify="center", width=18)

        # Show at most 15 active connections to fit the screen
        for c in conns[:15]:
            threat = self.detector.analyze_connection(
                remote_ip=c.remote_ip or "",
                remote_port=c.remote_port,
                process_name=c.process_name,
                pid=c.pid,
                exe_path=c.exe_path,
                cmdline=c.cmdline,
                status=c.status,
            )

            if threat:
                status_style = "bold red on #330000" if threat.severity == "CRITICAL" else "bold red"
                status_display = f"⚠️ {threat.severity} ({threat.score})"
            else:
                status_style = "green"
                status_display = "✓ Clean"

            local_str = f"{c.local_ip}:{c.local_port}"
            remote_str = f"{c.remote_ip}:{c.remote_port}" if c.remote_ip else "-"
            proc_display = (c.process_name or "unknown")[:15]

            table.add_row(
                c.protocol,
                str(c.pid or "-"),
                proc_display,
                local_str,
                remote_str,
                Text(status_display, style=status_style),
            )

        if not conns:
            table.add_row("-", "-", "No active connections", "-", "-", Text("Idle", style="dim"))

        return Panel(table, title="[bold]Active Established Network Sockets[/bold]", border_style="blue")

    def generate_alerts_panel(self) -> Panel:
        recent = self.db.get_recent_alerts(limit=5)
        table = Table(expand=True, box=None)
        table.add_column("Time", style="dim", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Process", style="white", width=14)
        table.add_column("Remote IP", style="yellow", width=18)
        table.add_column("Threat Details", style="white")

        for a in recent:
            sev = a.get("severity", "INFO")
            sev_style = "bold red" if sev in ("HIGH", "CRITICAL") else "bold yellow"
            ts_str = a.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts_str)
                time_disp = dt.strftime("%H:%M:%S")
            except Exception:
                time_disp = ts_str[:8]

            table.add_row(
                time_disp,
                Text(sev, style=sev_style),
                str(a.get("process_name") or "-"),
                str(a.get("remote_ip")),
                str(a.get("details") or a.get("threat_type")),
            )

        if not recent:
            table.add_row("-", Text("NONE", style="dim green"), "-", "-", "No security anomalies detected yet.")

        return Panel(table, title="[bold red]Recent Security Alerts & Threat Detections[/bold red]", border_style="red")

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="connections", ratio=3),
            Layout(name="alerts", ratio=2),
            Layout(name="footer", size=1),
        )
        layout["header"].update(self.generate_header())
        layout["connections"].update(self.generate_connections_table())
        layout["alerts"].update(self.generate_alerts_panel())
        layout["footer"].update(Text(" Press Ctrl+C to exit dashboard • Run 'netsentry --help' for CLI commands", style="dim italic center"))
        return layout

    def run(self, refresh_rate: float = 1.5) -> None:
        """Run the interactive TUI live loop."""
        with Live(self.make_layout(), console=self.console, screen=True, refresh_per_second=4) as live:
            try:
                while True:
                    live.update(self.make_layout())
                    time.sleep(refresh_rate)
            except KeyboardInterrupt:
                pass
