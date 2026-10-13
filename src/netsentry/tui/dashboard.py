"""Interactive terminal dashboard for NetSentry with live hotkeys and inspector."""

from __future__ import annotations

import os
import select
import sys
import termios
import time
import tty
from datetime import datetime
from typing import List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from netsentry.config import load_config
from netsentry.core.database import Database
from netsentry.core.detector import ThreatDetector
from netsentry.core.firewall import Firewall
from netsentry.core.forensics import get_process_forensics
from netsentry.core.monitor import ConnectionInfo, NetworkMonitor
from netsentry.core.resolver import IPResolver
from netsentry.core.terminator import kill_process
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
        self.resolver = IPResolver(db=self.db)
        self.firewall = Firewall()

        self.selected_index: int = 0
        self.inspect_mode: bool = False
        self.help_mode: bool = False
        self.status_message: Optional[str] = None
        self.status_message_time: float = 0.0
        self.cached_conns: List[ConnectionInfo] = []

    def set_status(self, message: str) -> None:
        self.status_message = message
        self.status_message_time = time.time()

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
        self.cached_conns = conns

        if conns:
            self.selected_index = max(0, min(self.selected_index, len(conns) - 1))
        else:
            self.selected_index = 0

        table = Table(expand=True, box=None)
        table.add_column(" ", width=2)
        table.add_column("Proto", style="cyan", width=6)
        table.add_column("PID", style="magenta", width=7)
        table.add_column("Process", style="bold white", width=14)
        table.add_column("Local", style="dim", width=20)
        table.add_column("Remote Endpoint", style="yellow", width=26)
        table.add_column("Security Status", justify="center", width=18)

        # Show a window of connections centered around selection
        max_rows = 12
        start_idx = max(0, min(self.selected_index - max_rows // 2, max(0, len(conns) - max_rows)))
        visible_conns = conns[start_idx : start_idx + max_rows]

        for i, c in enumerate(visible_conns):
            actual_idx = start_idx + i
            is_selected = actual_idx == self.selected_index

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
            if c.remote_ip:
                info = self.resolver.resolve(c.remote_ip, fetch_geo=False)
                badge = f" {info.badge}" if info.badge else ""
                remote_str = f"{c.remote_ip}:{c.remote_port}{badge}"
            else:
                remote_str = "-"

            proc_display = (c.process_name or "unknown")[:14]
            cursor = "▶" if is_selected else " "
            row_style = "bold white on #1a2332" if is_selected else None

            table.add_row(
                cursor,
                c.protocol,
                str(c.pid or "-"),
                proc_display,
                local_str,
                remote_str,
                Text(status_display, style=status_style),
                style=row_style,
            )

        if not conns:
            table.add_row(" ", "-", "-", "No active connections", "-", "-", Text("Idle", style="dim"))

        count_str = f"({self.selected_index + 1}/{len(conns)})" if conns else "(0)"
        return Panel(
            table,
            title=f"[bold]Active Established Network Sockets[/bold] [dim]{count_str}[/dim]",
            border_style="blue",
        )

    def generate_inspector_panel(self) -> Panel:
        """Detailed inspector modal for selected connection."""
        if not self.cached_conns or self.selected_index >= len(self.cached_conns):
            return Panel(Text("No connection selected for inspection", style="dim"), title="[bold]Inspector[/bold]")

        conn = self.cached_conns[self.selected_index]
        forensics = get_process_forensics(conn.pid) if conn.pid else {}
        ip_info = self.resolver.resolve(conn.remote_ip or "", fetch_geo=True) if conn.remote_ip else None
        ti_match = self.threat_intel.check_ip(conn.remote_ip or "") if conn.remote_ip else None

        grid = Table.grid(expand=True, padding=(0, 2))
        grid.add_column(style="cyan", ratio=1)
        grid.add_column(style="yellow", ratio=1)

        # Process metadata
        proc_text = Text()
        proc_text.append("Process Forensics:\n", style="bold underline")
        proc_text.append(f"• Name: {conn.process_name or '-'} (PID: {conn.pid or '-'})\n")
        proc_text.append(f"• Executable: {forensics.get('exe') or conn.exe_path or '-'}\n")
        proc_text.append(f"• SHA256: {forensics.get('file_hash_sha256') or '[dim]Not available[/dim]'}\n")
        proc_text.append(f"• Command: {(forensics.get('cmdline') or conn.cmdline or '-')[:45]}\n")
        proc_text.append(f"• User: {forensics.get('username') or conn.username or '-'}")

        # Remote IP metadata
        ip_text = Text()
        ip_text.append("Remote Target Intelligence:\n", style="bold underline")
        if ip_info:
            ip_text.append(f"• Endpoint: {conn.remote_ip}:{conn.remote_port} {ip_info.badge}\n")
            ip_text.append(f"• Hostname: {ip_info.hostname or '[dim]Unresolved[/dim]'}\n")
            ip_text.append(f"• Location: {ip_info.city or '-'}, {ip_info.country_name or '-'}\n")
            ip_text.append(f"• Organization: {(ip_info.org or '-')[:30]}\n")
            if ti_match:
                ip_text.append(f"• Threat Intel: [bold red]MATCH ({ti_match.get('category')})[/bold red]")
            else:
                ip_text.append("• Threat Intel: [green]No match[/green]")
        else:
            ip_text.append("• No remote IP associated")

        grid.add_row(proc_text, ip_text)
        return Panel(
            grid,
            title="[bold yellow]🔍 Process & Target Deep Inspector (Press [bold]i[/bold] to close)[/bold yellow]",
            border_style="yellow",
        )

    def generate_help_panel(self) -> Panel:
        """Help modal showing available keyboard controls."""
        table = Table(expand=True, box=None)
        table.add_column("Key", style="bold cyan", width=12)
        table.add_column("Action", style="white")

        table.add_row("↑ / ↓", "Navigate up and down through connection list")
        table.add_row("b", "Block selected remote IP in firewall (iptables DROP)")
        table.add_row("k", "Terminate / kill selected process by PID (SIGTERM/SIGKILL)")
        table.add_row("i / Enter", "Toggle deep forensic inspector for selected socket")
        table.add_row("? / h", "Toggle this help view")
        table.add_row("q / ESC", "Exit dashboard")

        return Panel(
            table,
            title="[bold green]⌨️ NetSentry Interactive Keyboard Controls (Press [bold]?/h[/bold] to close)[/bold green]",
            border_style="green",
        )

    def generate_alerts_panel(self) -> Panel:
        recent = self.db.get_recent_alerts(limit=5)
        table = Table(expand=True, box=None)
        table.add_column("Time", style="dim", width=10)
        table.add_column("Severity", width=9)
        table.add_column("Process", style="white", width=13)
        table.add_column("Remote IP", style="yellow", width=18)
        table.add_column("Status", width=12)
        table.add_column("Details", style="white")

        for a in recent:
            sev = a.get("severity", "INFO")
            sev_style = "bold red" if sev in ("HIGH", "CRITICAL") else "bold yellow"
            ts_str = a.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts_str)
                time_disp = dt.strftime("%H:%M:%S")
            except Exception:
                time_disp = ts_str[:8]

            actions = []
            if a.get("blocked"):
                actions.append("BLOCKED")
            if a.get("killed"):
                actions.append("KILLED")
            action_disp = Text(", ".join(actions) if actions else "LOGGED", style="bold red" if actions else "dim")

            table.add_row(
                time_disp,
                Text(sev, style=sev_style),
                str(a.get("process_name") or "-"),
                str(a.get("remote_ip")),
                action_disp,
                str(a.get("details") or a.get("threat_type")),
            )

        if not recent:
            table.add_row("-", Text("NONE", style="dim green"), "-", "-", "-", "No security anomalies detected yet.")

        return Panel(table, title="[bold red]Recent Security Alerts & Threat Detections[/bold red]", border_style="red")

    def generate_footer(self) -> Text:
        now = time.time()
        if self.status_message and now - self.status_message_time < 4.0:
            return Text.from_markup(f" [bold cyan]STATUS:[/bold cyan] {self.status_message}")

        return Text.from_markup(
            " [dim][bold]↑/↓[/bold] Select  •  [bold]b[/bold] Block IP  •  [bold]k[/bold] Kill PID  •  [bold]i[/bold] Inspect  •  [bold]?[/bold] Help  •  [bold]q[/bold] Quit[/dim]"
        )

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="connections", ratio=3),
            Layout(name="bottom", ratio=2),
            Layout(name="footer", size=1),
        )
        layout["header"].update(self.generate_header())
        layout["connections"].update(self.generate_connections_table())

        if self.help_mode:
            layout["bottom"].update(self.generate_help_panel())
        elif self.inspect_mode:
            layout["bottom"].update(self.generate_inspector_panel())
        else:
            layout["bottom"].update(self.generate_alerts_panel())

        layout["footer"].update(self.generate_footer())
        return layout

    def _read_key(self, timeout: float = 0.4) -> Optional[str]:
        """Read a single keypress or escape sequence non-blockingly."""
        if not sys.stdin.isatty():
            time.sleep(timeout)
            return None

        rlist, _, _ = select.select([sys.stdin], [], [], timeout)
        if not rlist:
            return None

        ch = sys.stdin.read(1)
        if ch == "\x1b":
            r2, _, _ = select.select([sys.stdin], [], [], 0.05)
            if r2:
                ch2 = sys.stdin.read(1)
                if ch2 == "[":
                    r3, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if r3:
                        ch3 = sys.stdin.read(1)
                        if ch3 == "A":
                            return "UP"
                        elif ch3 == "B":
                            return "DOWN"
                        elif ch3 == "C":
                            return "RIGHT"
                        elif ch3 == "D":
                            return "LEFT"
            return "ESC"
        return ch

    def handle_block_action(self) -> None:
        if not self.cached_conns or self.selected_index >= len(self.cached_conns):
            self.set_status("[yellow]No connection selected to block[/yellow]")
            return

        conn = self.cached_conns[self.selected_index]
        if not conn.remote_ip:
            self.set_status("[yellow]Selected connection has no remote IP[/yellow]")
            return

        success, msg = self.firewall.block_ip(conn.remote_ip)
        if success:
            self.db.add_blocked_ip(conn.remote_ip, reason=f"Blocked via TUI (PID {conn.pid})")
            self.threat_intel.add_bad_ip(conn.remote_ip, category="Manual Block")
            self.set_status(f"[bold green]✓ Blocked {conn.remote_ip} in firewall![/bold green]")
        else:
            self.set_status(f"[bold red]✗ {msg}[/bold red]")

    def handle_kill_action(self) -> None:
        if not self.cached_conns or self.selected_index >= len(self.cached_conns):
            self.set_status("[yellow]No connection selected to terminate[/yellow]")
            return

        conn = self.cached_conns[self.selected_index]
        if not conn.pid:
            self.set_status("[yellow]Selected connection has no PID[/yellow]")
            return

        success, msg = kill_process(conn.pid, force=False)
        if success:
            with self.db._get_connection() as c:
                c.cursor().execute("UPDATE alerts SET killed = 1 WHERE pid = ?", (conn.pid,))
                c.commit()
            self.set_status(f"[bold green]✓ {msg}![/bold green]")
        else:
            self.set_status(f"[bold red]✗ {msg}[/bold red]")

    def run(self, refresh_rate: float = 0.5) -> None:
        """Run the interactive live TUI dashboard loop with key event processing."""
        is_tty = sys.stdin.isatty()
        old_settings = None

        if is_tty:
            old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())

        try:
            with Live(self.make_layout(), console=self.console, screen=True, refresh_per_second=6) as live:
                while True:
                    live.update(self.make_layout())
                    key = self._read_key(timeout=refresh_rate)

                    if not key:
                        continue

                    if key in ("q", "Q", "ESC"):
                        if self.help_mode or self.inspect_mode:
                            self.help_mode = False
                            self.inspect_mode = False
                        else:
                            break
                    elif key == "UP":
                        self.selected_index = max(0, self.selected_index - 1)
                    elif key == "DOWN":
                        self.selected_index += 1
                    elif key in ("b", "B"):
                        self.handle_block_action()
                    elif key in ("k", "K"):
                        self.handle_kill_action()
                    elif key in ("i", "I", "\n", "\r"):
                        self.inspect_mode = not self.inspect_mode
                        self.help_mode = False
                    elif key in ("?", "h", "H"):
                        self.help_mode = not self.help_mode
                        self.inspect_mode = False

        except KeyboardInterrupt:
            pass
        finally:
            if is_tty and old_settings:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
