"""Unit tests for the interactive TUI Dashboard."""

from unittest.mock import MagicMock, patch
from netsentry.tui.dashboard import Dashboard


def test_dashboard_init():
    dashboard = Dashboard()
    assert dashboard.selected_index == 0
    assert dashboard.inspect_mode is False
    assert dashboard.help_mode is False


def test_dashboard_panels_render():
    dashboard = Dashboard()

    header = dashboard.generate_header()
    assert header is not None

    table = dashboard.generate_connections_table()
    assert table is not None

    alerts = dashboard.generate_alerts_panel()
    assert alerts is not None

    help_panel = dashboard.generate_help_panel()
    assert help_panel is not None

    inspector = dashboard.generate_inspector_panel()
    assert inspector is not None

    layout = dashboard.make_layout()
    assert layout is not None


def test_dashboard_status_message():
    dashboard = Dashboard()
    dashboard.set_status("Test status notification")
    assert dashboard.status_message == "Test status notification"

    footer = dashboard.generate_footer()
    assert "Test status notification" in footer.plain


def test_dashboard_actions_empty():
    dashboard = Dashboard()
    dashboard.cached_conns = []

    dashboard.handle_block_action()
    assert "No connection selected" in (dashboard.status_message or "")

    dashboard.handle_kill_action()
    assert "No connection selected" in (dashboard.status_message or "")
