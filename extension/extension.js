import GObject from 'gi://GObject';
import St from 'gi://St';
import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import Gio from 'gi://Gio';

import { Extension, gettext as _ } from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';

const NetSentryIndicator = GObject.registerClass(
class NetSentryIndicator extends PanelMenu.Button {
    _init(extension) {
        super._init(0.0, 'NetSentryIndicator');
        this._extension = extension;
        this._timeoutId = null;

        const box = new St.BoxLayout({ style_class: 'panel-status-menu-box' });

        this._icon = new St.Icon({
            icon_name: 'security-high-symbolic',
            style_class: 'system-status-icon netsentry-icon',
        });
        box.add_child(this._icon);

        this._badge = new St.Label({
            text: '',
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'netsentry-badge',
            visible: false,
        });
        box.add_child(this._badge);

        this.add_child(box);

        this._buildMenu();
        this._refresh();

        // Refresh status every 3 seconds
        this._timeoutId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 3, () => {
            this._refresh();
            return GLib.SOURCE_CONTINUE;
        });
    }

    _buildMenu() {
        this.menu.removeAll();

        // Title
        const titleItem = new PopupMenu.PopupMenuItem(_('🛡️ NetSentry Sentinel'), { reactive: false });
        titleItem.label.clutter_text.set_markup('<b>🛡️ NetSentry Sentinel</b>');
        this.menu.addMenuItem(titleItem);

        // Status Label
        this._statusItem = new PopupMenu.PopupMenuItem(_('Status: Checking...'), { reactive: false });
        this.menu.addMenuItem(this._statusItem);

        // Daemon Switch / Toggle
        this._toggleDaemonItem = new PopupMenu.PopupMenuItem(_('Start Monitoring Daemon'));
        this._toggleDaemonItem.connect('activate', () => {
            this._toggleDaemon();
        });
        this.menu.addMenuItem(this._toggleDaemonItem);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        // Metrics Items
        this._connsItem = new PopupMenu.PopupMenuItem(_('🌐 Active Sockets: -'), { reactive: false });
        this.menu.addMenuItem(this._connsItem);

        this._alertsItem = new PopupMenu.PopupMenuItem(_('⚠️ Recorded Alerts: -'), { reactive: false });
        this.menu.addMenuItem(this._alertsItem);

        this._blockedItem = new PopupMenu.PopupMenuItem(_('🚫 Blocked IPs: -'), { reactive: false });
        this.menu.addMenuItem(this._blockedItem);

        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());

        // Quick Actions
        const scanItem = new PopupMenu.PopupMenuItem(_('🔍 Run Socket Scan Now'));
        scanItem.connect('activate', () => {
            this._runCommandAsync('netsentry scan');
            this._extension.notify(_('NetSentry'), _('Socket scan triggered'));
        });
        this.menu.addMenuItem(scanItem);

        const tuiItem = new PopupMenu.PopupMenuItem(_('🖥️ Open Terminal Dashboard (TUI)'));
        tuiItem.connect('activate', () => {
            this._openTerminalDashboard();
        });
        this.menu.addMenuItem(tuiItem);

        const updateItem = new PopupMenu.PopupMenuItem(_('🔄 Update Threat Intelligence'));
        updateItem.connect('activate', () => {
            this._runCommandAsync('netsentry update-intel');
            this._extension.notify(_('NetSentry'), _('Updating threat intelligence feeds...'));
        });
        this.menu.addMenuItem(updateItem);
    }

    _getStatusData() {
        const home = GLib.get_home_dir();
        const commands = [
            'netsentry status --json',
            `${home}/.local/bin/netsentry status --json`,
            `${home}/Projects/Github/net-sentry/.venv/bin/netsentry status --json`,
        ];

        for (const cmd of commands) {
            try {
                const [ok, stdout, stderr, exitCode] = GLib.spawn_command_line_sync(cmd);
                if (ok && exitCode === 0) {
                    const text = new TextDecoder().decode(stdout);
                    return JSON.parse(text);
                }
            } catch (e) {
                // Try next
            }
        }
        return null;
    }

    _runCommandAsync(cmd) {
        const home = GLib.get_home_dir();
        const fullCmd = `bash -c "PATH=$PATH:${home}/.local/bin:${home}/Projects/Github/net-sentry/.venv/bin ${cmd}"`;
        try {
            GLib.spawn_command_line_async(fullCmd);
        } catch (e) {
            log(`[NetSentry] Failed to run async command: ${e}`);
        }
    }

    _openTerminalDashboard() {
        const home = GLib.get_home_dir();
        const runCmd = `PATH=$PATH:${home}/.local/bin:${home}/Projects/Github/net-sentry/.venv/bin netsentry tui`;
        const terminals = [
            `ptyxis -s -- bash -c "${runCmd}"`,
            `gnome-terminal -- bash -c "${runCmd}"`,
            `x-terminal-emulator -e bash -c "${runCmd}"`,
        ];

        for (const term of terminals) {
            try {
                const [ok] = GLib.spawn_command_line_async(term);
                if (ok) return;
            } catch (e) {}
        }
    }

    _toggleDaemon() {
        const data = this._getStatusData();
        if (data && data.running) {
            this._runCommandAsync('netsentry stop');
            this._extension.notify(_('NetSentry'), _('Stopping background monitor...'));
        } else {
            this._runCommandAsync('netsentry start');
            this._extension.notify(_('NetSentry'), _('Starting background monitor...'));
        }
        GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 1, () => {
            this._refresh();
            return GLib.SOURCE_REMOVE;
        });
    }

    _refresh() {
        const data = this._getStatusData();
        if (!data) {
            this._icon.icon_name = 'security-low-symbolic';
            this._statusItem.label.clutter_text.set_markup('<span color="#f6d32d">○ NetSentry: CLI Offline</span>');
            this._toggleDaemonItem.label.text = _('Start Monitoring Daemon');
            this._badge.visible = false;
            return;
        }

        const isRunning = data.running;
        const totalAlerts = data.total_alerts || 0;
        const blockedIps = data.active_blocked_ips || 0;
        const activeConns = data.established_connections_count || 0;

        if (isRunning) {
            if (totalAlerts > 0) {
                this._icon.icon_name = 'dialog-warning-symbolic';
                this._statusItem.label.clutter_text.set_markup(
                    `<span color="#e01b24">● Protected — ${totalAlerts} Alert(s)</span>`
                );
                this._badge.text = `${totalAlerts}`;
                this._badge.visible = true;
            } else {
                this._icon.icon_name = 'security-high-symbolic';
                this._statusItem.label.clutter_text.set_markup(
                    '<span color="#33d17a">● Protected & Monitoring</span>'
                );
                this._badge.visible = false;
            }
            this._toggleDaemonItem.label.text = _('⏹ Stop Monitoring Daemon');
        } else {
            this._icon.icon_name = 'security-low-symbolic';
            this._statusItem.label.clutter_text.set_markup(
                '<span color="#f6d32d">○ Monitoring Inactive</span>'
            );
            this._badge.visible = false;
            this._toggleDaemonItem.label.text = _('▶ Start Monitoring Daemon');
        }

        this._connsItem.label.text = `🌐 Active Sockets: ${activeConns}`;
        this._alertsItem.label.text = `⚠️ Recorded Alerts: ${totalAlerts}`;
        this._blockedItem.label.text = `🚫 Blocked IPs: ${blockedIps}`;
    }

    destroy() {
        if (this._timeoutId) {
            GLib.Source.remove(this._timeoutId);
            this._timeoutId = null;
        }
        super.destroy();
    }
});

export default class NetSentryExtension extends Extension {
    enable() {
        this._indicator = new NetSentryIndicator(this);
        Main.panel.addToStatusArea(this.uuid, this._indicator);
    }

    disable() {
        if (this._indicator) {
            this._indicator.destroy();
            this._indicator = null;
        }
    }

    notify(title, message) {
        Main.notify(title, message);
    }
}
