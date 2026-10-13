"""Multi-channel notification dispatcher (Desktop, Telegram, Webhook/Discord)."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Any, Dict, Optional, Tuple

import requests

from netsentry.config import Config, load_config

logger = logging.getLogger(__name__)


class Notifier:
    """Dispatches security alerts across desktop, Telegram, and Webhook/Discord."""

    def __init__(self, config: Optional[Config] = None, cooldown_seconds: Optional[int] = None):
        self.config = config or load_config()
        self.cooldown_seconds = (
            cooldown_seconds
            if cooldown_seconds is not None
            else self.config.notification_cooldown_seconds
        )
        self.notify_send_path = shutil.which("notify-send")
        self._last_alert_time: Dict[str, float] = {}

    def send_desktop(self, title: str, message: str, severity: str = "HIGH") -> Tuple[bool, str]:
        """Dispatch native Linux desktop notification via notify-send."""
        if not self.notify_send_path:
            return False, "notify-send binary not found on system"

        urgency = "normal"
        icon = "security-high"
        sev_upper = severity.upper()
        if sev_upper == "CRITICAL":
            urgency = "critical"
            icon = "dialog-error"
        elif sev_upper == "LOW":
            urgency = "low"

        cmd = [
            self.notify_send_path,
            "-a",
            "NetSentry",
            "-u",
            urgency,
            "-i",
            icon,
            title,
            message,
        ]

        try:
            res = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                return True, "Desktop notification sent successfully"
            return False, f"notify-send returned code {res.returncode}: {res.stderr}"
        except Exception as e:
            return False, f"Failed to execute notify-send: {e}"

    def send_telegram(self, title: str, message: str, severity: str = "HIGH") -> Tuple[bool, str]:
        """Send security alert to a Telegram chat via Bot API."""
        token = self.config.telegram_bot_token.strip()
        chat_id = self.config.telegram_chat_id.strip()

        if not token or not chat_id:
            return False, "Telegram bot token or chat ID is not configured"

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        sev_emoji = "🚨" if severity.upper() in ("HIGH", "CRITICAL") else "⚠️"
        text = f"<b>{sev_emoji} {title}</b>\n\n<pre>{message}</pre>"

        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }

        try:
            resp = requests.post(url, json=payload, timeout=5.0)
            if resp.status_code == 200:
                return True, "Telegram message sent successfully"
            data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
            err_desc = data.get("description", resp.text)
            return False, f"Telegram API error ({resp.status_code}): {err_desc}"
        except Exception as e:
            return False, f"Telegram request failed: {e}"

    def send_webhook(self, title: str, message: str, severity: str = "HIGH") -> Tuple[bool, str]:
        """Send security alert to a Webhook (Discord, Slack, or generic HTTP endpoint)."""
        webhook_url = self.config.webhook_url.strip()
        if not webhook_url:
            return False, "Webhook URL is not configured"

        is_discord = "discord.com" in webhook_url or "discordapp.com" in webhook_url
        sev_upper = severity.upper()

        if is_discord:
            # Discord Rich Embed color
            color_map = {
                "CRITICAL": 0xED4245,  # Red
                "HIGH": 0xE67E22,      # Orange
                "MEDIUM": 0xF1C40F,    # Yellow
                "LOW": 0x57F287,       # Green
            }
            color = color_map.get(sev_upper, 0x5865F2)

            payload = {
                "username": "NetSentry Sentinel",
                "embeds": [
                    {
                        "title": title,
                        "description": f"```\n{message}\n```",
                        "color": color,
                        "footer": {"text": "🛡️ NetSentry Linux Threat Sentinel"},
                    }
                ],
            }
        else:
            # Slack / Generic incoming webhook format
            payload = {
                "text": f"*{title}*\n```{message}```"
            }

        try:
            resp = requests.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            # Discord returns 204 No Content on success
            if resp.status_code in (200, 204):
                return True, "Webhook alert dispatched successfully"
            return False, f"Webhook server returned HTTP {resp.status_code}: {resp.text[:120]}"
        except Exception as e:
            return False, f"Webhook dispatch failed: {e}"

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "HIGH",
        throttle_key: Optional[str] = None,
    ) -> Dict[str, bool]:
        """Dispatch alert across all enabled channels, adhering to throttle limits."""
        now = time.time()
        if throttle_key:
            last = self._last_alert_time.get(throttle_key, 0.0)
            if now - last < self.cooldown_seconds:
                return {}
            self._last_alert_time[throttle_key] = now

        results: Dict[str, bool] = {}

        # 1. Desktop notification
        if self.config.desktop_notifications:
            ok, _ = self.send_desktop(title, message, severity)
            results["desktop"] = ok

        # 2. Telegram Bot
        if self.config.telegram_enabled:
            ok, _ = self.send_telegram(title, message, severity)
            results["telegram"] = ok

        # 3. Webhook (Discord / Slack)
        if self.config.webhook_enabled:
            ok, _ = self.send_webhook(title, message, severity)
            results["webhook"] = ok

        return results

    def test_all(self) -> Dict[str, Tuple[bool, str]]:
        """Test all channels (both enabled and configured) and return diagnostics."""
        test_title = "🛡️ NetSentry Notification Test"
        test_message = "Test alert from NetSentry. Verification of notification channels completed."
        results = {}

        # Always test desktop
        results["desktop"] = self.send_desktop(test_title, test_message, severity="LOW")

        # Test Telegram if configured or enabled
        if self.config.telegram_bot_token and self.config.telegram_chat_id:
            results["telegram"] = self.send_telegram(test_title, test_message, severity="LOW")
        else:
            results["telegram"] = (False, "Telegram not configured (bot token and chat ID empty)")

        # Test Webhook if configured or enabled
        if self.config.webhook_url:
            results["webhook"] = self.send_webhook(test_title, test_message, severity="LOW")
        else:
            results["webhook"] = (False, "Webhook not configured (webhook_url empty)")

        return results
