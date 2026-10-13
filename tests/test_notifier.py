"""Tests for multi-channel Notifier (Desktop, Telegram, Webhook)."""

from unittest.mock import MagicMock, patch
from netsentry.config import Config
from netsentry.core.notifier import Notifier


def test_notifier_desktop():
    cfg = Config()
    notifier = Notifier(config=cfg)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        ok, msg = notifier.send_desktop("Test Alert", "Sample message")
        assert ok is True
        assert "successfully" in msg


def test_notifier_telegram_unconfigured():
    cfg = Config(telegram_enabled=True, telegram_bot_token="", telegram_chat_id="")
    notifier = Notifier(config=cfg)

    ok, msg = notifier.send_telegram("Test", "Message")
    assert ok is False
    assert "not configured" in msg


def test_notifier_telegram_success():
    cfg = Config(
        telegram_enabled=True,
        telegram_bot_token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
        telegram_chat_id="987654321",
    )
    notifier = Notifier(config=cfg)

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_post.return_value = mock_resp

        ok, msg = notifier.send_telegram("Test Alert", "Threat detected")
        assert ok is True
        assert "successfully" in msg

        # Verify request payload
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert kwargs["json"]["chat_id"] == "987654321"
        assert "Test Alert" in kwargs["json"]["text"]


def test_notifier_webhook_discord():
    cfg = Config(
        webhook_enabled=True,
        webhook_url="https://discord.com/api/webhooks/123/tokenABC",
    )
    notifier = Notifier(config=cfg)

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock(status_code=204)  # Discord returns 204
        mock_post.return_value = mock_resp

        ok, msg = notifier.send_webhook("Discord Alert", "Malicious process")
        assert ok is True

        args, kwargs = mock_post.call_args
        assert "embeds" in kwargs["json"]
        assert kwargs["json"]["embeds"][0]["title"] == "Discord Alert"


def test_notifier_webhook_slack():
    cfg = Config(
        webhook_enabled=True,
        webhook_url="https://hooks.slack.com/services/T00/B00/X00",
    )
    notifier = Notifier(config=cfg)

    with patch("requests.post") as mock_post:
        mock_resp = MagicMock(status_code=200)
        mock_post.return_value = mock_resp

        ok, msg = notifier.send_webhook("Slack Alert", "Port scan detected")
        assert ok is True

        args, kwargs = mock_post.call_args
        assert "text" in kwargs["json"]


def test_notifier_throttling():
    cfg = Config(notification_cooldown_seconds=10)
    notifier = Notifier(config=cfg, cooldown_seconds=10)

    with patch.object(notifier, "send_desktop", return_value=(True, "ok")):
        # First alert with throttle key succeeds
        res1 = notifier.send_alert("Alert 1", "Msg 1", throttle_key="1.2.3.4")
        assert res1.get("desktop") is True

        # Second alert immediately with same throttle key is throttled
        res2 = notifier.send_alert("Alert 2", "Msg 2", throttle_key="1.2.3.4")
        assert res2 == {}
