"""Notification adapter registry — DESIGNED but DISABLED by default.

Outbound notifications are DISABLED until the owner explicitly authorizes them
(OPS_NOTIFY_ENABLED=1) AND at least one channel adapter is configured and
verified. This module contains NO network code: the only registered adapter is
the disabled recorder, so calling notify_alert() can never send anything.

Escalation hooks call notify_alert(); it records an ops event either way, so
the audit trail shows what WOULD have been notified.
"""
import os


class NotificationAdapter:
    name = "base"

    def send(self, alert: dict, channel: str, reason: str) -> dict:
        raise NotImplementedError


class DisabledNotificationAdapter(NotificationAdapter):
    """Records that a notification was suppressed. Sends nothing, ever."""

    name = "disabled"

    def send(self, alert: dict, channel: str, reason: str) -> dict:
        return {"sent": False, "adapter": self.name, "reason": reason, "channel": channel}


_ADAPTERS = {"disabled": DisabledNotificationAdapter()}


def notifications_enabled() -> bool:
    return os.getenv("OPS_NOTIFY_ENABLED") == "1"


def configured_channels() -> list[str]:
    raw = os.getenv("OPS_NOTIFY_CHANNELS", "")
    return [c.strip() for c in raw.split(",") if c.strip()]


def notify_alert(alert: dict, reason: str = "escalated") -> dict:
    """Notify about an alert. With notifications disabled (default) this only
    records an ops event and returns {"sent": False}. Never raises."""
    from app import ops

    if not notifications_enabled() or not configured_channels():
        try:
            ops.record_event(
                "info", "notifications",
                f"notification suppressed (disabled): alert #{alert.get('id')} "
                f"rule={alert.get('rule')} severity={alert.get('severity')} reason={reason}",
            )
        except Exception:
            pass
        return {"sent": False, "reason": "notifications disabled by policy"}
    # Even when enabled, only registered (in-repo, non-network) adapters exist;
    # real channels require owner-authorized adapter code + credentials.
    results = []
    for ch in configured_channels():
        adapter = _ADAPTERS.get("disabled")
        results.append(adapter.send(alert, ch, reason))
    return {"sent": False, "reason": "no authorized channel adapter configured", "results": results}
