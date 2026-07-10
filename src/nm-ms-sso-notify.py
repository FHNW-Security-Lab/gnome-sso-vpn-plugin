#!/usr/bin/env python3
"""Unprivileged desktop notification helper for MFA number matching."""

from __future__ import annotations

import json
import re
import sys
from typing import Any


NOTIFICATIONS_BUS_NAME = "org.freedesktop.Notifications"
NOTIFICATIONS_OBJECT_PATH = "/org/freedesktop/Notifications"
NOTIFICATIONS_INTERFACE = "org.freedesktop.Notifications"


def _uint32(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"invalid {field}")
    parsed = int(value)
    if parsed < 0 or parsed > 0xFFFFFFFF:
        raise ValueError(f"invalid {field}")
    return parsed


def validate_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        raise ValueError("invalid request")
    action = request.get("action")
    if action == "show":
        code = request.get("code")
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{2}", code):
            raise ValueError("invalid code")
        return {
            "action": "show",
            "code": code,
            "replaces_id": _uint32(request.get("replaces_id", 0), "replaces_id"),
        }
    if action == "close":
        return {
            "action": "close",
            "id": _uint32(request.get("id"), "id"),
        }
    raise ValueError("invalid action")


def perform_request(request: dict[str, Any]) -> int:
    import dbus

    bus = dbus.SessionBus()
    notifications = dbus.Interface(
        bus.get_object(NOTIFICATIONS_BUS_NAME, NOTIFICATIONS_OBJECT_PATH),
        dbus_interface=NOTIFICATIONS_INTERFACE,
    )

    if request["action"] == "close":
        notifications.CloseNotification(dbus.UInt32(request["id"]))
        return request["id"]

    return int(notifications.Notify(
        "MS SSO VPN",
        dbus.UInt32(request["replaces_id"]),
        "network-vpn",
        "VPN sign-in approval",
        f"Enter number {request['code']} in Microsoft Authenticator.",
        dbus.Array([], signature="s"),
        dbus.Dictionary({
            "urgency": dbus.Byte(2),
            "resident": dbus.Boolean(True),
            "category": dbus.String("network"),
            "sound-name": dbus.String("message-new-instant"),
        }, signature="sv"),
        120000,
    ))


def main() -> int:
    try:
        raw_request = sys.stdin.read(1025)
        if len(raw_request) > 1024:
            raise ValueError("request too large")
        request = validate_request(json.loads(raw_request))
        notification_id = perform_request(request)
        print(notification_id)
        return 0
    except Exception:
        print("notification request failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
