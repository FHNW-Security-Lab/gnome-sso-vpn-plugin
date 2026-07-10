#!/usr/bin/env python3

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = REPO_ROOT / "src" / "nm-ms-sso-notify.py"
SPEC = importlib.util.spec_from_file_location("nm_ms_sso_notify", HELPER_PATH)
HELPER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(HELPER)


class NotificationRequestTests(unittest.TestCase):
    def test_valid_show_and_close_requests(self):
        self.assertEqual(
            HELPER.validate_request({"action": "show", "code": "65", "replaces_id": 7}),
            {"action": "show", "code": "65", "replaces_id": 7},
        )
        self.assertEqual(
            HELPER.validate_request({"action": "close", "id": 7}),
            {"action": "close", "id": 7},
        )

    def test_code_is_strictly_two_ascii_digits(self):
        for value in ("5", "123", "6<5", "６５", 65, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                HELPER.validate_request({"action": "show", "code": value})

    def test_notification_ids_must_be_uint32(self):
        for value in (-1, 0x100000000, True, "not-a-number"):
            with self.subTest(value=value), self.assertRaises((TypeError, ValueError)):
                HELPER.validate_request({"action": "close", "id": value})

    def test_dbus_show_replaces_and_close_uses_returned_id(self):
        calls = []

        class Notifications:
            def Notify(self, *args):
                calls.append(("show", args))
                return 42

            def CloseNotification(self, notification_id):
                calls.append(("close", notification_id))

        notifications = Notifications()
        fake_bus = SimpleNamespace(get_object=lambda *_args: object())
        fake_dbus = SimpleNamespace(
            SessionBus=lambda: fake_bus,
            Interface=lambda *_args, **_kwargs: notifications,
            UInt32=int,
            Byte=int,
            Boolean=bool,
            String=str,
            Array=lambda values, **_kwargs: values,
            Dictionary=lambda values, **_kwargs: values,
        )

        with patch.dict(sys.modules, {"dbus": fake_dbus}):
            notification_id = HELPER.perform_request(
                {"action": "show", "code": "65", "replaces_id": 7}
            )
            HELPER.perform_request({"action": "close", "id": notification_id})

        self.assertEqual(notification_id, 42)
        self.assertEqual(calls[0][0], "show")
        self.assertEqual(calls[0][1][1], 7)
        self.assertIn("65", calls[0][1][4])
        self.assertTrue(calls[0][1][6]["resident"])
        self.assertEqual(calls[1], ("close", 42))


if __name__ == "__main__":
    unittest.main()
