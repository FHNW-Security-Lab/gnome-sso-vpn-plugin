#!/usr/bin/env python3

import importlib.util
import logging
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src" / "python"))

from core.auth import (  # noqa: E402
    SamlUiStalledError as CoreSamlUiStalledError,
    _ui_stall_exception,
)


SERVICE_PATH = REPO_ROOT / "src" / "nm-ms-sso-service.py"
PREEXISTING_LOG_HANDLERS = tuple(logging.getLogger("nm-ms-sso").handlers)
SPEC = importlib.util.spec_from_file_location(
    "nm_ms_sso_service_profile_recovery",
    SERVICE_PATH,
)
SERVICE_MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SERVICE_MODULE)

# Importing the production service configures process-global logging. Remove
# only the handlers added by this import so other test modules neither write to
# host syslog nor receive duplicate stderr records.
for handler in list(SERVICE_MODULE.log.handlers):
    if handler not in PREEXISTING_LOG_HANDLERS:
        SERVICE_MODULE.log.removeHandler(handler)
        handler.close()
if not SERVICE_MODULE.log.handlers:
    SERVICE_MODULE.log.addHandler(logging.NullHandler())


class CachedProfileRecoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.service = object.__new__(SERVICE_MODULE.VPNPluginService)

    def test_pre_credential_typed_stall_gets_exactly_one_ephemeral_retry(self):
        self.assertIs(
            SERVICE_MODULE.SamlUiStalledError,
            CoreSamlUiStalledError,
            "service and core must catch the same exported exception type",
        )
        cookies = {
            "webvpn": "session",
            "webvpnc": "session-metadata",
        }
        cancel_callback = lambda: False
        first_error = _ui_stall_exception(
            "Microsoft credential discovery stalled",
            sensitive_submission_started=False,
        )
        self.assertIsInstance(first_error, CoreSamlUiStalledError)

        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=[first_error, cookies],
        ) as auth:
            result = self.service._do_saml_auth_with_ui_stall_fallback(
                vpn_server="vpn.example.edu",
                protocol="anyconnect",
                username="user@example.edu",
                disable_browser_session_cache=False,
                cancel_callback=cancel_callback,
            )

        self.assertEqual(result, cookies)
        self.assertEqual(auth.call_count, 2)
        first_kwargs = auth.call_args_list[0].kwargs
        retry_kwargs = auth.call_args_list[1].kwargs
        self.assertFalse(first_kwargs["disable_browser_session_cache"])
        self.assertTrue(retry_kwargs["disable_browser_session_cache"])
        self.assertIs(retry_kwargs["cancel_callback"], cancel_callback)
        for key in ("vpn_server", "protocol", "username"):
            self.assertEqual(retry_kwargs[key], first_kwargs[key])

    def test_post_credential_stall_is_not_replayed_in_clean_profile(self):
        submitted_error = _ui_stall_exception(
            "Microsoft did not finish the submitted password",
            sensitive_submission_started=True,
        )
        self.assertIsInstance(submitted_error, RuntimeError)
        self.assertNotIsInstance(submitted_error, CoreSamlUiStalledError)

        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=submitted_error,
        ) as auth:
            with self.assertRaisesRegex(RuntimeError, "submitted password"):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="vpn.example.edu",
                    protocol="anyconnect",
                    disable_browser_session_cache=False,
                    cancel_callback=lambda: False,
                )

        auth.assert_called_once()

    def test_globalprotect_stall_is_not_retried_in_an_ephemeral_profile(self):
        stall = _ui_stall_exception(
            "GlobalProtect browser UI stalled",
            sensitive_submission_started=False,
        )

        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=stall,
        ) as auth:
            with self.assertRaisesRegex(
                CoreSamlUiStalledError,
                "GlobalProtect browser UI stalled",
            ):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="gp.example.edu",
                    protocol="gp",
                    disable_browser_session_cache=False,
                )

        auth.assert_called_once()


if __name__ == "__main__":
    unittest.main()
