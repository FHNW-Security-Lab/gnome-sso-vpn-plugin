#!/usr/bin/env python3

import importlib.util
import logging.handlers
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src" / "python"))

SERVICE_PATH = REPO_ROOT / "src" / "nm-ms-sso-service.py"
SPEC = importlib.util.spec_from_file_location("nm_ms_sso_service", SERVICE_PATH)
SERVICE_MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(SERVICE_MODULE)

# Importing the service configures production logging. Unit tests have no
# system syslog socket, so remove only that handler and retain stderr output.
for handler in list(SERVICE_MODULE.log.handlers):
    if isinstance(handler, logging.handlers.SysLogHandler):
        SERVICE_MODULE.log.removeHandler(handler)
        handler.close()


class FakeStdout:
    def __init__(self, reads):
        self.reads = list(reads)

    def read(self, _size):
        if not self.reads:
            raise BlockingIOError
        value = self.reads.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class FakeProcess:
    def __init__(self, reads):
        self.stdout = FakeStdout(reads)


class FakeStdin:
    def __init__(self):
        self.data = b""
        self.flushed = False
        self.closed = False

    def write(self, data):
        self.data += data

    def flush(self):
        self.flushed = True

    def close(self):
        self.closed = True


class OpenConnectOutputTests(unittest.TestCase):
    def setUp(self):
        self.service = object.__new__(SERVICE_MODULE.VPNPluginService)
        self.service.vpn_dns_servers = []
        self.service.vpn_domains = []
        self.service.vpn_split_excludes = []
        self.service.vpn_split_includes = []
        self.service.vpn_tunnel_all_dns = None
        self.service._vpn_stdout_partial = ""
        self.service.cancel_requested = False
        self.service._connect_generation = 2

    def test_session_marker_split_across_reads_is_detected(self):
        output, reported_up = self.service._consume_vpn_stdout(
            "",
            False,
            process=FakeProcess([b"CSTP connec", BlockingIOError()]),
        )
        self.assertFalse(reported_up)

        output, reported_up = self.service._consume_vpn_stdout(
            output,
            reported_up,
            process=FakeProcess([b"ted as 10.0.0.10\n", BlockingIOError()]),
        )
        self.assertTrue(reported_up)
        self.assertIn("CSTP connected as 10.0.0.10", output)

    def test_dns_line_split_across_reads_is_detected(self):
        output, reported_up = self.service._consume_vpn_stdout(
            "",
            False,
            process=FakeProcess([b"Got DNS server 10.0.", BlockingIOError()]),
        )
        output, reported_up = self.service._consume_vpn_stdout(
            output,
            reported_up,
            process=FakeProcess([b"0.53\n", BlockingIOError()]),
        )

        self.assertFalse(reported_up)
        self.assertEqual(self.service.vpn_dns_servers, ["10.0.0.53"])

    def test_unterminated_final_session_marker_is_flushed_at_eof(self):
        _output, reported_up = self.service._consume_vpn_stdout(
            "",
            False,
            process=FakeProcess([b"CSTP connected as 10.0.0.10", b""]),
        )

        self.assertTrue(reported_up)
        self.assertEqual(self.service._vpn_stdout_partial, "")

    def test_stale_connected_callback_cannot_touch_new_process(self):
        current_process = object()
        self.service.vpn_process = current_process

        result = self.service._emit_connected(
            connect_generation=1,
            vpn_process=object(),
            tun_device="tun-old",
        )

        self.assertFalse(result)
        self.assertIs(self.service.vpn_process, current_process)

    def test_stale_failure_callback_is_ignored(self):
        calls = []
        self.service._cleanup_dns = lambda: calls.append("cleanup")
        self.service.Failure = lambda _reason: calls.append("failure")
        self.service._set_state = lambda _state: calls.append("state")

        result = self.service._emit_failure("old failure", connect_generation=1)

        self.assertFalse(result)
        self.assertEqual(calls, [])

    def test_gp_cookie_stdin_is_closed_after_one_line(self):
        stream = FakeStdin()
        process = SimpleNamespace(stdin=stream)

        self.service._write_gp_cookie_and_close(process, "secret-cookie")

        self.assertEqual(stream.data, b"secret-cookie\n")
        self.assertTrue(stream.flushed)
        self.assertTrue(stream.closed)

    def test_gp_cookie_selection_prefers_reusable_portal_cookie(self):
        selected = self.service._select_gp_cookie({
            "prelogin-cookie": "one-time",
            "portal-userauthcookie": "reusable",
        })

        self.assertEqual(
            selected,
            ("reusable", "portal:portal-userauthcookie", True),
        )
        self.assertTrue(self.service._has_reusable_gp_cookie({
            "portal-userauthcookie": "reusable",
        }))
        self.assertFalse(self.service._has_reusable_gp_cookie({
            "prelogin-cookie": "one-time",
        }))
        self.assertFalse(self.service._has_reusable_gp_cookie(
            {
                "prelogin-cookie": "gateway-cookie",
                "portal-userauthcookie": "portal-cookie",
            },
            auth_interface="gateway",
        ))

    def test_gp_gateway_cookie_selection_skips_portal_handoff(self):
        selected = self.service._select_gp_cookie(
            {"prelogin-cookie": "one-time"},
            auth_interface="gateway",
        )

        self.assertEqual(
            selected,
            ("one-time", "gateway:prelogin-cookie", True),
        )

    def test_gp_gateway_cookie_selection_prefers_prelogin_when_both_exist(self):
        selected = self.service._select_gp_cookie(
            {
                "prelogin-cookie": "gateway-cookie",
                "portal-userauthcookie": "portal-cookie",
            },
            auth_interface="gateway",
        )

        self.assertEqual(
            selected,
            ("gateway-cookie", "gateway:prelogin-cookie", True),
        )

    def test_gp_gateway_cookie_selection_rejects_portal_only_artifact(self):
        with self.assertRaisesRegex(RuntimeError, "no gateway prelogin cookie"):
            self.service._select_gp_cookie(
                {"portal-userauthcookie": "portal-cookie"},
                auth_interface="gateway",
            )

    def test_cached_browser_ui_stall_retries_once_with_ephemeral_session(self):
        cookies = {"prelogin-cookie": "gateway-cookie"}
        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=[SERVICE_MODULE.SamlUiStalledError("stalled"), cookies],
        ) as auth:
            result = self.service._do_saml_auth_with_ui_stall_fallback(
                vpn_server="vpn.example.edu",
                disable_browser_session_cache=False,
                cancel_callback=lambda: False,
            )

        self.assertEqual(result, cookies)
        self.assertEqual(auth.call_count, 2)
        self.assertFalse(auth.call_args_list[0].kwargs["disable_browser_session_cache"])
        self.assertTrue(auth.call_args_list[1].kwargs["disable_browser_session_cache"])

    def test_second_browser_ui_stall_is_propagated_without_third_attempt(self):
        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=SERVICE_MODULE.SamlUiStalledError("stalled"),
        ) as auth:
            with self.assertRaises(SERVICE_MODULE.SamlUiStalledError):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="vpn.example.edu",
                    disable_browser_session_cache=False,
                    cancel_callback=lambda: False,
                )

        self.assertEqual(auth.call_count, 2)
        self.assertTrue(auth.call_args_list[1].kwargs["disable_browser_session_cache"])

    def test_ephemeral_browser_ui_stall_is_not_retried(self):
        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=SERVICE_MODULE.SamlUiStalledError("stalled"),
        ) as auth:
            with self.assertRaises(SERVICE_MODULE.SamlUiStalledError):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="vpn.example.edu",
                    disable_browser_session_cache=True,
                    cancel_callback=lambda: False,
                )

        auth.assert_called_once()

    def test_cancelled_cached_browser_ui_stall_is_not_retried(self):
        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=SERVICE_MODULE.SamlUiStalledError("stalled"),
        ) as auth:
            with self.assertRaises(SERVICE_MODULE.SamlUiStalledError):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="vpn.example.edu",
                    disable_browser_session_cache=False,
                    cancel_callback=lambda: True,
                )

        auth.assert_called_once()

    def test_non_ui_saml_failure_is_not_retried(self):
        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=RuntimeError("authentication failed"),
        ) as auth:
            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="vpn.example.edu",
                    disable_browser_session_cache=False,
                    cancel_callback=lambda: False,
                )

        auth.assert_called_once()

    def test_gp_command_uses_returned_identity_and_hip_for_all_cookie_types(self):
        command = self.service._build_gp_openconnect_command(
            openconnect_bin="openconnect",
            proto_flag="gp",
            gateway="vpn.example.edu",
            usergroup="portal:portal-userauthcookie",
            username="saml-returned-user",
            resolve_arg="--resolve=vpn.example.edu:192.0.2.10",
            hip_wrapper="/usr/libexec/nm-ms-sso-gp-hipreport",
        )

        self.assertIn("--passwd-on-stdin", command)
        self.assertFalse(any("portal-cookie" in arg for arg in command))
        self.assertIn("--user=saml-returned-user", command)
        self.assertIn("--usergroup=portal:portal-userauthcookie", command)
        self.assertIn("--useragent=PAN GlobalProtect", command)
        self.assertIn("--os=linux-64", command)
        self.assertIn("--csd-wrapper=/usr/libexec/nm-ms-sso-gp-hipreport", command)

    def test_gp_optimistic_connection_state_defaults_off(self):
        with patch.dict(os.environ, {
            "MS_SSO_NM_GP_EARLY_STARTED": "",
            "MS_SSO_NM_GP_EARLY_CONFIG": "",
            "MS_SSO_NM_GP_CONFIG_DELAY": "",
        }):
            self.assertFalse(self.service._gp_early_started_enabled())
            self.assertFalse(self.service._gp_initial_config_allowed())

        with patch.dict(os.environ, {
            "MS_SSO_NM_GP_EARLY_STARTED": "1",
            "MS_SSO_NM_GP_EARLY_CONFIG": "1",
        }):
            self.assertTrue(self.service._gp_early_started_enabled())
            self.assertTrue(self.service._gp_initial_config_allowed())

    def test_timeout_diagnostic_never_echoes_openconnect_output(self):
        output = "Password: super-secret\nHIP report pending"
        diagnostic = self.service._classify_openconnect_timeout(output)

        self.assertEqual(diagnostic, "waiting for additional credential input")
        self.assertNotIn("super-secret", diagnostic)


if __name__ == "__main__":
    unittest.main()
