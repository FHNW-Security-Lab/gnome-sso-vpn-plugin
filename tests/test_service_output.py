#!/usr/bin/env python3

import importlib.util
import logging.handlers
import os
import sys
import tempfile
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
            interface_name="tun-ms-sso7",
        )

        self.assertIn("--passwd-on-stdin", command)
        self.assertFalse(any("portal-cookie" in arg for arg in command))
        self.assertIn("--user=saml-returned-user", command)
        self.assertIn("--usergroup=portal:portal-userauthcookie", command)
        self.assertIn("--useragent=PAN GlobalProtect", command)
        self.assertIn("--os=linux-64", command)
        self.assertIn("--csd-wrapper=/usr/libexec/nm-ms-sso-gp-hipreport", command)
        self.assertIn("--interface=tun-ms-sso7", command)

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


class NetworkRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.service = object.__new__(SERVICE_MODULE.VPNPluginService)
        self.service.state = SERVICE_MODULE.NM_VPN_SERVICE_STATE_STOPPED
        self.service.vpn_process = None
        self.service.vpn_process_generation = None
        self.service.current_gateway = "vpn.example.edu"
        self.service.current_gateway_host = "vpn.example.edu"
        self.service.current_gateway_ip = "192.0.2.10"
        self.service.current_protocol = "anyconnect"
        self.service.current_connection_uuid = "vpn-uuid"
        self.service.current_tun_device = None
        self.service.current_dns_server_limit = 3
        self.service.vpn_dns_servers = []
        self.service.vpn_domains = []
        self.service.vpn_split_excludes = []
        self.service.vpn_split_includes = []
        self.service.vpn_tunnel_all_dns = None
        self.service.owned_tun_devices = set()
        self.service.owned_tun_ifindices = {}
        self.service.preexisting_tun_devices = set()
        self.service.ipv6_leak_protection_enabled = False
        self.service.pre_vpn_uplinks = {"eth0": "uplink-uuid"}
        self.service.pre_vpn_dns_default_uplinks = {"eth0"}
        self.service.pre_vpn_dns_state_captured = True
        self.service._uplinks_needing_reapply = set()
        self.service._network_recovery_token = 4
        self.service._network_recovery_deadline = 0.0
        self.service._network_recovery_reload_attempted = False
        self.service._network_recovery_thread = None
        self.service.cancel_requested = False
        self.service._connect_generation = 2

    def test_ipv6_leak_marker_is_durable_before_route_is_added(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"

            def add_route(_command, **_kwargs):
                self.assertTrue(marker.exists())
                self.assertEqual(
                    marker.read_text(encoding="utf-8"),
                    "connection_uuid=vpn-uuid\n",
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.dict(
                SERVICE_MODULE.os.environ,
                {"MS_SSO_NM_BLOCK_IPV6": "1"},
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                side_effect=add_route,
            ):
                self.service._apply_ipv6_leak_protection()

            self.assertTrue(self.service.ipv6_leak_protection_enabled)
            self.assertTrue(marker.exists())

    def test_ipv6_leak_marker_survives_until_route_absence_is_verified(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            marker.write_text("connection_uuid=vpn-uuid\n", encoding="utf-8")
            self.service.ipv6_leak_protection_enabled = True

            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                self.service,
                "_run_recovery_command",
                return_value=False,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=True,
            ):
                self.service._remove_ipv6_leak_protection()

            self.assertTrue(marker.exists())
            self.assertTrue(self.service.ipv6_leak_protection_enabled)

            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                self.service,
                "_run_recovery_command",
                return_value=False,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=False,
            ):
                self.service._remove_ipv6_leak_protection()

            self.assertFalse(marker.exists())
            self.assertFalse(self.service.ipv6_leak_protection_enabled)

    def test_cleanup_only_mutates_generation_owned_tunnels(self):
        commands = []
        self.service.current_tun_device = "tun-foreign"
        self.service.owned_tun_devices = {"tun-owned"}
        self.service.owned_tun_ifindices = {"tun-owned": 42}
        self.service.preexisting_tun_devices = {"tun-foreign"}
        self.service._remove_ipv6_leak_protection = lambda: None
        self.service._cleanup_leaked_vpn_dns_links = lambda: None
        self.service._run_recovery_command = (
            lambda command: commands.append(command) or True
        )

        with patch.object(
            SERVICE_MODULE.shutil,
            "which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ), patch.object(
            self.service,
            "_link_ifindex",
            side_effect=[42, None],
        ):
            self.service._cleanup_dns()

        self.assertEqual(
            commands,
            [
                ["resolvectl", "revert", "tun-owned"],
                ["resolvconf", "-d", "tun-owned"],
                ["ip", "-4", "route", "flush", "dev", "tun-owned"],
                ["ip", "-6", "route", "flush", "dev", "tun-owned"],
                ["ip", "link", "delete", "dev", "tun-owned"],
            ],
        )
        self.assertFalse(any("tun-foreign" in command for command in commands))
        self.assertIsNone(self.service.current_tun_device)
        self.assertEqual(self.service.owned_tun_devices, set())

    def test_cleanup_falls_back_when_resolvectl_returns_nonzero(self):
        commands = []
        self.service.current_tun_device = "tun42"
        self.service.owned_tun_devices = {"tun42"}
        self.service.owned_tun_ifindices = {"tun42": 42}
        self.service._remove_ipv6_leak_protection = lambda: None
        self.service._cleanup_leaked_vpn_dns_links = lambda: None

        def run_recovery(command):
            commands.append(command)
            return command[0] != "resolvectl"

        self.service._run_recovery_command = run_recovery
        with patch.object(
            SERVICE_MODULE.shutil,
            "which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ), patch.object(
            self.service,
            "_link_ifindex",
            side_effect=[42, None],
        ):
            self.service._cleanup_dns()

        self.assertEqual(
            commands[:2],
            [
                ["resolvectl", "revert", "tun42"],
                ["resolvconf", "-d", "tun42"],
            ],
        )

    def test_delayed_cleanup_cannot_touch_a_reused_tunnel_name(self):
        commands = []
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        self.service._remove_ipv6_leak_protection = lambda: None
        self.service._cleanup_leaked_vpn_dns_links = lambda: None
        self.service._run_recovery_command = (
            lambda command: commands.append(command) or True
        )

        with patch.object(self.service, "_link_ifindex", return_value=99):
            self.service._cleanup_dns()

        self.assertEqual(commands, [])

    def test_vanished_owned_tunnel_still_removes_name_keyed_dns_only(self):
        commands = []
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        self.service._remove_ipv6_leak_protection = lambda: None
        self.service._cleanup_leaked_vpn_dns_links = lambda: None
        self.service._run_recovery_command = (
            lambda command: commands.append(command) or True
        )

        with patch.object(self.service, "_link_ifindex", return_value=None), patch.object(
            SERVICE_MODULE.shutil,
            "which",
            side_effect=lambda command: f"/usr/bin/{command}",
        ):
            self.service._cleanup_dns()

        self.assertEqual(commands, [
            ["resolvectl", "revert", "tun-ms-sso7"],
            ["resolvconf", "-d", "tun-ms-sso7"],
        ])

    def test_failed_link_delete_preserves_exact_recovery_ownership(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        self.service._remove_ipv6_leak_protection = lambda: None
        self.service._cleanup_leaked_vpn_dns_links = lambda: None
        self.service._run_recovery_command = lambda _command: False

        with patch.object(
            self.service,
            "_link_ifindex",
            side_effect=[42, 42],
        ), patch.object(SERVICE_MODULE.shutil, "which", return_value=None):
            self.service._cleanup_dns()

        self.assertEqual(self.service.owned_tun_devices, {"tun-ms-sso7"})
        self.assertEqual(self.service.owned_tun_ifindices, {"tun-ms-sso7": 42})
        self.assertEqual(self.service.current_tun_device, "tun-ms-sso7")

    def test_vpn_dns_on_physical_uplink_is_reapplied_not_reverted(self):
        self.service.vpn_dns_servers = ["10.51.2.232"]
        resolved_status = SimpleNamespace(
            returncode=0,
            stderr="",
            stdout=(
                "Link 2 (eth0)\n"
                "    DNS Servers: 192.0.2.53 10.51.2.232\n"
                "Link 9 (tun-foreign)\n"
                "    DNS Servers: 10.51.2.232\n"
            ),
        )
        with patch.object(
            SERVICE_MODULE.shutil,
            "which",
            return_value="/usr/bin/resolvectl",
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            return_value=resolved_status,
        ) as run, patch.object(
            self.service,
            "_list_connected_uplinks",
            return_value={"eth0": "uplink-uuid"},
        ):
            self.service._cleanup_leaked_vpn_dns_links()

        self.assertEqual(self.service._uplinks_needing_reapply, {"eth0"})
        run.assert_called_once_with(
            ["resolvectl", "status"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )

    def test_recovery_command_reports_real_process_status(self):
        failed = SimpleNamespace(returncode=7, stdout="", stderr="failed")
        succeeded = SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            side_effect=[failed, succeeded],
        ) as run:
            self.assertFalse(self.service._run_recovery_command(["resolvectl", "revert", "tun0"]))
            self.assertTrue(self.service._run_recovery_command(["resolvconf", "-d", "tun0"]))

        self.assertEqual(run.call_count, 2)
        for call_args in run.call_args_list:
            self.assertFalse(call_args.kwargs["check"])
            self.assertEqual(call_args.kwargs["timeout"], 8)

    def test_base_network_requires_both_physical_route_and_dns(self):
        for route_ready, dns_ready, expected in (
            (True, True, True),
            (True, False, False),
            (False, True, False),
            (False, False, False),
        ):
            with self.subTest(route_ready=route_ready, dns_ready=dns_ready):
                with patch.object(
                    self.service,
                    "_route_to_base_network_uses_uplink",
                    return_value=route_ready,
                ), patch.object(
                    self.service,
                    "_base_dns_operational",
                    return_value=dns_ready,
                ), patch.object(
                    self.service,
                    "_physical_dns_route_restored",
                    return_value=True,
                ):
                    self.assertEqual(self.service._base_network_ready(), expected)

    def test_recovery_reloads_once_then_reapplies_connected_uplinks(self):
        with patch.object(
            self.service,
            "_base_network_ready",
            side_effect=[False, True],
        ) as ready, patch.object(
            self.service,
            "_reload_networkmanager_dns",
        ) as reload_dns, patch.object(
            self.service,
            "_reapply_connected_uplinks",
        ) as reapply:
            result = self.service._recover_base_network_once(reactivate=True)

        self.assertTrue(result)
        self.assertEqual(ready.call_count, 2)
        reload_dns.assert_called_once_with()
        reapply.assert_called_once_with(reactivate=True)
        self.assertTrue(self.service._network_recovery_reload_attempted)

    def test_recovery_does_nothing_when_base_network_is_already_ready(self):
        with patch.object(
            self.service,
            "_base_network_ready",
            return_value=True,
        ), patch.object(
            self.service,
            "_reload_networkmanager_dns",
        ) as reload_dns, patch.object(
            self.service,
            "_reapply_connected_uplinks",
        ) as reapply:
            result = self.service._recover_base_network_once(reactivate=True)

        self.assertTrue(result)
        reload_dns.assert_not_called()
        reapply.assert_not_called()

    def test_post_disconnect_recovery_cleans_then_stops_as_soon_as_ready(self):
        self.service._network_recovery_token = 9
        self.service._network_recovery_deadline = 110.0
        self.service._uplinks_needing_reapply = {"eth0"}
        with patch.object(self.service, "_cleanup_dns") as cleanup, patch.object(
            self.service,
            "_recover_base_network_once",
            return_value=True,
        ) as recover, patch.object(
            SERVICE_MODULE.time,
            "monotonic",
            return_value=100.0,
        ):
            result = self.service._post_disconnect_recovery_worker(9)

        self.assertIsNone(result)
        cleanup.assert_called_once_with(recovery_token=9)
        recover.assert_called_once_with(reactivate=False)
        self.assertEqual(self.service._uplinks_needing_reapply, set())

    def test_post_disconnect_recovery_escalates_near_deadline_and_retries(self):
        self.service._network_recovery_token = 9
        self.service._network_recovery_deadline = 105.0
        def stop_after_one_pass(*, reactivate):
            self.service._network_recovery_token = 10
            return False

        with patch.object(self.service, "_cleanup_dns") as cleanup, patch.object(
            self.service,
            "_recover_base_network_once",
            side_effect=stop_after_one_pass,
        ) as recover, patch.object(
            SERVICE_MODULE.time,
            "monotonic",
            return_value=100.0,
        ), patch.object(SERVICE_MODULE.time, "sleep") as sleep:
            result = self.service._post_disconnect_recovery_worker(9)

        self.assertIsNone(result)
        cleanup.assert_called_once_with(recovery_token=9)
        recover.assert_called_once_with(reactivate=True)
        sleep.assert_called_once_with(1.0)

    def test_stale_recovery_token_cannot_touch_new_activation(self):
        self.service._network_recovery_token = 10
        with patch.object(self.service, "_cleanup_dns") as cleanup, patch.object(
            self.service,
            "_recover_base_network_once",
        ) as recover:
            result = self.service._post_disconnect_recovery_tick(9)

        self.assertFalse(result)
        cleanup.assert_not_called()
        recover.assert_not_called()

    def test_cleanup_rechecks_recovery_token_under_lock(self):
        self.service._network_recovery_token = 10
        with patch.object(
            self.service,
            "_cleanup_owned_network_state",
        ) as cleanup:
            result = self.service._cleanup_dns(recovery_token=9)

        self.assertFalse(result)
        cleanup.assert_not_called()

    def test_recovery_timer_cannot_touch_active_new_activation(self):
        self.service.state = SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTING
        self.service._network_recovery_token = 9
        with patch.object(self.service, "_cleanup_dns") as cleanup, patch.object(
            self.service,
            "_recover_base_network_once",
        ) as recover:
            result = self.service._post_disconnect_recovery_tick(9)

        self.assertFalse(result)
        cleanup.assert_not_called()
        recover.assert_not_called()

    def test_failure_stops_activation_before_scheduling_recovery(self):
        events = []
        self.service.state = SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTED
        self.service.Failure = lambda reason: events.append(("failure", reason))
        self.service.StateChanged = lambda state: events.append(("state", state))
        self.service._schedule_post_disconnect_recovery = (
            lambda: events.append(("recover", None))
        )

        result = self.service._emit_failure("tunnel exited", connect_generation=2)

        self.assertFalse(result)
        self.assertEqual(
            events,
            [
                ("failure", SERVICE_MODULE.NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED),
                ("state", SERVICE_MODULE.NM_VPN_SERVICE_STATE_STOPPED),
                ("recover", None),
            ],
        )
        self.assertEqual(self.service.state, SERVICE_MODULE.NM_VPN_SERVICE_STATE_STOPPED)

    def test_disconnected_stops_activation_before_scheduling_recovery(self):
        events = []
        self.service.state = SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTED
        self.service.StateChanged = lambda state: events.append(("state", state))
        self.service._schedule_post_disconnect_recovery = (
            lambda: events.append(("recover", None))
        )

        result = self.service._emit_disconnected(connect_generation=2)

        self.assertFalse(result)
        self.assertEqual(
            events,
            [
                ("state", SERVICE_MODULE.NM_VPN_SERVICE_STATE_STOPPED),
                ("recover", None),
            ],
        )

    def test_started_activation_cannot_transition_back_to_starting(self):
        emitted = []
        self.service.state = SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTED
        self.service.StateChanged = emitted.append

        result = self.service._emit_starting_keepalive(connect_generation=2)

        self.assertFalse(result)
        self.assertEqual(self.service.state, SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTED)
        self.assertEqual(emitted, [])

    def test_stale_split_dns_callback_cannot_mutate_reused_tunnel(self):
        self.service.current_tun_device = "tun0"
        self.service.owned_tun_devices = {"tun0"}
        with patch.object(SERVICE_MODULE.subprocess, "run") as run:
            result = self.service._apply_split_dns_resolved(
                "tun0",
                ["~corp.example"],
                connect_generation=1,
            )

        self.assertFalse(result)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
