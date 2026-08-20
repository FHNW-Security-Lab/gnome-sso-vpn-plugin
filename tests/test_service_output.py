#!/usr/bin/env python3

import importlib.util
import errno
import json
import logging.handlers
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


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
        self.service.configured_dns_servers = []
        self.service.dns_leak_protection_ready = False
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

    def test_connected_emits_nm_owned_metadata_without_owning_vpnc_routes(self):
        process = SimpleNamespace(poll=lambda: None)
        self.service.vpn_process = process
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.current_gateway = "vpn.example.edu"
        self.service.current_gateway_ip = "192.0.2.10"
        self.service.current_dns_server_limit = 1
        self.service.vpn_dns_servers = ["10.0.0.53"]
        self.service.dns_leak_protection_ready = True
        self.service._get_tun_ipv4_config = lambda _device: ("10.3.0.38", 32)
        self.service._apply_ipv6_leak_protection = lambda: True
        self.service._apply_full_dns_resolved = lambda *_args: True
        no_resolved_dns = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="not configured",
        )

        for protocol in ("gp", "anyconnect"):
            with self.subTest(protocol=protocol):
                configs = []
                ip4_configs = []
                states = []
                self.service.current_protocol = protocol
                # Exercise the full-tunnel AnyConnect case too: NetworkManager
                # must never add a competing default even when the server does.
                self.service.vpn_tunnel_all_dns = True
                self.service.Config = configs.append
                self.service.Ip4Config = ip4_configs.append
                self.service._set_state = states.append

                with patch.object(
                    SERVICE_MODULE.subprocess,
                    "run",
                    return_value=no_resolved_dns,
                ):
                    result = self.service._emit_connected(
                        connect_generation=2,
                        vpn_process=process,
                        tun_device="tun-ms-sso7",
                    )

                self.assertFalse(result)
                self.assertEqual(len(configs), 1)
                self.assertEqual(len(ip4_configs), 1)
                ip4_config = ip4_configs[0]
                self.assertEqual(
                    int(ip4_config["address"]),
                    self.service._ipv4_to_nm_uint32("10.3.0.38"),
                )
                self.assertEqual(int(ip4_config["prefix"]), 32)
                self.assertTrue(bool(ip4_config["preserve-routes"]))
                self.assertTrue(bool(ip4_config["never-default"]))
                self.assertNotIn("addresses", ip4_config)
                self.assertNotIn("routes", ip4_config)
                self.assertEqual(list(ip4_config["domains"]).count("~."), 1)
                self.assertEqual(
                    [int(value) for value in ip4_config["dns"]],
                    [self.service._ipv4_to_nm_uint32("10.0.0.53")],
                )
                self.assertEqual(
                    states,
                    [SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTED],
                )

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

    def test_anyconnect_cookie_header_excludes_capture_metadata(self):
        header = self.service._build_anyconnect_cookie_header({
            "webvpn": "session",
            "webvpnc": "configuration",
            "vendor-cookie": "preserved",
            "_vendor-cookie": "also-preserved",
            "SAMLResponse": "large-assertion",
            "saml-username": "captured-user",
            "_gateway_ip": "192.0.2.10",
        })

        self.assertEqual(
            header,
            "webvpn=session; webvpnc=configuration; vendor-cookie=preserved; "
            "_vendor-cookie=also-preserved",
        )
        self.assertNotIn("large-assertion", header)
        self.assertNotIn("captured-user", header)

    def test_anyconnect_memfd_config_preserves_cookie_larger_than_7_kib(self):
        cookie_header = (
            "webvpn=session; webvpnc="
            + ("configuration-fragment-" * 340)
            + "; vendor-cookie=preserved"
        )
        expected = f"cookie={cookie_header}\n".encode("utf-8")
        self.assertGreater(len(expected), 7 * 1024)

        config_fd = self.service._create_anyconnect_cookie_config_fd(
            cookie_header
        )
        try:
            actual = b""
            while True:
                chunk = os.read(config_fd, 8192)
                if not chunk:
                    break
                actual += chunk
        finally:
            os.close(config_fd)

        self.assertEqual(actual, expected)

    def test_anyconnect_memfd_survives_popen_when_stdin_was_closed(self):
        regression_script = textwrap.dedent(
            r"""
            import importlib.util
            import os
            import subprocess
            import sys

            service_path = sys.argv[1]
            spec = importlib.util.spec_from_file_location(
                "nm_ms_sso_closed_stdin_regression",
                service_path,
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            service = object.__new__(module.VPNPluginService)

            os.close(0)
            real_memfd_create = module.os.memfd_create
            raw_fds = []

            def recording_memfd_create(*args, **kwargs):
                raw_fd = real_memfd_create(*args, **kwargs)
                raw_fds.append(raw_fd)
                return raw_fd

            module.os.memfd_create = recording_memfd_create
            cookie_header = "webvpn=session; webvpnc=configuration"
            expected = service._build_anyconnect_cookie_config(cookie_header)
            config_fd = service._create_anyconnect_cookie_config_fd(cookie_header)
            if raw_fds != [0]:
                raise RuntimeError(f"closed stdin did not yield raw fd 0: {raw_fds}")
            if config_fd < 3:
                raise RuntimeError(f"unsafe duplicated config fd: {config_fd}")

            reader_code = (
                "import pathlib, sys; "
                "sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())"
            )
            try:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        reader_code,
                        f"/proc/self/fd/{config_fd}",
                    ],
                    **service._build_anyconnect_popen_kwargs(config_fd),
                )
            finally:
                os.close(config_fd)

            output = process.communicate(timeout=10)[0]
            if process.returncode != 0 or output != expected:
                raise RuntimeError(
                    f"inherited config read failed: rc={process.returncode}, "
                    f"bytes={len(output)}"
                )
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", regression_script, str(SERVICE_PATH)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def test_anyconnect_command_reads_cookie_from_inherited_memfd_config(self):
        command = self.service._build_anyconnect_openconnect_command(
            openconnect_bin="openconnect",
            proto_flag="anyconnect",
            gateway="vpn.example.edu",
            cookie_config_fd=73,
            resolve_arg="--resolve=vpn.example.edu:192.0.2.10",
            interface_name="tun-ms-sso7",
        )

        self.assertIn("--config=/proc/self/fd/73", command)
        self.assertIn("--non-inter", command)
        self.assertIn("--interface=tun-ms-sso7", command)
        self.assertIn("--resolve=vpn.example.edu:192.0.2.10", command)
        self.assertIn("--force-dpd=30", command)
        self.assertNotIn("--force-dpd=10", command)
        self.assertNotIn("--cookie-on-stdin", command)
        self.assertFalse(any(argument.startswith("--cookie=") for argument in command))

    def test_anyconnect_popen_inherits_only_config_fd_and_disables_stdin(self):
        kwargs = self.service._build_anyconnect_popen_kwargs(73)

        self.assertEqual(kwargs["pass_fds"], (73,))
        self.assertEqual(kwargs["stdin"], SERVICE_MODULE.subprocess.DEVNULL)
        self.assertEqual(kwargs["stdout"], SERVICE_MODULE.subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], SERVICE_MODULE.subprocess.STDOUT)

    def test_service_has_no_live_cookie_debug_dump_escape_hatch(self):
        service_source = SERVICE_PATH.read_text(encoding="utf-8")

        for forbidden in (
            "MS_SSO_NM_DEBUG_DUMP_COOKIES",
            "/tmp/nm-vpn-cached-cookies.json",
            "/tmp/nm-vpn-fresh-cookies.json",
            "/tmp/nm-vpn-debug-cmd.txt",
        ):
            self.assertNotIn(forbidden, service_source)

    def test_anyconnect_structural_readiness_requires_stable_ifindex_and_ip(self):
        ready, stable_ifindex, stable_since = (
            self.service._advance_anyconnect_structural_readiness(
                candidate_ifindex=42,
                ip_addr="10.0.0.10",
                stable_ifindex=None,
                stable_since=None,
                now=10.0,
                grace_seconds=1.0,
            )
        )
        self.assertFalse(ready)
        self.assertEqual(stable_ifindex, 42)
        self.assertEqual(stable_since, 10.0)

        ready, stable_ifindex, stable_since = (
            self.service._advance_anyconnect_structural_readiness(
                candidate_ifindex=42,
                ip_addr="10.0.0.10",
                stable_ifindex=stable_ifindex,
                stable_since=stable_since,
                now=11.0,
                grace_seconds=1.0,
            )
        )
        self.assertTrue(ready)
        self.assertEqual(stable_ifindex, 42)
        self.assertEqual(stable_since, 10.0)

        ready, stable_ifindex, stable_since = (
            self.service._advance_anyconnect_structural_readiness(
                candidate_ifindex=43,
                ip_addr="10.0.0.10",
                stable_ifindex=stable_ifindex,
                stable_since=stable_since,
                now=12.0,
                grace_seconds=1.0,
            )
        )
        self.assertFalse(ready)
        self.assertEqual(stable_ifindex, 43)
        self.assertEqual(stable_since, 12.0)

        ready, stable_ifindex, stable_since = (
            self.service._advance_anyconnect_structural_readiness(
                candidate_ifindex=43,
                ip_addr=None,
                stable_ifindex=stable_ifindex,
                stable_since=stable_since,
                now=13.0,
                grace_seconds=1.0,
            )
        )
        self.assertFalse(ready)
        self.assertIsNone(stable_ifindex)
        self.assertIsNone(stable_since)

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
                protocol="anyconnect",
                disable_browser_session_cache=False,
                cancel_callback=lambda: False,
            )

        self.assertEqual(result, cookies)
        self.assertEqual(auth.call_count, 2)
        self.assertFalse(auth.call_args_list[0].kwargs["disable_browser_session_cache"])
        self.assertTrue(auth.call_args_list[1].kwargs["disable_browser_session_cache"])

    def test_gp_browser_ui_stall_is_not_retried_in_clean_session(self):
        with patch.object(
            SERVICE_MODULE,
            "do_saml_auth",
            side_effect=SERVICE_MODULE.SamlUiStalledError("stalled"),
        ) as auth:
            with self.assertRaises(SERVICE_MODULE.SamlUiStalledError):
                self.service._do_saml_auth_with_ui_stall_fallback(
                    vpn_server="vpn.example.edu",
                    protocol="gp",
                    disable_browser_session_cache=False,
                    cancel_callback=lambda: False,
                )

        auth.assert_called_once()

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

    def test_anyconnect_totp_uses_clean_browser_session_by_default(self):
        disabled = self.service._browser_session_cache_disabled(
            "anyconnect",
            "totp",
            "TESTTOTPSECRET",
            explicitly_disabled=False,
            explicitly_enabled=False,
        )

        self.assertTrue(disabled)

    def test_browser_session_cache_can_still_be_explicitly_enabled(self):
        disabled = self.service._browser_session_cache_disabled(
            "anyconnect",
            "totp",
            "TESTTOTPSECRET",
            explicitly_disabled=True,
            explicitly_enabled=True,
        )

        self.assertFalse(disabled)

    def test_push_and_globalprotect_keep_browser_session_cache_default(self):
        for protocol, preference, secret in (
            ("anyconnect", "push", "TESTTOTPSECRET"),
            ("anyconnect", "totp", ""),
            ("gp", "totp", "TESTTOTPSECRET"),
        ):
            with self.subTest(protocol=protocol, preference=preference):
                self.assertFalse(
                    self.service._browser_session_cache_disabled(
                        protocol,
                        preference,
                        secret,
                        explicitly_disabled=False,
                        explicitly_enabled=False,
                    )
                )

    def test_reconnect_waits_for_prior_auth_worker_instead_of_rejecting(self):
        prior_thread = MagicMock()
        prior_thread.is_alive.return_value = False
        self.service._connect_generation = 7

        with patch.object(self.service, "_cleanup_dns") as cleanup, patch.object(
            self.service,
            "_connect_thread",
        ) as connect:
            self.service._connect_after_prior_activation(
                prior_thread,
                None,
                {"vpn": {}},
                7,
            )

        prior_thread.join.assert_called_once_with(
            timeout=SERVICE_MODULE.CONNECT_DRAIN_TIMEOUT_SECONDS
        )
        cleanup.assert_called_once_with()
        connect.assert_called_once_with({"vpn": {}}, 7)

    def test_reconnect_after_recovery_is_not_cancelled_by_old_generation_flag(self):
        recovery_thread = MagicMock()
        recovery_thread.is_alive.return_value = False
        self.service._connect_generation = 8
        self.service.cancel_requested = True

        with patch.object(self.service, "_connect_thread") as connect:
            self.service._connect_after_recovery(
                recovery_thread,
                {"vpn": {}},
                8,
            )

        connect.assert_called_once_with({"vpn": {}}, 8)

    def test_failed_attempt_cleanup_precedes_fresh_anyconnect_auth_retries(self):
        """A failed attempt's DNS firewall must not reach the next SAML flow."""
        settings = {
            "connection": {"uuid": "test-anyconnect-uuid"},
            "vpn": {
                "data": {
                    "gateway": "vpn.example.edu",
                    "protocol": "anyconnect",
                    "username": "test-user",
                    "auto-reconnect": "false",
                },
                "secrets": {
                    "password": "test-password",
                    "totp-secret": "TESTTOTP",
                },
            },
            "ipv4": {"dns-priority": -100, "dns-search": ["~."]},
            "ipv6": {"dns-priority": -100},
        }
        cached_cookies = {
            "webvpn": "cached",
            "webvpnc": "cached-config",
        }
        events = []
        dns_firewall = {"active": False}
        fresh_auth_count = 0

        self.service.auth_in_progress = False
        self.service.auth_generation = None
        self.service.saml_start_time = None
        self.service._auth_started_guard_triggered = False

        def ensure_dns_profile_policy():
            self.service.dns_profile_policy_ready = True
            return True

        def attempt_vpn(_gateway, _protocol, cookies, _username, **_kwargs):
            dns_firewall["active"] = True
            events.append(f"attempt:{cookies['webvpn']}")
            if cookies["webvpn"] == "cached":
                return False, "Cookie rejected by server", 0
            return False, "VPN transport unavailable", 0

        def cleanup_dns():
            events.append("cleanup")
            dns_firewall["active"] = False
            return True

        def saml_auth(**_kwargs):
            nonlocal fresh_auth_count
            self.assertFalse(
                dns_firewall["active"],
                "fresh Microsoft SAML started behind the previous attempt's DNS firewall",
            )
            fresh_auth_count += 1
            events.append(f"saml:{fresh_auth_count}")
            return {
                "webvpn": f"fresh-{fresh_auth_count}",
                "webvpnc": "fresh-config",
            }

        test_environment = {
            "PATH": os.environ.get("PATH", ""),
            "MS_SSO_NM_ANYCONNECT_FRESH_RETRIES": "1",
            "MS_SSO_NM_ANYCONNECT_RETRY_DELAY_SECONDS": "0",
        }
        with patch.dict(os.environ, test_environment, clear=True), patch.object(
            self.service,
            "_reset_inactivity_timeout",
        ), patch.object(
            self.service,
            "_systemd_resolved_is_active",
            return_value=False,
        ), patch.object(
            self.service,
            "_ensure_dns_profile_policy",
            side_effect=ensure_dns_profile_policy,
        ), patch.object(
            self.service,
            "_capture_base_network_state",
        ), patch.object(
            self.service,
            "_wait_for_base_network_before_connect",
            return_value=True,
        ), patch.object(
            self.service,
            "_clear_onlink_host_route",
        ), patch.object(
            self.service,
            "_ensure_tun_available",
            return_value=True,
        ), patch.object(
            self.service,
            "_attempt_vpn_connection",
            side_effect=attempt_vpn,
        ), patch.object(
            self.service,
            "_cleanup_dns",
            side_effect=cleanup_dns,
        ), patch.object(
            self.service,
            "_do_saml_auth_with_ui_stall_fallback",
            side_effect=saml_auth,
        ), patch.object(
            SERVICE_MODULE.socket,
            "gethostbyname",
            return_value="192.0.2.10",
        ), patch.object(
            SERVICE_MODULE,
            "get_nm_stored_cookies",
            return_value=(cached_cookies, None),
        ), patch.object(
            SERVICE_MODULE,
            "clear_nm_cookies",
        ), patch.object(
            SERVICE_MODULE,
            "store_nm_cookies",
        ), patch.object(
            SERVICE_MODULE.GLib,
            "idle_add",
            return_value=1,
        ):
            self.service._connect_thread(settings, connect_generation=2)

        self.assertEqual(
            events,
            [
                "attempt:cached",
                "cleanup",
                "saml:1",
                "attempt:fresh-1",
                "cleanup",
                "saml:2",
                "attempt:fresh-2",
                "cleanup",
            ],
        )
        self.assertFalse(dns_firewall["active"])

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
        self.assertIn("--non-inter", command)
        self.assertFalse(any("portal-cookie" in arg for arg in command))
        self.assertIn("--user=saml-returned-user", command)
        self.assertIn("--usergroup=portal:portal-userauthcookie", command)
        self.assertIn("--useragent=PAN GlobalProtect", command)
        self.assertIn("--os=linux-64", command)
        self.assertIn("--csd-wrapper=/usr/libexec/nm-ms-sso-gp-hipreport", command)
        self.assertIn("--interface=tun-ms-sso7", command)
        self.assertIn("--force-dpd=10", command)
        self.assertNotIn("--force-dpd=30", command)
        self.assertNotIn("--no-dtls", command)

    def test_gp_gateway_route_mismatch_detects_stale_nonprimary_uplink(self):
        self.service.pre_vpn_uplinks = {
            "eth0": "wired-uuid",
            "wlan0": "wifi-uuid",
        }
        self.service._list_connected_uplinks = lambda: dict(
            self.service.pre_vpn_uplinks
        )
        for defaults, gateway_device, expected in (
            (
                "default via 192.0.2.1 dev eth0 metric 100\n"
                "default via 192.0.2.1 dev wlan0 metric 600\n",
                "eth0",
                False,
            ),
            (
                "default via 192.0.2.1 dev wlan0 metric 600\n"
                "default via 192.0.2.1 dev eth0 metric 100\n",
                "wlan0",
                True,
            ),
            (
                "default via 192.0.2.1 dev eth0 metric 100\n"
                "default via 192.0.2.1 dev wlan0 metric 100\n",
                "wlan0",
                False,
            ),
            (
                "default dev wg0 metric 5\n"
                "default via 192.0.2.1 dev eth0 metric 100\n"
                "default via 192.0.2.1 dev wlan0 metric 600\n",
                "eth0",
                False,
            ),
        ):
            with self.subTest(gateway_device=gateway_device):
                default_routes = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=defaults,
                    stderr="",
                )
                gateway_route = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout=(
                        "192.0.2.10 via 192.0.2.1 "
                        f"dev {gateway_device} src 192.0.2.20\n"
                    ),
                    stderr="",
                )
                with patch.object(
                    SERVICE_MODULE.subprocess,
                    "run",
                    side_effect=(default_routes, gateway_route),
                ):
                    self.assertEqual(
                        self.service._gp_gateway_route_mismatch("192.0.2.10"),
                        expected,
                    )

        failed_defaults = subprocess.CompletedProcess(
            args=[],
            returncode=2,
            stdout="",
            stderr="failed",
        )
        with patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            return_value=failed_defaults,
        ) as run:
            self.assertFalse(
                self.service._gp_gateway_route_mismatch("192.0.2.10")
            )
        run.assert_called_once()

    def test_gp_gateway_route_stabilization_requires_two_stable_samples(self):
        self.service._uplinks_needing_reapply = set()
        current_uplinks = {
            "eth0": "wired-uuid",
            "wlan0": "wifi-uuid",
        }
        with patch.object(
            self.service,
            "_gp_gateway_route_mismatch",
            side_effect=[True, False, False],
        ) as mismatch, patch.object(
            self.service,
            "_list_connected_uplinks",
            return_value=current_uplinks,
        ), patch.object(
            self.service,
            "_reapply_connected_uplinks",
        ) as reapply, patch.object(
            SERVICE_MODULE.time,
            "sleep",
        ) as sleep:
            stable = self.service._stabilize_gp_gateway_route("192.0.2.10")

        self.assertTrue(stable)
        self.assertEqual(
            self.service._uplinks_needing_reapply,
            {"eth0", "wlan0"},
        )
        self.assertEqual(mismatch.call_count, 3)
        reapply.assert_called_once_with()
        sleep.assert_called_once_with(0.2)

    def test_gp_gateway_route_stabilization_is_bounded_when_still_stale(self):
        self.service._uplinks_needing_reapply = set()
        with patch.object(
            self.service,
            "_gp_gateway_route_mismatch",
            return_value=True,
        ) as mismatch, patch.object(
            self.service,
            "_list_connected_uplinks",
            return_value={"eth0": "wired-uuid"},
        ), patch.object(
            self.service,
            "_reapply_connected_uplinks",
        ) as reapply, patch.object(
            SERVICE_MODULE.time,
            "sleep",
        ) as sleep:
            stable = self.service._stabilize_gp_gateway_route("192.0.2.10")

        self.assertFalse(stable)
        reapply.assert_called_once_with()
        self.assertEqual(
            mismatch.call_count,
            1 + len(SERVICE_MODULE.GP_GATEWAY_ROUTE_STABILIZATION_DELAYS),
        )
        self.assertEqual(
            [item.args[0] for item in sleep.call_args_list],
            [
                delay
                for delay in SERVICE_MODULE.GP_GATEWAY_ROUTE_STABILIZATION_DELAYS
                if delay
            ],
        )

    def test_gp_gateway_route_stabilization_skips_reapply_when_already_stable(self):
        self.service._uplinks_needing_reapply = set()
        with patch.object(
            self.service,
            "_gp_gateway_route_mismatch",
            return_value=False,
        ), patch.object(
            self.service,
            "_list_connected_uplinks",
        ) as list_uplinks, patch.object(
            self.service,
            "_reapply_connected_uplinks",
        ) as reapply:
            stable = self.service._stabilize_gp_gateway_route("192.0.2.10")

        self.assertTrue(stable)
        list_uplinks.assert_not_called()
        reapply.assert_not_called()

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

    def test_vpn_dns_domains_always_include_root_route(self):
        self.service.vpn_domains = ["corp.example", "~corp.example", "~."]
        for protocol in ("gp", "anyconnect"):
            for tunnel_all_dns in (None, False, True):
                with self.subTest(protocol=protocol, tunnel_all_dns=tunnel_all_dns):
                    self.service.current_protocol = protocol
                    self.service.vpn_tunnel_all_dns = tunnel_all_dns
                    domains = self.service._normalize_vpn_domains()
                    self.assertEqual(domains.count("~."), 1)
                    self.assertIn("~corp.example", domains)

    def test_dns_candidates_prefer_configured_pushed_then_unibas_fallback(self):
        self.service.current_gateway_host = "vpn.unibas.ch"
        self.service.configured_dns_servers = "10.0.0.53, 10.0.0.54"
        self.service.vpn_dns_servers = ["10.0.0.55"]
        self.assertEqual(
            self.service._dns_candidates_for_vpn("gp"),
            ["10.0.0.53", "10.0.0.54"],
        )

        self.service.configured_dns_servers = []
        self.assertEqual(
            self.service._dns_candidates_for_vpn("gp"),
            ["10.0.0.55"],
        )

        self.service.vpn_dns_servers = []
        self.assertEqual(
            self.service._dns_candidates_for_vpn("gp"),
            ["131.152.1.1", "131.152.1.5"],
        )
        self.service.current_gateway_host = "vpn.unibas.ch.evil"
        self.assertEqual(self.service._dns_candidates_for_vpn("gp"), [])
        self.service.current_gateway_host = "vpn.unibas.ch"
        self.assertEqual(self.service._dns_candidates_for_vpn("anyconnect"), [])

    def test_connection_secrets_capture_configured_dns_servers(self):
        settings = {
            "vpn": {
                "data": {"dns-servers": "10.0.0.53,10.0.0.54"},
                "secrets": {"password": "set", "totp-secret": "set"},
            },
        }

        secrets = self.service._get_connection_secrets(settings)

        self.assertEqual(secrets["dns_servers"], "10.0.0.53,10.0.0.54")

    def test_dns_route_must_use_exact_owned_tunnel(self):
        for output, returncode, expected in (
            ("10.0.0.53 dev tun-ms-sso7 src 10.3.0.1", 0, True),
            ("10.0.0.53 dev eth0 src 192.0.2.10", 0, False),
            ("10.0.0.53 dev tun-ms-sso70 src 10.3.0.1", 0, False),
            ("", 2, False),
        ):
            with self.subTest(output=output, returncode=returncode), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=returncode,
                    stdout=output,
                    stderr="",
                ),
            ):
                self.assertEqual(
                    self.service._dns_route_uses_tunnel(
                        "10.0.0.53",
                        "tun-ms-sso7",
                    ),
                    expected,
                )

    def test_dns_probe_binds_to_tunnel_and_requires_answer(self):
        class FakeSocketContext:
            def __init__(self, response):
                self.response = response
                self.options = []
                self.destination = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def setsockopt(self, *args):
                self.options.append(args)

            def settimeout(self, _timeout):
                pass

            def sendto(self, _packet, destination):
                self.destination = destination

            def recvfrom(self, _size):
                return self.response, ("10.0.0.53", 53)

        response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        fake_socket = FakeSocketContext(response)
        with patch.object(
            self.service,
            "_build_dns_probe_query",
            return_value=(b"\x12\x34", b"query"),
        ), patch.object(
            SERVICE_MODULE.socket,
            "socket",
            return_value=fake_socket,
        ):
            self.assertTrue(self.service._probe_dns_server(
                "10.0.0.53",
                tun_device="tun-ms-sso7",
                require_answer=True,
            ))

        self.assertIn(
            (
                SERVICE_MODULE.socket.SOL_SOCKET,
                SERVICE_MODULE.socket.SO_BINDTODEVICE,
                b"tun-ms-sso7\0",
            ),
            fake_socket.options,
        )
        self.assertEqual(fake_socket.destination, ("10.0.0.53", 53))

        no_answer = FakeSocketContext(
            b"\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"
        )
        with patch.object(
            self.service,
            "_build_dns_probe_query",
            return_value=(b"\x12\x34", b"query"),
        ), patch.object(SERVICE_MODULE.socket, "socket", return_value=no_answer):
            self.assertFalse(self.service._probe_dns_server(
                "10.0.0.53",
                tun_device="tun-ms-sso7",
                require_answer=True,
            ))

    def test_full_dns_resolved_applies_global_route_on_owned_generation(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        successful = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(
            self.service,
            "_systemd_resolved_is_active",
            return_value=True,
        ), patch.object(
            self.service,
            "_resolved_dns_protection_matches",
            return_value=True,
        ), patch.object(
            SERVICE_MODULE.shutil,
            "which",
            return_value="/usr/bin/resolvectl",
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            return_value=successful,
        ) as run:
            self.assertTrue(self.service._apply_full_dns_resolved(
                "tun-ms-sso7",
                ["10.0.0.53", "10.0.0.54"],
                2,
            ))

        commands = [item.args[0] for item in run.call_args_list]
        self.assertEqual(commands[:3], [
            ["resolvectl", "dns", "tun-ms-sso7", "10.0.0.53", "10.0.0.54"],
            ["resolvectl", "domain", "tun-ms-sso7", "~."],
            ["resolvectl", "default-route", "tun-ms-sso7", "true"],
        ])

    def test_resolved_dns_verifier_requires_servers_root_and_owned_ifindex(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        replies = [
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=(
                    '[{"ifname":"tun-ms-sso7","ifindex":42,'
                    '"servers":[{"addressString":"10.0.0.53"}]}]'
                ),
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=(
                    '[{"ifname":"tun-ms-sso7","ifindex":42,'
                    '"searchDomains":[{"name":".","routeOnly":true}]}]'
                ),
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=(
                    '[{"ifname":"tun-ms-sso7","ifindex":42,'
                    '"defaultRoute":true}]'
                ),
            ),
        ]
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            side_effect=replies,
        ):
            self.assertTrue(self.service._resolved_dns_protection_matches(
                "tun-ms-sso7",
                ["10.0.0.53"],
            ))

        self.service.owned_tun_ifindices["tun-ms-sso7"] = 41
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
            self.assertFalse(self.service._resolved_dns_protection_matches(
                "tun-ms-sso7",
                ["10.0.0.53"],
            ))
            run.assert_not_called()

    def test_resolved_dns_verifier_falls_back_to_locale_pinned_text(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        replies = [
            SimpleNamespace(
                returncode=1,
                stderr="Unknown option --json=short",
                stdout="",
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout="Link 42 (tun-ms-sso7): 10.0.0.53 10.0.0.54\n",
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout="Link 42 (tun-ms-sso7): ~.\n",
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout="Link 42 (tun-ms-sso7): yes\n",
            ),
        ]
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            side_effect=replies,
        ) as run:
            self.assertTrue(self.service._resolved_dns_protection_matches(
                "tun-ms-sso7",
                ["10.0.0.53", "10.0.0.54"],
            ))

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["resolvectl", "dns", "tun-ms-sso7", "--json=short"],
                ["resolvectl", "dns", "tun-ms-sso7"],
                ["resolvectl", "domain", "tun-ms-sso7"],
                ["resolvectl", "default-route", "tun-ms-sso7"],
            ],
        )
        for call in run.call_args_list[1:]:
            self.assertEqual(call.kwargs["env"]["LC_ALL"], "C")

    def test_resolved_dns_verifier_rejects_an_extra_resolver(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        replies = [
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=(
                    '[{"ifindex":42,"servers":['
                    '{"addressString":"10.0.0.53"},'
                    '{"addressString":"192.0.2.53"}]}]'
                ),
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout=(
                    '[{"ifindex":42,"searchDomains":['
                    '{"name":".","routeOnly":true}]}]'
                ),
            ),
            SimpleNamespace(
                returncode=0,
                stderr="",
                stdout='[{"ifindex":42,"defaultRoute":true}]',
            ),
        ]
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            side_effect=replies,
        ):
            self.assertFalse(self.service._resolved_dns_protection_matches(
                "tun-ms-sso7", ["10.0.0.53"],
            ))

    def test_full_dns_resolved_rejects_stale_or_reused_tunnel(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        with patch.object(SERVICE_MODULE.subprocess, "run") as run:
            self.assertFalse(self.service._apply_full_dns_resolved(
                "tun-ms-sso7", ["10.0.0.53"], 1,
            ))
            run.assert_not_called()
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=99,
        ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
            self.assertFalse(self.service._apply_full_dns_resolved(
                "tun-ms-sso7", ["10.0.0.53"], 2,
            ))
            run.assert_not_called()

    def test_collect_tunnel_dns_waits_for_vpnc_script_route_convergence(self):
        # vpnc-script addresses the tunnel before it replaces the default
        # route, so the first route lookups still resolve via an uplink.
        process = object()
        self.service.vpn_process = process
        route_results = [False, False, False, True]
        with patch.object(
            self.service,
            "_dns_route_uses_tunnel",
            side_effect=route_results,
        ) as route, patch.object(
            self.service,
            "_probe_dns_server",
            return_value=True,
        ), patch("time.sleep"):
            working = self.service._collect_tunnel_dns_servers(
                ["10.0.0.53"],
                "tun-ms-sso7",
                1,
                connect_generation=2,
                process=process,
                timeout_seconds=20,
            )

        self.assertEqual(working, ["10.0.0.53"])
        self.assertEqual(route.call_count, len(route_results))

    def test_collect_tunnel_dns_fails_closed_when_route_never_converges(self):
        process = object()
        self.service.vpn_process = process
        with patch.object(
            self.service,
            "_dns_route_uses_tunnel",
            return_value=False,
        ) as route, patch.object(
            self.service,
            "_probe_dns_server",
            return_value=True,
        ) as probe, patch("time.sleep"):
            working = self.service._collect_tunnel_dns_servers(
                ["10.0.0.53"],
                "tun-ms-sso7",
                1,
                connect_generation=2,
                process=process,
                timeout_seconds=1,
            )

        self.assertEqual(working, [])
        probe.assert_not_called()
        # The mismatch is reported once the wait is abandoned, not per poll.
        self.assertEqual(
            [call.kwargs.get("log_mismatch") for call in route.call_args_list].count(True),
            1,
        )

    def test_collect_tunnel_dns_stops_when_openconnect_exits(self):
        process = MagicMock()
        process.poll.return_value = 1
        self.service.vpn_process = process
        with patch.object(
            self.service,
            "_dns_route_uses_tunnel",
            return_value=False,
        ) as route, patch("time.sleep"):
            working = self.service._collect_tunnel_dns_servers(
                ["10.0.0.53"],
                "tun-ms-sso7",
                1,
                connect_generation=2,
                process=process,
                timeout_seconds=20,
            )

        self.assertEqual(working, [])
        route.assert_not_called()

    def test_prepare_dns_protection_filters_to_tunnel_responders(self):
        process = object()
        self.service.vpn_process = process
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        self.service.current_dns_server_limit = 1
        with patch.object(
            self.service,
            "_dns_candidates_for_vpn",
            return_value=["10.0.0.53", "10.0.0.54"],
        ), patch.object(
            self.service,
            "_dns_route_uses_tunnel",
            side_effect=[False, True],
        ), patch.object(
            self.service,
            "_probe_dns_server",
            return_value=True,
        ) as probe, patch.object(
            self.service,
            "_apply_full_dns_resolved",
            return_value=True,
        ) as apply_dns:
            self.assertTrue(self.service._prepare_vpn_dns_protection(
                "gp", "tun-ms-sso7", 2, process=process,
            ))

        self.assertEqual(self.service.vpn_dns_servers, ["10.0.0.54"])
        self.assertTrue(self.service.dns_leak_protection_ready)
        probe.assert_called_once_with(
            "10.0.0.54",
            tun_device="tun-ms-sso7",
            require_answer=True,
        )
        apply_dns.assert_called_once_with("tun-ms-sso7", ["10.0.0.54"], 2)

    def test_prepare_dns_protection_fails_closed_without_candidates(self):
        process = object()
        self.service.vpn_process = process
        with patch.object(
            self.service,
            "_dns_candidates_for_vpn",
            return_value=[],
        ):
            self.assertFalse(self.service._prepare_vpn_dns_protection(
                "gp", "tun-ms-sso7", 2, process=process,
            ))
        self.assertFalse(self.service.dns_leak_protection_ready)

    def test_dns_profile_policy_sets_exclusive_priority_and_root(self):
        self.service.current_connection_uuid = "vpn-uuid"
        modifications = []
        reads = {
            "vpn.service-type": ["org.freedesktop.NetworkManager.ms-sso\n"],
            "ipv4.dns-priority": ["0\n", "-100\n"],
            "ipv4.dns-search": ["\n", "~.\n"],
            "ipv6.dns-priority": ["0\n", "-100\n"],
        }

        def run_nmcli(command, **_kwargs):
            if command[1] == "--get-values":
                value = reads[command[2]].pop(0)
                return SimpleNamespace(returncode=0, stdout=value, stderr="")
            modifications.append(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(
            SERVICE_MODULE.shutil,
            "which",
            return_value="/usr/bin/nmcli",
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            side_effect=run_nmcli,
        ):
            self.assertTrue(self.service._ensure_dns_profile_policy())

        self.assertEqual(len(modifications), 1)
        command = modifications[0]
        self.assertIn("ipv4.dns-priority", command)
        self.assertIn("ipv6.dns-priority", command)
        self.assertIn("+ipv4.dns-search", command)
        self.assertIn("~.", command)

    def test_networkmanager_backend_requires_both_dns_policy_snapshots(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        self.service.vpn_dns_backend = "networkmanager"
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
            cases = (
                (True, True, True),
                (False, True, False),
                (True, False, False),
                (False, False, False),
            )
            for profile_ready, activation_ready, expected in cases:
                with self.subTest(
                    profile_ready=profile_ready,
                    activation_ready=activation_ready,
                ):
                    self.service.dns_profile_policy_ready = profile_ready
                    self.service.dns_activation_policy_ready = activation_ready
                    self.assertEqual(
                        self.service._apply_full_dns_resolved(
                            "tun-ms-sso7", ["10.0.0.53"], 2,
                        ),
                        expected,
                    )
            run.assert_not_called()

    def test_connection_snapshot_requires_exclusive_v4_v6_dns_and_root_route(self):
        valid = {
            "ipv4": {
                "dns-priority": -100,
                "dns-search": ["vpn.example.edu", "~."],
            },
            "ipv6": {"dns-priority": "-25"},
        }
        self.assertTrue(self.service._connection_snapshot_has_dns_policy(valid))

        invalid = {
            "missing_ipv4_priority": {
                "ipv4": {"dns-search": ["~."]},
                "ipv6": {"dns-priority": -100},
            },
            "missing_ipv6_priority": {
                "ipv4": {"dns-priority": -100, "dns-search": ["~."]},
                "ipv6": {},
            },
            "missing_root_route": {
                "ipv4": {
                    "dns-priority": -100,
                    "dns-search": ["vpn.example.edu"],
                },
                "ipv6": {"dns-priority": -100},
            },
        }
        for label, settings in invalid.items():
            with self.subTest(label=label):
                self.assertFalse(
                    self.service._connection_snapshot_has_dns_policy(settings)
                )

    def test_pinned_resolved_backend_fails_closed_if_daemon_disappears(self):
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.owned_tun_devices = {"tun-ms-sso7"}
        self.service.owned_tun_ifindices = {"tun-ms-sso7": 42}
        self.service.vpn_dns_backend = "resolved"
        with patch.object(
            self.service,
            "_link_ifindex",
            return_value=42,
        ), patch.object(
            self.service,
            "_systemd_resolved_is_active",
            return_value=False,
        ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
            self.assertFalse(self.service._apply_full_dns_resolved(
                "tun-ms-sso7", ["10.0.0.53"], 2,
            ))
            run.assert_not_called()

    def test_dns_profile_policy_repairs_ipv6_priority_when_ipv4_is_ready(self):
        self.service.current_connection_uuid = "vpn-uuid"
        reads = {
            "vpn.service-type": ["org.freedesktop.NetworkManager.ms-sso\n"],
            "ipv4.dns-priority": ["-100\n", "-100\n"],
            "ipv4.dns-search": ["~.\n", "~.\n"],
            "ipv6.dns-priority": ["0\n", "-100\n"],
        }
        modifications = []

        def run_nmcli(command, **_kwargs):
            if command[1] == "--get-values":
                return SimpleNamespace(
                    returncode=0,
                    stdout=reads[command[2]].pop(0),
                    stderr="",
                )
            modifications.append(command)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(
            SERVICE_MODULE.shutil,
            "which",
            return_value="/usr/bin/nmcli",
        ), patch.object(
            SERVICE_MODULE.subprocess,
            "run",
            side_effect=run_nmcli,
        ):
            self.assertTrue(self.service._ensure_dns_profile_policy())

        self.assertEqual(len(modifications), 1)
        self.assertIn("ipv6.dns-priority", modifications[0])
        self.assertNotIn("+ipv4.dns-search", modifications[0])

    def test_only_explicit_leak_failure_prefix_is_terminal(self):
        self.assertTrue(self.service._is_leak_protection_failure(
            "Leak protection failed: DNS unavailable"
        ))
        self.assertFalse(self.service._is_leak_protection_failure(
            "OpenConnect DNS negotiation failed"
        ))

    def test_connected_callback_refuses_missing_leak_readiness(self):
        process = SimpleNamespace(poll=lambda: None)
        self.service.vpn_process = process
        self.service.current_tun_device = "tun-ms-sso7"
        self.service.current_gateway = "vpn.example.edu"
        self.service.Config = lambda _config: self.fail("Config must not be emitted")
        self.service.Ip4Config = lambda _config: self.fail("Ip4Config must not be emitted")
        self.service._emit_failure = lambda *_args: False
        self.service._stop_vpn_process = lambda **_kwargs: None

        self.service.dns_leak_protection_ready = False
        self.assertFalse(self.service._emit_connected(2, process, "tun-ms-sso7"))

        self.service.dns_leak_protection_ready = True
        self.service._apply_ipv6_leak_protection = lambda: False
        self.assertFalse(self.service._emit_connected(2, process, "tun-ms-sso7"))


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
        self.service.pending_tun_device = None
        self.service.current_dns_server_limit = 3
        self.service.configured_dns_servers = []
        self.service.vpn_dns_servers = []
        self.service.vpn_dns_backend = None
        self.service.dns_profile_policy_ready = False
        self.service.dns_activation_policy_ready = False
        self.service.dns_leak_protection_ready = False
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

    @staticmethod
    def _ipv6_firewall_marker_text(connection_uuid="vpn-uuid"):
        return (
            "version=1\n"
            f"connection_uuid={connection_uuid}\n"
            "family=inet\n"
            "table=nm_ms_sso_ipv6\n"
        )

    @staticmethod
    def _nft_firewall_document(ipv6_devices, dns_devices):
        def oif_match(devices):
            return {
                "match": {
                    "op": "!=",
                    "left": {"meta": {"key": "oifname"}},
                    "right": {"set": sorted(devices)},
                },
            }

        def dns_rule(protocol, comment):
            return {
                "rule": {
                    "family": "inet",
                    "table": "nm_ms_sso_ipv6",
                    "chain": "output",
                    "comment": comment,
                    "expr": [
                        oif_match(dns_devices),
                        {
                            "match": {
                                "op": "==",
                                "left": {
                                    "payload": {
                                        "protocol": protocol,
                                        "field": "dport",
                                    },
                                },
                                "right": {"set": [53, 853]},
                            },
                        },
                        {"counter": {"packets": 0, "bytes": 0}},
                        {"drop": None},
                    ],
                },
            }

        return {
            "nftables": [
                {
                    "table": {
                        "family": "inet",
                        "name": "nm_ms_sso_ipv6",
                    },
                },
                {
                    "chain": {
                        "family": "inet",
                        "table": "nm_ms_sso_ipv6",
                        "name": "output",
                        "type": "filter",
                        "hook": "output",
                        "prio": -150,
                        "policy": "accept",
                    },
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "nm_ms_sso_ipv6",
                        "chain": "output",
                        "comment": SERVICE_MODULE.IPV6_FIREWALL_COMMENT,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "nfproto"}},
                                    "right": "ipv6",
                                },
                            },
                            oif_match(ipv6_devices),
                            {"counter": {"packets": 0, "bytes": 0}},
                            {"drop": None},
                        ],
                    },
                },
                dns_rule("udp", SERVICE_MODULE.DNS_UDP_FIREWALL_COMMENT),
                dns_rule("tcp", SERVICE_MODULE.DNS_TCP_FIREWALL_COMMENT),
            ],
        }

    @staticmethod
    def _nft_rule(document, comment):
        return next(
            entry["rule"]
            for entry in document["nftables"]
            if entry.get("rule", {}).get("comment") == comment
        )

    def test_ipv6_firewall_policy_is_written_after_durable_marker(self):
        with tempfile.TemporaryDirectory() as tempdir:
            route_marker = Path(tempdir) / "ipv6-leak-route"
            firewall_marker = Path(tempdir) / "ipv6-firewall"
            recovery_lock = Path(tempdir) / "recovery.lock"
            self.service.current_tun_device = "tun-current"
            self.service.pending_tun_device = "tun-pending"
            expected_ipv6_devices = {
                "lo",
                "tun-current",
                "tun-pending",
                "wg-dgx",
                "wg0",
            }
            expected_dns_devices = {"lo", "tun-current", "tun-pending"}
            nft_batches = []

            def run(command, **kwargs):
                if command == ["ip", "-o", "link", "show", "type", "wireguard"]:
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(
                            "5: wg0: <POINTOPOINT,NOARP,UP> mtu 1420 state UNKNOWN\n"
                            "6: wg-dgx@NONE: <POINTOPOINT,NOARP,UP> mtu 1420 "
                            "state UNKNOWN\n"
                        ),
                        stderr="",
                    )
                if command == ["nft", "-f", "-"]:
                    self.assertTrue(firewall_marker.exists())
                    self.assertEqual(
                        firewall_marker.read_text(encoding="utf-8"),
                        self._ipv6_firewall_marker_text(),
                    )
                    nft_batches.append(kwargs["input"])
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                self.fail(f"Unexpected command: {command!r}")

            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                route_marker,
            ), patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.object(
                SERVICE_MODULE,
                "RECOVERY_LOCK_FILE",
                recovery_lock,
            ), patch.object(
                self.service,
                "_ipv6_firewall_table_present",
                return_value=False,
            ), patch.object(
                self.service,
                "_verify_ipv6_firewall",
                return_value=True,
            ) as verify, patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                side_effect=run,
            ):
                self.assertTrue(self.service._install_ipv6_firewall())

            verify.assert_called_once_with(
                expected_ipv6_devices,
                expected_dns_devices,
            )
            self.assertEqual(len(nft_batches), 1)
            self.assertEqual(
                nft_batches[0],
                "add table inet nm_ms_sso_ipv6\n"
                "add chain inet nm_ms_sso_ipv6 output "
                "{ type filter hook output priority -150; policy accept; }\n"
                "add rule inet nm_ms_sso_ipv6 output meta nfproto ipv6 "
                "oifname != { \"lo\", \"tun-current\", \"tun-pending\", "
                "\"wg-dgx\", \"wg0\" } counter drop "
                "comment \"nm-ms-sso direct IPv6 kill switch\"\n"
                "add rule inet nm_ms_sso_ipv6 output "
                "oifname != { \"lo\", \"tun-current\", \"tun-pending\" } "
                "udp dport { 53, 853 } counter drop "
                "comment \"nm-ms-sso direct UDP DNS kill switch\"\n"
                "add rule inet nm_ms_sso_ipv6 output "
                "oifname != { \"lo\", \"tun-current\", \"tun-pending\" } "
                "tcp dport { 53, 853 } counter drop "
                "comment \"nm-ms-sso direct TCP DNS kill switch\"\n",
            )
            self.assertNotIn("eth0", nft_batches[0])
            # WireGuard remains available for IPv6 routes but cannot bypass
            # the VPN-only resolver path.
            self.assertEqual(nft_batches[0].count('"wg-dgx"'), 1)
            self.assertEqual(nft_batches[0].count('"wg0"'), 1)

    def test_ipv6_firewall_json_verifier_accepts_exact_three_rule_policy(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-firewall"
            marker.write_text(
                self._ipv6_firewall_marker_text(),
                encoding="utf-8",
            )
            expected_ipv6 = {"lo", "tun-current", "tun-pending", "wg0"}
            expected_dns = {"lo", "tun-current", "tun-pending"}
            document = self._nft_firewall_document(expected_ipv6, expected_dns)
            result = SimpleNamespace(
                returncode=0,
                stdout=json.dumps(document),
                stderr="",
            )

            with patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                marker,
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                return_value=result,
            ) as run:
                self.assertTrue(self.service._verify_ipv6_firewall(
                    expected_ipv6,
                    expected_dns,
                ))

            run.assert_called_once_with(
                ["nft", "-j", "list", "table", "inet", "nm_ms_sso_ipv6"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )

    def test_ipv6_firewall_json_verifier_rejects_policy_variations(self):
        expected_ipv6 = {"lo", "tun-current", "tun-pending", "wg0"}
        expected_dns = {"lo", "tun-current", "tun-pending"}

        extra_physical = self._nft_firewall_document(
            expected_ipv6 | {"eth0"},
            expected_dns,
        )
        missing_wireguard = self._nft_firewall_document(
            expected_ipv6 - {"wg0"},
            expected_dns,
        )
        dns_over_wireguard = self._nft_firewall_document(
            expected_ipv6,
            expected_dns | {"wg0"},
        )
        wrong_drop = self._nft_firewall_document(expected_ipv6, expected_dns)
        ipv6_rule = self._nft_rule(
            wrong_drop,
            SERVICE_MODULE.IPV6_FIREWALL_COMMENT,
        )
        ipv6_rule["expr"][-1] = {"accept": None}
        wrong_match = self._nft_firewall_document(expected_ipv6, expected_dns)
        ipv6_rule = self._nft_rule(
            wrong_match,
            SERVICE_MODULE.IPV6_FIREWALL_COMMENT,
        )
        ipv6_rule["expr"][1]["match"]["op"] = "=="
        wrong_dns_ports = self._nft_firewall_document(expected_ipv6, expected_dns)
        udp_rule = self._nft_rule(
            wrong_dns_ports,
            SERVICE_MODULE.DNS_UDP_FIREWALL_COMMENT,
        )
        udp_rule["expr"][1]["match"]["right"] = {"set": [53]}

        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-firewall"
            marker.write_text(
                self._ipv6_firewall_marker_text(),
                encoding="utf-8",
            )
            with patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                marker,
            ):
                for name, document in (
                    ("extra physical IPv6 interface", extra_physical),
                    ("missing WireGuard IPv6 interface", missing_wireguard),
                    ("DNS allowed over WireGuard", dns_over_wireguard),
                    ("wrong IPv6 verdict", wrong_drop),
                    ("wrong IPv6 interface match", wrong_match),
                    ("missing encrypted-DNS port", wrong_dns_ports),
                ):
                    with self.subTest(name=name), patch.object(
                        SERVICE_MODULE.subprocess,
                        "run",
                        return_value=SimpleNamespace(
                            returncode=0,
                            stdout=json.dumps(document),
                            stderr="",
                        ),
                    ):
                        self.assertFalse(self.service._verify_ipv6_firewall(
                            expected_ipv6,
                            expected_dns,
                        ))

    def test_ipv6_firewall_cleanup_requires_valid_marker_and_verified_absence(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-firewall"
            marker.write_text(
                self._ipv6_firewall_marker_text(),
                encoding="utf-8",
            )
            successful = SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                marker,
            ), patch.object(
                self.service,
                "_ipv6_firewall_table_present",
                side_effect=[True, False],
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                return_value=successful,
            ) as run:
                self.assertTrue(self.service._remove_owned_ipv6_firewall())

            run.assert_called_once_with(
                ["nft", "delete", "table", "inet", "nm_ms_sso_ipv6"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertFalse(marker.exists())

        for name, marker_text, table_states, delete_result in (
            (
                "invalid marker",
                "version=1\nconnection_uuid=vpn-uuid\n"
                "family=ip6\ntable=nm_ms_sso_ipv6\n",
                [],
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ),
            (
                "delete failed",
                self._ipv6_firewall_marker_text(),
                [True],
                SimpleNamespace(returncode=1, stdout="", stderr="denied"),
            ),
            (
                "absence unverified",
                self._ipv6_firewall_marker_text(),
                [True, None],
                SimpleNamespace(returncode=0, stdout="", stderr=""),
            ),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tempdir:
                marker = Path(tempdir) / "ipv6-firewall"
                marker.write_text(marker_text, encoding="utf-8")
                with patch.object(
                    SERVICE_MODULE,
                    "IPV6_FIREWALL_MARKER",
                    marker,
                ), patch.object(
                    self.service,
                    "_ipv6_firewall_table_present",
                    side_effect=table_states,
                ), patch.object(
                    SERVICE_MODULE.subprocess,
                    "run",
                    return_value=delete_result,
                ) as run:
                    self.assertFalse(self.service._remove_owned_ipv6_firewall())

                self.assertTrue(marker.exists())
                if name == "invalid marker":
                    run.assert_not_called()
                else:
                    run.assert_called_once_with(
                        [
                            "nft", "delete", "table", "inet",
                            "nm_ms_sso_ipv6",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=5,
                    )

    def test_ipv6_leak_marker_is_durable_before_route_is_added(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            firewall_marker = Path(tempdir) / "ipv6-firewall"
            route_commands = []

            def add_route(command, **_kwargs):
                route_commands.append(command)
                self.assertTrue(marker.exists())
                self.assertEqual(
                    marker.read_text(encoding="utf-8"),
                    "version=2\n"
                    "connection_uuid=vpn-uuid\n"
                    "metric=1\n"
                    "protocol=99\n",
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.dict(SERVICE_MODULE.os.environ, {}, clear=True), patch.object(
                self.service,
                "_recovery_state_lock",
                return_value=nullcontext(),
            ), patch.object(
                self.service,
                "_install_ipv6_firewall",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=False,
            ), patch.object(
                self.service,
                "_verify_ipv6_leak_protection",
                return_value=True,
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                side_effect=add_route,
            ):
                self.assertTrue(self.service._apply_ipv6_leak_protection())

            self.assertTrue(self.service.ipv6_leak_protection_enabled)
            self.assertTrue(marker.exists())
            self.assertEqual(route_commands, [[
                "ip", "-6", "route", "add", "unreachable", "::/0",
                "metric", "1", "proto", "99",
            ]])
            self.assertNotIn("replace", route_commands[0])

    def test_ipv6_leak_protection_explicit_opt_out_is_successful(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.dict(
                SERVICE_MODULE.os.environ,
                {"MS_SSO_NM_BLOCK_IPV6": "0"},
                clear=True,
            ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
                self.assertTrue(self.service._apply_ipv6_leak_protection())

            self.assertFalse(self.service.ipv6_leak_protection_enabled)
            self.assertFalse(marker.exists())
            run.assert_not_called()

    def test_ipv6_leak_protection_does_not_claim_preexisting_route(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            firewall_marker = Path(tempdir) / "ipv6-firewall"
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.dict(SERVICE_MODULE.os.environ, {}, clear=True), patch.object(
                self.service,
                "_recovery_state_lock",
                return_value=nullcontext(),
            ), patch.object(
                self.service,
                "_install_ipv6_firewall",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=True,
            ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
                self.assertFalse(self.service._apply_ipv6_leak_protection())

            self.assertFalse(marker.exists())
            self.assertFalse(self.service.ipv6_leak_protection_enabled)
            run.assert_not_called()

    def test_ipv6_leak_protection_add_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            firewall_marker = Path(tempdir) / "ipv6-firewall"
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.dict(SERVICE_MODULE.os.environ, {}, clear=True), patch.object(
                self.service,
                "_recovery_state_lock",
                return_value=nullcontext(),
            ), patch.object(
                self.service,
                "_install_ipv6_firewall",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                side_effect=[False, False],
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                return_value=SimpleNamespace(returncode=2, stdout="", stderr="denied"),
            ):
                self.assertFalse(self.service._apply_ipv6_leak_protection())

            self.assertFalse(marker.exists())
            self.assertFalse(self.service.ipv6_leak_protection_enabled)

    def test_ipv6_leak_marker_survives_until_route_absence_is_verified(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            firewall_marker = Path(tempdir) / "ipv6-firewall"
            marker.write_text("connection_uuid=vpn-uuid\n", encoding="utf-8")
            self.service.ipv6_leak_protection_enabled = True

            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.object(
                self.service,
                "_recovery_state_lock",
                return_value=nullcontext(),
            ), patch.object(
                self.service,
                "_run_recovery_command",
                return_value=False,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=True,
            ), patch.object(
                self.service,
                "_remove_owned_ipv6_firewall",
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
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.object(
                self.service,
                "_recovery_state_lock",
                return_value=nullcontext(),
            ), patch.object(
                self.service,
                "_run_recovery_command",
                return_value=False,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=False,
            ), patch.object(
                self.service,
                "_remove_owned_ipv6_firewall",
                return_value=True,
            ):
                self.service._remove_ipv6_leak_protection()

            self.assertFalse(marker.exists())
            self.assertFalse(self.service.ipv6_leak_protection_enabled)

    def test_ipv6_leak_cleanup_deletes_only_the_exact_owned_route(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            firewall_marker = Path(tempdir) / "ipv6-firewall"
            marker.write_text("owned\n", encoding="utf-8")
            commands = []
            self.service.ipv6_leak_protection_enabled = True
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                SERVICE_MODULE,
                "IPV6_FIREWALL_MARKER",
                firewall_marker,
            ), patch.object(
                self.service,
                "_recovery_state_lock",
                return_value=nullcontext(),
            ), patch.object(
                self.service,
                "_run_recovery_command",
                side_effect=lambda command: commands.append(command) or True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=False,
            ), patch.object(
                self.service,
                "_remove_owned_ipv6_firewall",
                return_value=True,
            ):
                self.service._remove_ipv6_leak_protection()

            self.assertEqual(commands, [[
                "ip", "-6", "route", "del", "unreachable", "::/0",
                "metric", "1", "proto", "99",
            ]])
            self.assertFalse(marker.exists())

    def test_ipv6_verifier_accepts_unreachable_public_targets(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            marker.touch()
            for route_error in (
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
            ):
                with self.subTest(route_error=route_error), patch.object(
                    SERVICE_MODULE,
                    "IPV6_LEAK_ROUTE_MARKER",
                    marker,
                ), patch.object(
                    self.service,
                    "_ipv6_leak_marker_matches_current",
                    return_value=True,
                ), patch.object(
                    self.service,
                    "_ipv6_leak_route_present",
                    return_value=True,
                ), patch.object(
                    self.service,
                    "_verify_ipv6_firewall",
                    return_value=True,
                ), patch.object(
                    self.service,
                    "_ipv6_route_probe_error",
                    return_value=route_error,
                ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
                    self.assertTrue(
                        self.service._verify_ipv6_leak_protection()
                    )
                    run.assert_not_called()

    def test_ipv6_verifier_preserves_wireguard_but_rejects_physical_route(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            marker.touch()
            route = SimpleNamespace(
                returncode=0,
                stdout="2606:4700:4700::1111 dev wg0 src fd00::1",
                stderr="",
            )
            common = (
                patch.object(SERVICE_MODULE, "IPV6_LEAK_ROUTE_MARKER", marker),
                patch.object(
                    self.service,
                    "_ipv6_leak_marker_matches_current",
                    return_value=True,
                ),
                patch.object(
                    self.service,
                    "_ipv6_leak_route_present",
                    return_value=True,
                ),
                patch.object(
                    self.service,
                    "_verify_ipv6_firewall",
                    return_value=True,
                ),
                patch.object(
                    self.service,
                    "_ipv6_route_probe_error",
                    return_value=0,
                ),
                patch.object(SERVICE_MODULE.subprocess, "run", return_value=route),
            )
            with common[0], common[1], common[2], common[3], common[4], common[5], patch.object(
                self.service,
                "_is_wireguard_device",
                return_value=True,
            ):
                self.assertTrue(self.service._verify_ipv6_leak_protection())

            route.stdout = "2606:4700:4700::1111 dev eth0 src 2001:db8::1"
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                self.service,
                "_ipv6_leak_marker_matches_current",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=True,
            ), patch.object(
                self.service,
                "_verify_ipv6_firewall",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_route_probe_error",
                return_value=0,
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                return_value=route,
            ), patch.object(
                self.service,
                "_is_wireguard_device",
                return_value=False,
            ):
                self.assertFalse(self.service._verify_ipv6_leak_protection())

    def test_ipv6_verifier_does_not_treat_generic_command_error_as_blocked(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            marker.touch()
            failed = SimpleNamespace(
                returncode=2,
                stdout="",
                stderr="Operation not permitted",
            )
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                self.service,
                "_ipv6_leak_marker_matches_current",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=True,
            ), patch.object(
                self.service,
                "_verify_ipv6_firewall",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_route_probe_error",
                return_value=0,
            ), patch.object(
                SERVICE_MODULE.subprocess,
                "run",
                return_value=failed,
            ):
                self.assertFalse(self.service._verify_ipv6_leak_protection())

    def test_ipv6_verifier_rejects_unexpected_kernel_route_error(self):
        with tempfile.TemporaryDirectory() as tempdir:
            marker = Path(tempdir) / "ipv6-leak-route"
            marker.touch()
            with patch.object(
                SERVICE_MODULE,
                "IPV6_LEAK_ROUTE_MARKER",
                marker,
            ), patch.object(
                self.service,
                "_ipv6_leak_marker_matches_current",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_leak_route_present",
                return_value=True,
            ), patch.object(
                self.service,
                "_verify_ipv6_firewall",
                return_value=True,
            ), patch.object(
                self.service,
                "_ipv6_route_probe_error",
                return_value=errno.EPERM,
            ), patch.object(SERVICE_MODULE.subprocess, "run") as run:
                self.assertFalse(self.service._verify_ipv6_leak_protection())
                run.assert_not_called()

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

    def test_in_activation_retry_cleanup_preserves_pinned_dns_policy(self):
        self.service.state = SERVICE_MODULE.NM_VPN_SERVICE_STATE_STARTING
        self.service.configured_dns_servers = ["10.0.0.53"]
        self.service.vpn_dns_backend = "networkmanager"
        self.service.dns_profile_policy_ready = True
        self.service.dns_activation_policy_ready = True
        self.service.vpn_dns_servers = ["10.0.0.53"]
        self.service.dns_leak_protection_ready = True
        self.service.vpn_domains = ["~."]
        self.service._remove_ipv6_leak_protection = lambda: None
        self.service._cleanup_leaked_vpn_dns_links = lambda: None

        self.assertTrue(self.service._cleanup_dns())

        self.assertEqual(self.service.configured_dns_servers, ["10.0.0.53"])
        self.assertEqual(self.service.vpn_dns_backend, "networkmanager")
        self.assertTrue(self.service.dns_profile_policy_ready)
        self.assertTrue(self.service.dns_activation_policy_ready)
        self.assertEqual(self.service.vpn_dns_servers, [])
        self.assertFalse(self.service.dns_leak_protection_ready)
        self.assertEqual(self.service.vpn_domains, [])

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

    def test_base_network_rejects_stale_gp_gateway_route(self):
        self.service.current_protocol = "gp"
        with patch.object(
            self.service,
            "_route_to_base_network_uses_uplink",
            return_value=True,
        ), patch.object(
            self.service,
            "_base_dns_operational",
            return_value=True,
        ), patch.object(
            self.service,
            "_physical_dns_route_restored",
            return_value=True,
        ), patch.object(
            self.service,
            "_gp_gateway_route_mismatch",
            return_value=True,
        ) as mismatch:
            ready = self.service._base_network_ready()

        self.assertFalse(ready)
        mismatch.assert_called_once_with("192.0.2.10")

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

    def test_recovery_reapplies_marked_uplinks_before_health_check(self):
        events = []
        self.service._uplinks_needing_reapply = {"eth0"}
        with patch.object(
            self.service,
            "_reapply_connected_uplinks",
            side_effect=lambda: events.append("reapply"),
        ) as reapply, patch.object(
            self.service,
            "_base_network_ready",
            side_effect=lambda: events.append("health") or True,
        ), patch.object(
            self.service,
            "_reload_networkmanager_dns",
        ) as reload_dns:
            result = self.service._recover_base_network_once(reactivate=True)

        self.assertTrue(result)
        self.assertEqual(events, ["reapply", "health"])
        reapply.assert_called_once_with()
        reload_dns.assert_not_called()

    def test_schedule_post_disconnect_recovery_marks_current_uplinks(self):
        self.service._uplinks_needing_reapply = set()
        with patch.object(
            self.service,
            "_list_connected_uplinks",
            return_value={
                "eth0": "wired-uuid",
                "wlan0": "wifi-uuid",
            },
        ), patch.object(
            SERVICE_MODULE.time,
            "monotonic",
            return_value=100.0,
        ), patch.object(
            SERVICE_MODULE.GLib,
            "timeout_add",
        ) as timeout_add:
            self.service._schedule_post_disconnect_recovery()

        self.assertEqual(
            self.service._uplinks_needing_reapply,
            {"eth0", "wlan0"},
        )
        self.assertEqual(self.service._network_recovery_token, 5)
        self.assertEqual(
            self.service._network_recovery_deadline,
            100.0 + SERVICE_MODULE.NETWORK_RECOVERY_TIMEOUT_SECONDS,
        )
        timeout_add.assert_called_once()
        delay, callback, token = timeout_add.call_args.args
        self.assertEqual(delay, SERVICE_MODULE.NETWORK_RECOVERY_INITIAL_DELAY_MS)
        self.assertEqual(callback, self.service._post_disconnect_recovery_tick)
        self.assertEqual(token, 5)

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

    def test_new_recovery_timer_retries_while_old_worker_unwinds(self):
        old_worker = SimpleNamespace(is_alive=lambda: True)
        self.service._network_recovery_token = 10
        self.service._network_recovery_thread = old_worker

        with patch.object(SERVICE_MODULE.threading, "Thread") as thread:
            result = self.service._post_disconnect_recovery_tick(10)

        self.assertTrue(result)
        thread.assert_not_called()
        self.assertIs(self.service._network_recovery_thread, old_worker)

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
