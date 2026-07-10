#!/usr/bin/env python3

import importlib.util
import logging.handlers
import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
