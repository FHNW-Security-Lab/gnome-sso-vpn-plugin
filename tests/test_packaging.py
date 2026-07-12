#!/usr/bin/env python3

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class DebianPackagingTests(unittest.TestCase):
    def test_postinst_stops_stale_helper_before_networkmanager_restart(self):
        postinst = (REPO_ROOT / "packaging" / "debian" / "postinst").read_text()

        stop_helper = "pkill -TERM -f /usr/libexec/nm-ms-sso-service"
        force_stop_helper = "pkill -KILL -f /usr/libexec/nm-ms-sso-service"
        restart_networkmanager = "systemctl restart NetworkManager"
        self.assertIn(stop_helper, postinst)
        self.assertIn(force_stop_helper, postinst)
        self.assertIn(restart_networkmanager, postinst)
        self.assertLess(
            postinst.index(stop_helper),
            postinst.index(restart_networkmanager),
        )
        self.assertLess(
            postinst.index(force_stop_helper),
            postinst.index(restart_networkmanager),
        )

    def test_recovery_helper_is_installed_as_libexec_and_dispatcher(self):
        meson = (REPO_ROOT / "meson.build").read_text()

        self.assertIn("src/nm-ms-sso-recover-network", meson)
        self.assertIn("rename: 'nm-ms-sso-recover-network'", meson)
        self.assertIn("rename: '90-nm-ms-sso-recover-network'", meson)
        self.assertIn("'NetworkManager', 'dispatcher.d'", meson)
        self.assertGreaterEqual(meson.count("install_mode: 'rwxr-xr-x'"), 2)

    def test_nixos_dispatcher_delegates_to_packaged_recovery_helper(self):
        module = (REPO_ROOT / "nix" / "nixos-module.nix").read_text()

        self.assertIn(
            "${pkgs.networkmanager-ms-sso}/libexec/nm-ms-sso-recover-network",
            module,
        )

    def test_dispatcher_verifies_ipv6_route_absence_before_removing_marker(self):
        helper = (
            REPO_ROOT / "src" / "nm-ms-sso-recover-network"
        ).read_text()

        delete_route = (
            "ip -6 route del unreachable ::/0 metric 42760 proto 186"
        )
        inspect_route = (
            "ip -6 route show table all type unreachable ::/0"
        )
        remove_marker = 'rm -f -- "$ipv6_marker"'
        self.assertIn(delete_route, helper)
        self.assertIn(inspect_route, helper)
        self.assertIn(remove_marker, helper)
        self.assertLess(helper.index(delete_route), helper.index(inspect_route))
        self.assertLess(helper.index(inspect_route), helper.index(remove_marker))


class DispatcherFilteringTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.bin_dir = Path(self.tempdir.name) / "bin"
        self.bin_dir.mkdir()
        self.call_log = Path(self.tempdir.name) / "calls.log"
        fake_command = self.bin_dir / "fake-command"
        fake_command.write_text(
            """#!/bin/sh
tool="${0##*/}"
printf '%s %s\\n' "$tool" "$*" >> "$CALL_LOG"
case "$tool" in
    nmcli)
        if [ "${1:-}" = "--get-values" ] && [ "${2:-}" = "vpn.service-type" ]; then
            printf '%s\\n' "${FAKE_SERVICE_TYPE:-org.freedesktop.NetworkManager.ms-sso}"
        elif [ "${1:-}" = "--get-values" ] && [ "${2:-}" = "vpn.data" ]; then
            printf '%s\\n' 'gateway=vpn.example.edu,protocol=anyconnect'
        elif [ "${1:-}" = "--terse" ]; then
            case "$*" in
                *UUID,TYPE*)
                    [ "${FAKE_ACTIVE_MS_SSO:-0}" = "1" ] \\
                        && printf '%s\\n' 'active-vpn-uuid:vpn'
                    ;;
                *) printf '%s\\n' 'eth0:ethernet:connected:uplink-uuid' ;;
            esac
        fi
        ;;
    ip)
        if [ "${1:-}" = "-4" ] && [ "${2:-}" = "route" ] && [ "${3:-}" = "get" ]; then
            printf '%s\\n' '1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.20'
        fi
        ;;
    getent)
        printf '%s\\n' '192.0.2.10 STREAM vpn.example.edu'
        exit "${FAKE_DNS_STATUS:-0}"
        ;;
esac
exit 0
""",
            encoding="utf-8",
        )
        fake_command.chmod(0o755)
        for command in (
            "nmcli",
            "ip",
            "getent",
            "resolvectl",
            "resolvconf",
            "logger",
            "sleep",
            "rm",
        ):
            (self.bin_dir / command).symlink_to(fake_command)

    def _run_dispatcher(
            self,
            action="vpn-down",
            service_type="org.freedesktop.NetworkManager.ms-sso",
            vpn_iface="tun42",
            connection_uuid="vpn-uuid",
            active_ms_sso=False,
    ):
        self.call_log.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update({
            "PATH": f"{self.bin_dir}:/usr/bin:/bin",
            "CALL_LOG": str(self.call_log),
            "CONNECTION_UUID": connection_uuid,
            "VPN_IP_IFACE": vpn_iface,
            "FAKE_SERVICE_TYPE": service_type,
            "FAKE_ACTIVE_MS_SSO": "1" if active_ms_sso else "0",
        })
        return subprocess.run(
            [
                "/bin/sh",
                str(REPO_ROOT / "src" / "nm-ms-sso-recover-network"),
                vpn_iface,
                action,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env=env,
        )

    def _calls(self):
        if not self.call_log.exists():
            return []
        return self.call_log.read_text(encoding="utf-8").splitlines()

    def test_non_vpn_down_event_is_ignored_before_any_command(self):
        result = self._run_dispatcher(action="up")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._calls(), [])

    def test_event_without_connection_uuid_is_ignored(self):
        result = self._run_dispatcher(connection_uuid="")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._calls(), [])

    def test_foreign_vpn_service_is_filtered_before_network_mutation(self):
        result = self._run_dispatcher(
            service_type="org.freedesktop.NetworkManager.openvpn",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].startswith("nmcli --get-values vpn.service-type"))
        self.assertFalse(any(call.startswith(("ip ", "resolvectl ", "resolvconf ")) for call in calls))

    def test_dispatcher_never_reverts_an_unowned_interface_name(self):
        result = self._run_dispatcher(vpn_iface="eth0")

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertNotIn("resolvectl revert eth0", calls)
        self.assertIn("resolvectl flush-caches", calls)

        result = self._run_dispatcher(vpn_iface="tun42")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("resolvectl revert tun42", self._calls())
        self.assertIn("resolvectl flush-caches", self._calls())

    def test_queued_old_event_cannot_mutate_a_new_ms_sso_activation(self):
        result = self._run_dispatcher(active_ms_sso=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertFalse(any(call.startswith((
            "ip ",
            "resolvectl ",
            "resolvconf ",
            "rm ",
        )) for call in calls))


if __name__ == "__main__":
    unittest.main()
