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

    def test_recovery_lock_is_acquired_after_service_type_validation(self):
        helper = (
            REPO_ROOT / "src" / "nm-ms-sso-recover-network"
        ).read_text()

        validation = (
            '[ "$service_type" = '
            '"org.freedesktop.NetworkManager.ms-sso" ] || exit 0'
        )
        lock = 'flock -x 9'
        self.assertIn('/run/network-manager-ms-sso/recovery.lock', helper)
        self.assertIn(validation, helper)
        self.assertIn(lock, helper)
        self.assertLess(helper.index(validation), helper.index(lock))

    def test_dispatcher_verifies_ipv6_route_absence_before_removing_marker(self):
        helper = (
            REPO_ROOT / "src" / "nm-ms-sso-recover-network"
        ).read_text()

        delete_route = (
            "ip -6 route del unreachable ::/0 metric 1 proto 99"
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

    def test_recovery_only_mutates_owned_ipv6_default_signature(self):
        helper = (
            REPO_ROOT / "src" / "nm-ms-sso-recover-network"
        ).read_text()

        self.assertIn(
            "ip -6 route del unreachable ::/0 metric 1 proto 99",
            helper,
        )
        self.assertNotIn("ip -6 route replace", helper)
        self.assertNotIn("ip -6 route flush table", helper)

    def test_recovery_verifies_owned_nft_table_absence_before_marker_removal(self):
        helper = (
            REPO_ROOT / "src" / "nm-ms-sso-recover-network"
        ).read_text()

        delete_table = "nft delete table inet nm_ms_sso_ipv6"
        inspect_tables = "nft list tables"
        remove_marker = 'rm -f -- "$ipv6_firewall_marker"'
        self.assertIn(delete_table, helper)
        self.assertIn(inspect_tables, helper)
        self.assertIn(remove_marker, helper)
        self.assertNotIn("nft flush ruleset", helper)
        self.assertLess(helper.index(delete_table), helper.index(inspect_tables))
        self.assertLess(helper.index(inspect_tables), helper.index(remove_marker))

    def test_historical_ipv6_route_signatures_are_migrated(self):
        service = (REPO_ROOT / "src" / "nm-ms-sso-service.py").read_text()

        self.assertIn('IPV6_LEAK_ROUTE_METRIC = "1"', service)
        self.assertIn('IPV6_LEAK_ROUTE_PROTOCOL = "99"', service)
        self.assertIn('("42760", "186")', service)
        self.assertIn('("50", None)', service)

    def test_arch_declares_iproute2_for_service_and_dispatcher(self):
        pkgbuild = (REPO_ROOT / "packaging" / "arch" / "PKGBUILD").read_text()
        srcinfo = (REPO_ROOT / "packaging" / "arch" / ".SRCINFO").read_text()

        self.assertIn("'iproute2'", pkgbuild)
        self.assertIn("depends = iproute2", srcinfo)

    def test_all_packages_declare_nftables_for_ipv6_kill_switch(self):
        build_deb = (REPO_ROOT / "build-deb.sh").read_text()
        debian = (REPO_ROOT / "packaging" / "debian" / "control").read_text()
        pkgbuild = (REPO_ROOT / "packaging" / "arch" / "PKGBUILD").read_text()
        srcinfo = (REPO_ROOT / "packaging" / "arch" / ".SRCINFO").read_text()
        nix_package = (REPO_ROOT / "nix" / "networkmanager-ms-sso.nix").read_text()
        nix_module = (REPO_ROOT / "nix" / "nixos-module.nix").read_text()

        self.assertIn("    nftables\n", build_deb)
        self.assertIn("         nftables,", debian)
        self.assertIn("'nftables'", pkgbuild)
        self.assertIn("depends = nftables", srcinfo)
        self.assertIn(", nftables", nix_package)
        self.assertGreaterEqual(nix_package.count("      nftables"), 2)
        self.assertIn("pkgs.nftables", nix_module)

    def test_runtime_tmpfiles_creates_crash_safe_state_directory(self):
        tmpfiles = (
            REPO_ROOT / "data" / "networkmanager-ms-sso.tmpfiles"
        ).read_text()
        meson = (REPO_ROOT / "meson.build").read_text()

        self.assertIn("d /run/network-manager-ms-sso 0755 root root -", tmpfiles)
        self.assertIn("data/networkmanager-ms-sso.tmpfiles", meson)
        self.assertIn("rename: ['networkmanager-ms-sso.conf']", meson)
        self.assertIn("'lib', 'tmpfiles.d'", meson)

    def test_nixos_recovery_dispatcher_is_unconditional(self):
        module = (REPO_ROOT / "nix" / "nixos-module.nix").read_text()

        assignment = module.index("networking.networkmanager.dispatcherScripts")
        nearby = module[max(0, assignment - 100):assignment + 250]
        self.assertNotIn("lib.optional cfg.autoCleanupDns", nearby)

    def test_editor_saves_exclusive_dns_priority(self):
        editor = (
            REPO_ROOT / "src" / "editor" / "nm-ms-sso-editor.c"
        ).read_text()

        self.assertIn("nm_connection_get_setting_ip4_config", editor)
        self.assertIn("nm_setting_ip4_config_new", editor)
        self.assertIn("nm_connection_get_setting_ip6_config", editor)
        self.assertGreaterEqual(
            editor.count("NM_SETTING_IP_CONFIG_DNS_PRIORITY"),
            2,
        )
        self.assertIn("-100", editor)
        self.assertIn('nm_setting_ip_config_add_dns_search(s_ip4, "~.")', editor)


class DispatcherFilteringTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.bin_dir = Path(self.tempdir.name) / "bin"
        self.bin_dir.mkdir()
        self.call_log = Path(self.tempdir.name) / "calls.log"
        self.recovery_lock = Path(self.tempdir.name) / "recovery.lock"
        self.state_file = Path(self.tempdir.name) / "openconnect.state"
        self.ipv6_marker = Path(self.tempdir.name) / "ipv6-leak-route"
        self.ipv6_firewall_marker = Path(self.tempdir.name) / "ipv6-firewall"
        self.helper_path = Path(self.tempdir.name) / "nm-ms-sso-recover-network"
        helper = (
            REPO_ROOT / "src" / "nm-ms-sso-recover-network"
        ).read_text(encoding="utf-8")
        for installed, temporary in (
            ("/run/network-manager-ms-sso/recovery.lock", self.recovery_lock),
            ("/run/network-manager-ms-sso/openconnect.state", self.state_file),
            ("/run/network-manager-ms-sso/ipv6-leak-route", self.ipv6_marker),
            (
                "/run/network-manager-ms-sso/ipv6-firewall",
                self.ipv6_firewall_marker,
            ),
        ):
            helper = helper.replace(installed, str(temporary))
        self.helper_path.write_text(helper, encoding="utf-8")
        self.helper_path.chmod(0o755)
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
    nft)
        case "$*" in
            "delete table inet nm_ms_sso_ipv6")
                exit "${FAKE_NFT_DELETE_STATUS:-0}"
                ;;
            "list tables")
                if [ "${FAKE_NFT_LIST_STATUS:-0}" -ne 0 ]; then
                    exit "${FAKE_NFT_LIST_STATUS}"
                fi
                if [ "${FAKE_NFT_TABLE_PRESENT:-0}" = "1" ]; then
                    printf '%s\\n' 'table inet nm_ms_sso_ipv6'
                fi
                ;;
        esac
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
            "nft",
            "flock",
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
            nft_table_present=False,
            nft_list_status=0,
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
            "FAKE_NFT_TABLE_PRESENT": "1" if nft_table_present else "0",
            "FAKE_NFT_LIST_STATUS": str(nft_list_status),
        })
        return subprocess.run(
            [
                "/bin/sh",
                str(self.helper_path),
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

    def _write_firewall_marker(self, connection_uuid="vpn-uuid", *, extra=""):
        self.ipv6_firewall_marker.write_text(
            "version=1\n"
            f"connection_uuid={connection_uuid}\n"
            "family=inet\n"
            "table=nm_ms_sso_ipv6\n"
            f"{extra}",
            encoding="utf-8",
        )

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

    def test_dispatcher_reapplies_uplinks_before_accepting_base_route(self):
        result = self._run_dispatcher()

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        reapply_index = calls.index("nmcli device reapply eth0")
        first_route_check = next(
            index
            for index, command in enumerate(calls)
            if command.startswith("ip -4 route get 1.1.1.1")
        )
        self.assertLess(reapply_index, first_route_check)

    def test_queued_old_event_cannot_mutate_a_new_ms_sso_activation(self):
        self._write_firewall_marker()
        result = self._run_dispatcher(active_ms_sso=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertFalse(any(call.startswith((
            "ip ",
            "resolvectl ",
            "resolvconf ",
            "nft ",
            "rm ",
        )) for call in calls))

    def test_valid_firewall_marker_removes_only_owned_nft_table(self):
        self._write_firewall_marker()

        result = self._run_dispatcher()

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertIn("nft delete table inet nm_ms_sso_ipv6", calls)
        self.assertIn("nft list tables", calls)
        self.assertIn(
            f"rm -f -- {self.ipv6_firewall_marker}",
            calls,
        )

    def test_unscoped_firewall_marker_is_owned_by_dispatcher(self):
        self._write_firewall_marker(connection_uuid="")

        result = self._run_dispatcher()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "nft delete table inet nm_ms_sso_ipv6",
            self._calls(),
        )

    def test_foreign_firewall_marker_is_preserved(self):
        self._write_firewall_marker(connection_uuid="other-vpn-uuid")

        result = self._run_dispatcher()

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertFalse(any(call.startswith("nft ") for call in calls))
        self.assertFalse(any(
            call == f"rm -f -- {self.ipv6_firewall_marker}"
            for call in calls
        ))
        self.assertTrue(any(
            "belongs to another VPN activation" in call
            for call in calls
        ))

    def test_invalid_firewall_marker_is_preserved(self):
        self._write_firewall_marker(extra="unexpected=true\n")

        result = self._run_dispatcher()

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertFalse(any(call.startswith("nft ") for call in calls))
        self.assertTrue(any(
            "invalid IPv6 firewall marker" in call
            for call in calls
        ))

    def test_firewall_marker_is_preserved_when_table_still_exists(self):
        self._write_firewall_marker()

        result = self._run_dispatcher(nft_table_present=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertIn("nft delete table inet nm_ms_sso_ipv6", calls)
        self.assertIn("nft list tables", calls)
        self.assertFalse(any(
            call == f"rm -f -- {self.ipv6_firewall_marker}"
            for call in calls
        ))
        self.assertTrue(any(
            "firewall table still exists" in call
            for call in calls
        ))

    def test_firewall_marker_is_preserved_when_verification_fails(self):
        self._write_firewall_marker()

        result = self._run_dispatcher(nft_list_status=1)

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        self.assertFalse(any(
            call == f"rm -f -- {self.ipv6_firewall_marker}"
            for call in calls
        ))
        self.assertTrue(any(
            "could not verify IPv6 firewall removal" in call
            for call in calls
        ))


if __name__ == "__main__":
    unittest.main()
