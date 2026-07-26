#!/usr/bin/env python3

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HELPER = REPO_ROOT / "src" / "nm-ms-sso-migrate-dns-policy"


class DnsPolicyMigrationRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.bin_dir = Path(self.tempdir.name) / "bin"
        self.bin_dir.mkdir()
        self.call_log = Path(self.tempdir.name) / "nmcli.calls"
        self.nmcli = self.bin_dir / "nmcli"
        self.nmcli.write_text(
            """#!/bin/sh
printf '%s\\n' "$*" >> "$NMCLI_CALL_LOG"

if [ "${1:-}" = "--terse" ]; then
    [ "${FAKE_LIST_FAILURE:-0}" = "1" ] && exit 41
    printf '%s\\n' \\
        'ms-missing-root:vpn' \\
        'ms-has-root:vpn' \\
        'foreign-vpn:vpn' \\
        'wired-profile:ethernet'
    exit 0
fi

if [ "${1:-}" = "--get-values" ]; then
    property="${2:-}"
    uuid="${6:-}"
    case "$property:$uuid" in
        vpn.service-type:ms-missing-root|vpn.service-type:ms-has-root)
            printf '%s\\n' 'org.freedesktop.NetworkManager.ms-sso'
            ;;
        vpn.service-type:foreign-vpn)
            printf '%s\\n' 'org.freedesktop.NetworkManager.openvpn'
            ;;
        ipv4.dns-search:ms-missing-root)
            if [ -n "${FAKE_DNS_STATE:-}" ] \\
                && [ -e "$FAKE_DNS_STATE" ]; then
                printf '%s\\n' 'corp.example,~.'
            else
                printf '%s\\n' 'corp.example'
            fi
            ;;
        ipv4.dns-search:ms-has-root)
            # Exercise both separators accepted by nmcli output. An existing
            # root route must prevent the helper from appending another one.
            printf '%s\\n' 'corp.example;~.,internal.example'
            ;;
        *)
            exit 42
            ;;
    esac
    exit 0
fi

if [ "${1:-}" = "connection" ] && [ "${2:-}" = "modify" ]; then
    [ "${FAKE_FAIL_MODIFY_UUID:-}" = "${4:-}" ] && exit 43
    if [ "${4:-}" = "ms-missing-root" ] \\
        && [ -n "${FAKE_DNS_STATE:-}" ]; then
        : > "$FAKE_DNS_STATE"
    fi
    exit 0
fi

exit 44
""",
            encoding="utf-8",
        )
        self.nmcli.chmod(0o755)

    def _run(self, **environment):
        self.call_log.unlink(missing_ok=True)
        env = os.environ.copy()
        env.update({
            "PATH": f"{self.bin_dir}:/usr/bin:/bin",
            "NMCLI_CALL_LOG": str(self.call_log),
        })
        env.update(environment)
        return subprocess.run(
            ["/bin/sh", str(HELPER)],
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

    def test_only_ms_sso_vpns_receive_complete_exclusive_dns_policy(self):
        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self._calls()
        modifications = [
            call for call in calls if call.startswith("connection modify uuid ")
        ]
        self.assertEqual(len(modifications), 2, calls)
        self.assertTrue(any(
            call.startswith("connection modify uuid ms-missing-root ")
            for call in modifications
        ))
        self.assertTrue(any(
            call.startswith("connection modify uuid ms-has-root ")
            for call in modifications
        ))
        self.assertFalse(any("foreign-vpn" in call for call in modifications))
        self.assertFalse(any("wired-profile" in call for call in modifications))

        for call in modifications:
            self.assertIn("ipv4.dns-priority -100", call)
            self.assertIn("ipv4.ignore-auto-dns no", call)
            self.assertIn("ipv6.dns-priority -100", call)

        missing_root = next(
            call for call in modifications if "uuid ms-missing-root " in call
        )
        existing_root = next(
            call for call in modifications if "uuid ms-has-root " in call
        )
        self.assertIn("+ipv4.dns-search ~.", missing_root)
        self.assertEqual(missing_root.split().count("~."), 1)
        self.assertNotIn("+ipv4.dns-search", existing_root)
        self.assertNotIn("~.", existing_root)

        self.assertFalse(any(
            "vpn.service-type" in call and "wired-profile" in call
            for call in calls
        ))

    def test_missing_nmcli_is_a_successful_noop(self):
        self.nmcli.unlink()

        # Deliberately exclude the host's real nmcli: this test must be a
        # no-op even on developer workstations with live NM connections.
        result = self._run(PATH=str(self.bin_dir))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._calls(), [])

    def test_second_run_does_not_append_a_duplicate_root_route(self):
        dns_state = Path(self.tempdir.name) / "dns-state"

        first = self._run(FAKE_DNS_STATE=str(dns_state))
        first_modification = next(
            call for call in self._calls()
            if call.startswith("connection modify uuid ms-missing-root ")
        )
        second = self._run(FAKE_DNS_STATE=str(dns_state))
        second_modification = next(
            call for call in self._calls()
            if call.startswith("connection modify uuid ms-missing-root ")
        )

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_modification.split().count("~."), 1)
        self.assertNotIn("+ipv4.dns-search", second_modification)
        self.assertNotIn("~.", second_modification)

    def test_connection_listing_failure_is_a_successful_noop(self):
        result = self._run(FAKE_LIST_FAILURE="1")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._calls(),
            ["--terse --escape no --fields UUID,TYPE connection show"],
        )

    def test_modify_failure_warns_and_does_not_block_other_profiles(self):
        result = self._run(FAKE_FAIL_MODIFY_UUID="ms-missing-root")

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "could not update DNS policy for MS SSO VPN ms-missing-root",
            result.stderr,
        )
        self.assertIn(
            "Updated exclusive DNS policy for MS SSO VPN ms-has-root",
            result.stdout,
        )
        modifications = [
            call for call in self._calls()
            if call.startswith("connection modify uuid ")
        ]
        self.assertEqual(len(modifications), 2)


class DnsPolicyMigrationPackagingTests(unittest.TestCase):
    def test_meson_installs_executable_helper_in_libexec(self):
        meson = (REPO_ROOT / "meson.build").read_text(encoding="utf-8")
        start = meson.index(
            "install_data('src/nm-ms-sso-migrate-dns-policy'"
        )
        block = meson[start:meson.index("\n)\n", start) + 3]

        self.assertIn("rename: 'nm-ms-sso-migrate-dns-policy'", block)
        self.assertIn("install_dir: libexecdir", block)
        self.assertIn("install_mode: 'rwxr-xr-x'", block)

    def test_debian_postinst_migrates_before_networkmanager_reload(self):
        postinst = (
            REPO_ROOT / "packaging" / "debian" / "postinst"
        ).read_text(encoding="utf-8")
        migration = "/usr/libexec/nm-ms-sso-migrate-dns-policy || true"
        restart = "systemctl restart NetworkManager"

        self.assertEqual(postinst.count(migration), 1)
        self.assertIn(restart, postinst)
        self.assertLess(postinst.index(migration), postinst.index(restart))

    def test_arch_install_hook_migrates_before_networkmanager_reload(self):
        install_hook = (
            REPO_ROOT
            / "packaging"
            / "arch"
            / "networkmanager-ms-sso-git.install"
        ).read_text(encoding="utf-8")
        start = install_hook.index("post_install() {")
        end = install_hook.index("\n}", start)
        post_install = install_hook[start:end]
        migration = "/usr/libexec/nm-ms-sso-migrate-dns-policy || true"
        reload_call = "_reload_networkmanager_plugin"

        self.assertEqual(post_install.count(migration), 1)
        self.assertLess(
            post_install.index(migration),
            post_install.index(reload_call),
        )
        self.assertIn("post_upgrade()", install_hook)
        self.assertIn("post_install", install_hook[install_hook.index("post_upgrade()") :])

    def test_nixos_runs_migration_as_boot_oneshot_after_nm_is_available(self):
        module = (
            REPO_ROOT / "nix" / "nixos-module.nix"
        ).read_text(encoding="utf-8")
        start = module.index("systemd.services.nm-ms-sso-dns-policy")
        end = module.index(
            "networking.networkmanager.dispatcherScripts",
            start,
        )
        service = module[start:end]

        self.assertIn('wantedBy = [ "multi-user.target" ]', service)
        self.assertIn('wants = [ "NetworkManager.service" ]', service)
        self.assertIn('after = [ "NetworkManager.service" ]', service)
        self.assertIn('serviceConfig.Type = "oneshot"', service)
        self.assertIn(
            "${pkgs.networkmanager-ms-sso}/libexec/"
            "nm-ms-sso-migrate-dns-policy",
            service,
        )


if __name__ == "__main__":
    unittest.main()
