#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SEMVER = r"[0-9]+\.[0-9]+\.[0-9]+"


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _required_match(pattern: str, text: str, source: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if match is None:
        raise AssertionError(f"Could not find release version in {source}")
    return match.group(1)


class ReleaseMetadataConsistencyTests(unittest.TestCase):
    def test_all_package_formats_use_the_meson_release_version(self):
        meson_version = _required_match(
            rf"^\s*version:\s*'({SEMVER})',\s*$",
            _read("meson.build"),
            "meson.build",
        )

        versions = {
            "Makefile": _required_match(
                rf"^VERSION\s*\?=\s*({SEMVER})\s*$",
                _read("Makefile"),
                "Makefile",
            ),
            "build-deb.sh": _required_match(
                rf'^VERSION="({SEMVER})"\s*$',
                _read("build-deb.sh"),
                "build-deb.sh",
            ),
            "Debian changelog": _required_match(
                rf"^network-manager-ms-sso \(({SEMVER})-[^)]+\)",
                _read("packaging/debian/changelog"),
                "packaging/debian/changelog",
            ),
            "Arch PKGBUILD": _required_match(
                rf"^pkgver=({SEMVER})(?:\.|$)",
                _read("packaging/arch/PKGBUILD"),
                "packaging/arch/PKGBUILD",
            ),
            "Arch .SRCINFO": _required_match(
                rf"^\s*pkgver\s*=\s*({SEMVER})(?:\.|$)",
                _read("packaging/arch/.SRCINFO"),
                "packaging/arch/.SRCINFO",
            ),
            "Nix core": _required_match(
                rf'^\s*version\s*=\s*"({SEMVER})";\s*$',
                _read("nix/ms-sso-openconnect-core.nix"),
                "nix/ms-sso-openconnect-core.nix",
            ),
            "Nix application": _required_match(
                rf'^\s*version\s*=\s*"({SEMVER})";\s*$',
                _read("nix/networkmanager-ms-sso.nix"),
                "nix/networkmanager-ms-sso.nix",
            ),
        }

        self.assertEqual(
            {meson_version},
            set(versions.values()),
            f"Release metadata diverges: meson={meson_version}, others={versions}",
        )

    def test_readme_install_example_names_the_current_debian_package(self):
        version = _required_match(
            rf"^\s*version:\s*'({SEMVER})',\s*$",
            _read("meson.build"),
            "meson.build",
        )

        self.assertIn(
            f"network-manager-ms-sso_{version}-1_amd64.deb",
            _read("README.md"),
        )

    def test_arch_dynamic_pkgver_is_derived_from_meson_and_git(self):
        pkgbuild = _read("packaging/arch/PKGBUILD")
        srcinfo = _read("packaging/arch/.SRCINFO")

        self.assertIn("sed -n \"s/^  version:", pkgbuild)
        self.assertIn("git rev-list --count HEAD", pkgbuild)
        self.assertIn("git rev-parse --short HEAD", pkgbuild)
        self.assertIn(
            "printf '%s.r%s.g%s\\n' \"${version}\" \"${rev}\" \"${short}\"",
            pkgbuild,
        )
        pkgver = _required_match(r"^pkgver=(\S+)$", pkgbuild, "PKGBUILD")
        srcinfo_pkgver = _required_match(
            r"^\s*pkgver\s*=\s*(\S+)\s*$",
            srcinfo,
            ".SRCINFO",
        )
        self.assertEqual(pkgver, srcinfo_pkgver)


if __name__ == "__main__":
    unittest.main()
