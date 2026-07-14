#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _shell_array(script: str, name: str) -> set[str]:
    match = re.search(
        rf"^{re.escape(name)}=\(\s*$(.*?)^\)\s*$",
        script,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"Could not find shell array {name}")

    entries = set()
    for raw_line in match.group(1).splitlines():
        value = raw_line.split("#", 1)[0].strip().strip("'\"")
        if value:
            entries.add(value)
    return entries


def _binary_package_dependencies(control: str, package: str) -> set[str]:
    package_match = re.search(
        rf"^Package:\s*{re.escape(package)}\s*$(.*?)(?:\n\s*\n|\Z)",
        control,
        flags=re.MULTILINE | re.DOTALL,
    )
    if package_match is None:
        raise AssertionError(f"Could not find Debian binary package {package}")

    depends_match = re.search(
        r"^Depends:\s*(.*(?:\n[ \t]+.*)*)",
        package_match.group(1),
        flags=re.MULTILINE,
    )
    if depends_match is None:
        raise AssertionError(f"Could not find Depends for {package}")

    dependencies = set()
    for expression in depends_match.group(1).replace("\n", " ").split(","):
        expression = expression.strip()
        if not expression or expression.startswith("${"):
            continue
        # The local preflight checks the concrete package name; Debian version
        # constraints remain authoritative in control.
        name = re.sub(r"\s*\([^)]*\)\s*$", "", expression).strip()
        dependencies.add(name)
    return dependencies


class DebianDependencyConsistencyTests(unittest.TestCase):
    def test_runtime_preflight_matches_binary_package_dependencies(self):
        preflight = _shell_array(
            _read("build-deb.sh"),
            "RUNTIME_DEPENDENCIES",
        )
        declared = _binary_package_dependencies(
            _read("packaging/debian/control"),
            "network-manager-ms-sso",
        )

        self.assertEqual(
            declared,
            preflight,
            "build-deb.sh runtime checks must match packaging/debian/control",
        )

    def test_totp_has_no_obsolete_external_runtime_dependency(self):
        dependency_metadata = "\n".join([
            _read("build-deb.sh"),
            _read("packaging/debian/control"),
        ])

        self.assertNotIn("python3-pyotp", dependency_metadata)
        self.assertTrue((REPO_ROOT / "src/python/core/totp.py").is_file())
        self.assertIn("from .totp import", _read("src/python/core/auth.py"))

    def test_openconnect_minimum_version_is_consistent_across_packages(self):
        build_script = _read("build-deb.sh")
        minimum_match = re.search(
            r'^MIN_OPENCONNECT_VERSION="([0-9]+\.[0-9]+)"$',
            build_script,
            flags=re.MULTILINE,
        )
        self.assertIsNotNone(minimum_match)
        minimum = minimum_match.group(1)

        self.assertIn(
            f"openconnect (>= {minimum})",
            _read("packaging/debian/control"),
        )
        self.assertIn(
            'dpkg --compare-versions "$installed_version" ge "$minimum_version"',
            build_script,
        )
        self.assertIn(
            'check_minimum_package_version "openconnect" '
            '"$MIN_OPENCONNECT_VERSION"',
            build_script,
        )
        self.assertIn(
            f"'openconnect>={minimum}'",
            _read("packaging/arch/PKGBUILD"),
        )
        self.assertIn(
            f"depends = openconnect>={minimum}",
            _read("packaging/arch/.SRCINFO"),
        )
        self.assertIn(
            f'lib.versionAtLeast openconnect.version "{minimum}"',
            _read("nix/networkmanager-ms-sso.nix"),
        )


if __name__ == "__main__":
    unittest.main()
