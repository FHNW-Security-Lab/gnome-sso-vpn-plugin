#!/usr/bin/env python3

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src" / "python"))

from core.platform_info import DEFAULT_GP_OS_VERSION, get_gp_os_version  # noqa: E402


class GlobalProtectOsVersionTests(unittest.TestCase):
    @patch("core.platform_info._detect_os_version", return_value="Arch Linux")
    def test_empty_setting_detects_the_host_distribution(self, _detect):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MS_SSO_GP_OS_VERSION", None)
            self.assertEqual(get_gp_os_version(), "Arch Linux")

    @patch("core.platform_info._detect_os_version", return_value="NixOS 26.05")
    def test_auto_setting_detects_the_host_distribution(self, _detect):
        with patch.dict(os.environ, {"MS_SSO_GP_OS_VERSION": "auto"}):
            self.assertEqual(get_gp_os_version(), "NixOS 26.05")

    @patch("core.platform_info._detect_os_version")
    def test_explicit_compatibility_override_wins(self, detect):
        with patch.dict(
            os.environ,
            {"MS_SSO_GP_OS_VERSION": "Ubuntu 24.04 LTS"},
        ):
            self.assertEqual(get_gp_os_version(), "Ubuntu 24.04 LTS")
        detect.assert_not_called()

    @patch("core.platform_info._detect_os_version", return_value=None)
    def test_detection_failure_uses_safe_fallback(self, _detect):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MS_SSO_GP_OS_VERSION", None)
            self.assertEqual(get_gp_os_version(), DEFAULT_GP_OS_VERSION)


if __name__ == "__main__":
    unittest.main()
