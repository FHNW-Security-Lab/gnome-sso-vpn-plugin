#!/usr/bin/env python3

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


class DebianPackagingTests(unittest.TestCase):
    def test_postinst_stops_stale_helper_before_networkmanager_restart(self):
        postinst = (REPO_ROOT / "packaging" / "debian" / "postinst").read_text()

        stop_helper = "pkill -f /usr/libexec/nm-ms-sso-service"
        restart_networkmanager = "systemctl restart NetworkManager"
        self.assertIn(stop_helper, postinst)
        self.assertIn(restart_networkmanager, postinst)
        self.assertLess(
            postinst.index(stop_helper),
            postinst.index(restart_networkmanager),
        )


if __name__ == "__main__":
    unittest.main()
