/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <glib.h>

#include "nm-ms-sso-timeout-policy.h"

static void
test_anyconnect_timeout_floor(void)
{
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(TRUE, 0), ==, 360);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(TRUE, 180), ==, 360);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(TRUE, 359), ==, 360);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(TRUE, 360), ==, 360);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(TRUE, 600), ==, 600);
}

static void
test_globalprotect_timeout_unchanged(void)
{
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(FALSE, 0), ==, 300);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(FALSE, 180), ==, 180);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(FALSE, 300), ==, 300);
    g_assert_cmpuint(ms_sso_vpn_activation_timeout(FALSE, 600), ==, 600);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/timeout-policy/anyconnect-floor",
                    test_anyconnect_timeout_floor);
    g_test_add_func("/timeout-policy/globalprotect-unchanged",
                    test_globalprotect_timeout_unchanged);

    return g_test_run();
}
