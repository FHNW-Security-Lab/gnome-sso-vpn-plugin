/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "nm-ms-sso-timeout-policy.h"

guint
ms_sso_vpn_activation_timeout(gboolean is_anyconnect, guint current_timeout)
{
    if (is_anyconnect && current_timeout < MS_SSO_MIN_ANYCONNECT_TIMEOUT)
        return MS_SSO_MIN_ANYCONNECT_TIMEOUT;

    if (!is_anyconnect && current_timeout == 0)
        return MS_SSO_DEFAULT_GP_TIMEOUT;

    return current_timeout;
}
