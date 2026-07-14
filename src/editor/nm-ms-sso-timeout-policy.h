/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef NM_MS_SSO_TIMEOUT_POLICY_H
#define NM_MS_SSO_TIMEOUT_POLICY_H

#include <glib.h>

#define MS_SSO_MIN_ANYCONNECT_TIMEOUT 360U
#define MS_SSO_DEFAULT_GP_TIMEOUT     300U

guint ms_sso_vpn_activation_timeout(gboolean is_anyconnect,
                                    guint current_timeout);

#endif /* NM_MS_SSO_TIMEOUT_POLICY_H */
