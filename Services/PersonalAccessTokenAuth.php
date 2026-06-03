<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Services;

/**
 * Main plugin service.
 *
 * Leantime resolves a service class named after the plugin folder
 * (Leantime\Plugins\PersonalAccessTokenAuth\Services\PersonalAccessTokenAuth)
 * and calls install()/uninstall() when the plugin is installed/removed.
 *
 * This plugin stores tokens in Leantime's core `zp_access_tokens` table, so
 * there is nothing to create or drop here. The actual authentication wiring
 * lives in register.php (event listener) and BearerTokenAuthenticator.
 */
class PersonalAccessTokenAuth
{
    public function install(): void
    {
        // No-op: reuses Leantime core's zp_access_tokens table.
    }

    public function uninstall(): void
    {
        // No-op: nothing plugin-specific to remove.
    }
}
