<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Services;

use Leantime\Domain\Auth\Models\Roles;
use Leantime\Domain\Auth\Repositories\AccessTokenRepository;
use Leantime\Domain\Setting\Repositories\Setting;

/**
 * Single source of truth for "who may issue a Personal Access Token" and the
 * revocation that follows when someone may not.
 *
 * Two modes:
 *
 *  - **OIDC-connect mode** (env flag OIDC_PAT_ISSUE_INTEGRATION is on AND the
 *    AdvancedOidc plugin is present): issuance is gated SOLELY on the IdP
 *    entitlement the AdvancedOidc plugin computes at login and leaves in the
 *    session (`advancedOidc.patIssueAllowed`). The Leantime role is ignored.
 *  - **Standard mode** (default / flag off / AdvancedOidc absent): issuance is
 *    gated on the Leantime role — the user's role must rank at least as high as
 *    the admin-selected minimum.
 *
 * The on/off switch lives in env (ops-controlled, applied on container
 * recreate) rather than a DB setting, so it cannot be toggled off by accident
 * from the admin UI. Only the standard-mode minimum role is admin-editable.
 *
 * Whenever a user is found NOT entitled, their existing tokens are revoked
 * (fail-closed): at login via {@see enforceAtLogin()} (called by AdvancedOidc),
 * and defensively when they open the account-settings page via
 * {@see enforceForCurrentUser()} (called by TokenTab). Revocation goes straight
 * through the repository so it does not depend on the session being the user.
 */
class IssuancePolicy
{
    /** zp_settings key for the only admin-configurable knob (standard mode). */
    public const SETTING_MIN_ROLE = 'personalAccessTokenAuth.minRole';

    /** Env flag that switches OIDC-integration gating on (ops-controlled). */
    public const ENV_OIDC_INTEGRATION = 'OIDC_PAT_ISSUE_INTEGRATION';

    /** Session key written by AdvancedOidc at login (contract; advancedOidc.*). */
    public const SESSION_KEY = 'advancedOidc.patIssueAllowed';

    /** AdvancedOidc service class — its presence means OIDC-connect is possible. */
    private const OIDC_SERVICE = 'Leantime\\Plugins\\AdvancedOidc\\Services\\AdvancedOidc';

    /**
     * Default minimum Leantime role in standard mode. 5 = readonly, i.e. every
     * role qualifies — this preserves the pre-0.3.0 behaviour ("any logged-in
     * user may issue") so upgrading does not silently revoke anyone's tokens.
     * Admins raise this on the admin page to tighten issuance.
     */
    public const DEFAULT_MIN_ROLE = 5;

    public function __construct(
        private Setting $settings,
        private AccessTokenRepository $tokenRepo,
    ) {}

    // --- Configuration ----------------------------------------------------

    /**
     * Whether the AdvancedOidc plugin is loaded. Detected by class presence
     * rather than the DB plugin manager, because AdvancedOidc is deployed as a
     * system plugin (LEAN_PLUGINS) and may not appear in getEnabledPlugins().
     * This mirrors how AdvancedOidc calls back into this plugin.
     */
    public function oidcPluginAvailable(): bool
    {
        return class_exists(self::OIDC_SERVICE);
    }

    /**
     * The raw env switch (independent of whether the OIDC plugin is present).
     * Accepts true/1/yes/on; unset/anything else => off.
     */
    public function oidcIntegrationEnabled(): bool
    {
        return filter_var(env(self::ENV_OIDC_INTEGRATION, false), FILTER_VALIDATE_BOOLEAN);
    }

    /** Connect-mode is effective only when the env flag is on AND the OIDC plugin exists. */
    public function usesOidc(): bool
    {
        return $this->oidcIntegrationEnabled() && $this->oidcPluginAvailable();
    }

    /** Admin-selected minimum Leantime role key for standard mode. */
    public function minRole(): int
    {
        $value = $this->settings->getSetting(self::SETTING_MIN_ROLE, false);
        $value = is_numeric($value) ? (int) $value : self::DEFAULT_MIN_ROLE;

        return array_key_exists($value, Roles::getRoles()) ? $value : self::DEFAULT_MIN_ROLE;
    }

    // --- Decision ---------------------------------------------------------

    /** Whether the current session user may issue a Personal Access Token. */
    public function currentUserMayIssue(): bool
    {
        if ($this->usesOidc()) {
            // OIDC-connect: ONLY the IdP entitlement matters; Leantime role ignored.
            return session(self::SESSION_KEY) === true;
        }

        // Standard mode: Leantime role threshold.
        return $this->roleAtLeast((string) session('userdata.role'), $this->minRole());
    }

    /** True if the named role ranks at least as high as the minimum role key. */
    private function roleAtLeast(string $roleName, int $minRoleKey): bool
    {
        $have = array_search($roleName, Roles::getRoles(), true);

        return $have !== false && (int) $have >= $minRoleKey;
    }

    // --- Enforcement / revocation ----------------------------------------

    /**
     * Revoke every Personal Access Token a user holds. Goes through the
     * repository directly (like the CLI), so it works without a matching
     * session. Best-effort per token.
     */
    public function revokeAllForUser(int $userId): void
    {
        if ($userId <= 0) {
            return;
        }

        foreach ($this->tokenRepo->getAllTokensByUserId($userId) ?? [] as $token) {
            $token = (array) $token;
            if (! isset($token['id'])) {
                continue;
            }
            try {
                $this->tokenRepo->deleteToken((int) $token['id']);
            } catch (\Throwable $e) {
                // best effort — one failed delete must not abort the rest
            }
        }
    }

    /**
     * Called by AdvancedOidc at login when the user is NOT entitled. Only
     * revokes in connect-mode; in standard mode the Leantime role governs
     * issuance and OIDC must not touch tokens.
     */
    public function enforceAtLogin(int $userId): void
    {
        if ($this->usesOidc()) {
            $this->revokeAllForUser($userId);
        }
    }

    /**
     * Defensive trigger for the account-settings page: if the current user may
     * not issue, make sure none of their tokens survive. Applies in either mode
     * (whoever may not issue gets purged). Idempotent.
     */
    public function enforceForCurrentUser(): void
    {
        $userId = (int) session('userdata.id');
        if ($userId > 0 && ! $this->currentUserMayIssue()) {
            $this->revokeAllForUser($userId);
        }
    }
}
