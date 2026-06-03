<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Services;

use Leantime\Core\Http\ApiRequest;
use Leantime\Domain\Api\Services\Api;
use Leantime\Domain\Auth\Repositories\AccessTokenRepository;
use Leantime\Domain\Users\Repositories\Users as UserRepository;

/**
 * Authenticates an API request that carries a Bearer Personal Access Token.
 *
 * Mirrors the core API-key flow (load the user, then Api::setApiUserSession)
 * but keyed off a PAT instead of an X-API-KEY. The token is the 40-char
 * plaintext produced by AccessTokenRepository::createToken; it is matched by
 * its sha256 hash. Expiry is enforced here because the repository's findToken
 * does not filter on it.
 */
class BearerTokenAuthenticator
{
    /**
     * Establish the token owner's session if a valid, unexpired Bearer PAT is
     * present. No-op otherwise: requests with an X-API-KEY (or none) fall
     * through to the normal guards, and an invalid/expired token just results
     * in the usual 401 downstream.
     */
    public function authenticate(): void
    {
        $request = app(ApiRequest::class);
        $bearer = $request->getBearerToken();
        if (empty($bearer)) {
            return;
        }

        $tokenRepo = app(AccessTokenRepository::class);
        $tokenRow = $tokenRepo->findToken($bearer);
        if (empty($tokenRow)) {
            return;
        }

        // findToken() matches on the hash only; enforce expiry ourselves.
        if (! empty($tokenRow['expires_at']) && strtotime((string) $tokenRow['expires_at']) < time()) {
            return;
        }

        $userId = (int) ($tokenRow['tokenable_id'] ?? 0);
        if ($userId <= 0) {
            return;
        }

        $user = app(UserRepository::class)->getUser($userId);
        if (empty($user) || ! is_array($user)) {
            return;
        }

        // Establish the session as the token's human owner. isExternalAuth=true
        // matches how the core API-key path calls setApiUserSession.
        app(Api::class)->setApiUserSession($user, true);

        // Best-effort last-used bookkeeping; never block the request on it.
        try {
            $tokenRepo->updateLastUsedAt((int) $tokenRow['id']);
        } catch (\Throwable $e) {
            // non-fatal
        }
    }
}
