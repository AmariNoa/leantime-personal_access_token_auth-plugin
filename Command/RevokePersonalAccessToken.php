<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Command;

use Illuminate\Console\Command;
use Leantime\Domain\Auth\Repositories\AccessTokenRepository;

/**
 * Revoke (delete) a Personal Access Token by its id (see `pat:list`).
 *
 *   php bin/leantime pat:revoke 5
 */
class RevokePersonalAccessToken extends Command
{
    protected $signature = 'pat:revoke {tokenId : the token id from pat:list}';

    protected $description = 'Revoke (delete) a Personal Access Token by id.';

    public function handle(): int
    {
        $tokenId = (int) $this->argument('tokenId');
        $ok = app(AccessTokenRepository::class)->deleteToken($tokenId);

        if ($ok) {
            $this->info("Token {$tokenId} revoked.");

            return self::SUCCESS;
        }

        $this->error("No token with id {$tokenId} (or already revoked).");

        return self::FAILURE;
    }
}
