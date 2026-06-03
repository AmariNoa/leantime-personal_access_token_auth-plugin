<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Command;

use Illuminate\Console\Command;
use Leantime\Domain\Auth\Repositories\AccessTokenRepository;

/**
 * List a user's Personal Access Tokens (metadata only — the token value is
 * hashed and never recoverable).
 *
 *   php bin/leantime pat:list 2
 */
class ListPersonalAccessTokens extends Command
{
    protected $signature = 'pat:list {userId : Leantime user id}';

    protected $description = 'List the Personal Access Tokens issued for a user.';

    public function handle(): int
    {
        $userId = (int) $this->argument('userId');
        $tokens = app(AccessTokenRepository::class)->getAllTokensByUserId($userId) ?? [];

        if (empty($tokens)) {
            $this->info("No tokens for user {$userId}.");

            return self::SUCCESS;
        }

        $rows = array_map(static function (array $t): array {
            return [
                $t['id'] ?? '',
                $t['name'] ?? '',
                $t['created_at'] ?? '',
                $t['last_used_at'] ?? 'never',
                $t['expires_at'] ?? 'never',
            ];
        }, $tokens);

        $this->table(['id', 'name', 'created', 'last used', 'expires'], $rows);

        return self::SUCCESS;
    }
}
