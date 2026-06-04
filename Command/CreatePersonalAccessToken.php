<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Command;

use Illuminate\Console\Command;
use Leantime\Core\Db\Db;
use Leantime\Domain\Auth\Repositories\AccessTokenRepository;
use Leantime\Domain\Users\Repositories\Users as UserRepository;

/**
 * Mint a Personal Access Token for a user. The plaintext token is shown ONCE
 * and cannot be retrieved later (only its sha256 hash is stored).
 *
 *   php bin/leantime pat:create 2 "claude-code"
 *   php bin/leantime pat:create 2 "ci-bot" --days=90
 */
class CreatePersonalAccessToken extends Command
{
    protected $signature = 'pat:create
        {userId : Leantime user id the token acts as}
        {name=personal-token : a label to identify this token}
        {--days= : optional expiry, in days from now}';

    protected $description = 'Create a Personal Access Token for a user (Bearer token for the JSON-RPC API).';

    public function handle(): int
    {
        $userId = (int) $this->argument('userId');
        $name = (string) $this->argument('name');

        $user = app(UserRepository::class)->getUser($userId);
        if (empty($user) || ! is_array($user)) {
            $this->error("No user found with id {$userId}.");

            return self::FAILURE;
        }

        $repo = app(AccessTokenRepository::class);

        // Disallow duplicate labels for the same user (case-insensitive),
        // matching the web UI behavior (Controllers/Tokens).
        foreach ($repo->getAllTokensByUserId($userId) ?? [] as $existing) {
            $existing = (array) $existing;
            if (strcasecmp((string) ($existing['name'] ?? ''), $name) === 0) {
                $this->error("User {$userId} already has a token labeled '{$name}'.");

                return self::FAILURE;
            }
        }

        $created = $repo->createToken($userId, $name);

        $days = $this->option('days');
        if ($days !== null && $days !== '' && (int) $days > 0) {
            $expiresAt = now()->addDays((int) $days);
            app(Db::class)->getConnection()
                ->table('zp_access_tokens')
                ->where('id', $created['id'])
                ->update(['expires_at' => $expiresAt]);
            $this->line("Expires: {$expiresAt}");
        }

        $this->info("Personal Access Token created for user {$userId} ({$user['username']}), label '{$name}'.");
        $this->warn('Store it now — it is shown only once and cannot be retrieved later:');
        $this->line('');
        $this->line($created['token']);
        $this->line('');
        $this->comment('Use it as:  Authorization: Bearer <token>   (env LEANTIME_PAT in the MCP)');

        return self::SUCCESS;
    }
}
