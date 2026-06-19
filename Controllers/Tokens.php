<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Controllers;

use Leantime\Core\Controller\Controller;
use Leantime\Core\Controller\Frontcontroller;
use Leantime\Core\Db\Db;
use Leantime\Domain\Auth\Services\AccessToken;
use Leantime\Plugins\PersonalAccessTokenAuth\Services\IssuancePolicy;
use Symfony\Component\HttpFoundation\Response;

/**
 * Handles create/revoke POSTs from the "Personal Access Tokens" tab on the
 * Account Settings page (the UI itself is rendered there via TokenTab). Uses
 * the core AccessToken service, which enforces self-or-admin authorization.
 */
class Tokens extends Controller
{
    private AccessToken $accessTokenService;

    public function init(): void
    {
        $this->accessTokenService = app()->make(AccessToken::class);
    }

    private function backToTab(): Response
    {
        return Frontcontroller::redirect(BASE_URL.'/users/editOwn#patTokens');
    }

    public function get(): Response
    {
        // The token UI is a tab on the Account Settings page; send users there.
        return $this->backToTab();
    }

    public function post(array $params): Response
    {
        $userId = (int) session('userdata.id');

        if (isset($params['createToken'])) {
            // Enforce the issuance policy server-side. The tab is hidden for
            // ineligible users, but a forged POST must still be rejected — and a
            // user who is no longer eligible should not keep stale tokens.
            $policy = app()->make(IssuancePolicy::class);
            if (! $policy->currentUserMayIssue()) {
                $policy->revokeAllForUser($userId);
                $this->tpl->setNotification('You are not allowed to create personal access tokens.', 'error');

                return $this->backToTab();
            }

            $label = trim((string) ($params['label'] ?? ''));
            // Blank/absent or <= 0 means "no expiry" (token never expires);
            // only a positive value sets an expires_at below.
            $days = (int) ($params['days'] ?? 0);

            if ($label === '') {
                $this->tpl->setNotification('A label is required.', 'error');

                return $this->backToTab();
            }

            // Disallow duplicate labels for the same user (case-insensitive).
            foreach ($this->accessTokenService->getUserTokens($userId) ?? [] as $existing) {
                $existing = (array) $existing;
                if (strcasecmp((string) ($existing['name'] ?? ''), $label) === 0) {
                    $this->tpl->setNotification('You already have a token with that label.', 'error');

                    return $this->backToTab();
                }
            }

            $created = $this->accessTokenService->createToken($userId, $label);
            if ($created && isset($created->token)) {
                if ($days > 0 && isset($created->id)) {
                    app()->make(Db::class)->getConnection()
                        ->table('zp_access_tokens')
                        ->where('id', $created->id)
                        ->update(['expires_at' => now()->addDays($days)]);
                }
                session(['pat.newToken' => $created->token]);
                $this->tpl->setNotification('Personal access token created.', 'success');
            } else {
                $this->tpl->setNotification('Could not create token.', 'error');
            }
        } elseif (isset($params['revokeToken'])) {
            try {
                $this->accessTokenService->deleteToken((int) $params['revokeToken']);
                $this->tpl->setNotification('Token revoked.', 'success');
            } catch (\Throwable $e) {
                $this->tpl->setNotification('You are not allowed to revoke that token.', 'error');
            }
        }

        return $this->backToTab();
    }
}
