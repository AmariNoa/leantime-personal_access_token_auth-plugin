<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Controllers;

use Leantime\Core\Controller\Controller;
use Leantime\Core\Controller\Frontcontroller;
use Leantime\Core\Db\Db;
use Leantime\Domain\Auth\Models\Roles;
use Leantime\Domain\Auth\Services\AccessToken;
use Leantime\Domain\Auth\Services\Auth;
use Symfony\Component\HttpFoundation\Response;

/**
 * Admin page: list all users' personal access tokens (with an optional per-user
 * filter) and revoke any of them. Admin/owner only. Revoking uses the core
 * AccessToken service, whose authorization permits admins to delete any token.
 */
class Admin extends Controller
{
    public function get(): Response
    {
        Auth::authOrRedirect([Roles::$owner, Roles::$admin], true);

        $db = app(Db::class)->getConnection();
        $filterUserId = (int) ($_GET['userId'] ?? 0);

        $usersWithTokens = $db->select(
            'SELECT DISTINCT u.id, u.firstname, u.lastname, u.username '
            .'FROM zp_access_tokens t JOIN zp_user u ON t.tokenable_id = u.id '
            .'ORDER BY u.firstname, u.lastname'
        );

        $sql = 'SELECT t.id, t.name, t.tokenable_id, t.created_at, t.last_used_at, t.expires_at, '
            .'u.firstname, u.lastname, u.username '
            .'FROM zp_access_tokens t LEFT JOIN zp_user u ON t.tokenable_id = u.id ';

        if ($filterUserId > 0) {
            $tokens = $db->select($sql.'WHERE t.tokenable_id = ? ORDER BY t.created_at DESC', [$filterUserId]);
        } else {
            $tokens = $db->select($sql.'ORDER BY u.firstname, u.lastname, t.created_at DESC');
        }

        $this->tpl->assign('tokens', $tokens);
        $this->tpl->assign('usersWithTokens', $usersWithTokens);
        $this->tpl->assign('filterUserId', $filterUserId);

        return $this->tpl->display('personalAccessTokenAuth.admin');
    }

    public function post(array $params): Response
    {
        Auth::authOrRedirect([Roles::$owner, Roles::$admin], true);

        if (isset($params['revokeToken'])) {
            try {
                app(AccessToken::class)->deleteToken((int) $params['revokeToken']);
                $this->tpl->setNotification('Token revoked.', 'success');
            } catch (\Throwable $e) {
                $this->tpl->setNotification('Could not revoke token.', 'error');
            }
        }

        $filter = (int) ($params['filterUserId'] ?? 0);
        $url = BASE_URL.'/personalAccessTokenAuth/admin'.($filter > 0 ? '?userId='.$filter : '');

        return Frontcontroller::redirect($url);
    }
}
