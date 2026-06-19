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
use Leantime\Domain\Setting\Repositories\Setting;
use Leantime\Plugins\PersonalAccessTokenAuth\Services\IssuancePolicy;
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

        $policy = app(IssuancePolicy::class);

        $this->tpl->assign('tokens', $tokens);
        $this->tpl->assign('usersWithTokens', $usersWithTokens);
        $this->tpl->assign('filterUserId', $filterUserId);
        // Issuance-policy state for the admin form. The OIDC on/off switch is an
        // env flag (not editable here); only the standard-mode min role is.
        $this->tpl->assign('usesOidc', $policy->usesOidc());
        $this->tpl->assign('oidcIntegrationEnabled', $policy->oidcIntegrationEnabled());
        $this->tpl->assign('oidcAvailable', $policy->oidcPluginAvailable());
        $this->tpl->assign('minRole', $policy->minRole());
        $this->tpl->assign('roles', Roles::getRoles());

        return $this->tpl->display('personalAccessTokenAuth.admin');
    }

    public function post(array $params): Response
    {
        Auth::authOrRedirect([Roles::$owner, Roles::$admin], true);

        if (isset($params['saveSettings'])) {
            // Only the standard-mode minimum role is editable here; the OIDC
            // on/off switch is the OIDC_PAT_ISSUE_INTEGRATION env flag.
            $minRole = (int) ($params['minRole'] ?? IssuancePolicy::DEFAULT_MIN_ROLE);
            if (array_key_exists($minRole, Roles::getRoles())) {
                app(Setting::class)->saveSetting(IssuancePolicy::SETTING_MIN_ROLE, (string) $minRole);
            }

            $this->tpl->setNotification('Settings saved.', 'success');

            return Frontcontroller::redirect(BASE_URL.'/personalAccessTokenAuth/admin');
        }

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
