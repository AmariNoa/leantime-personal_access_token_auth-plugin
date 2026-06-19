<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

$tokens = $tpl->get('tokens') ?? [];
$users = $tpl->get('usersWithTokens') ?? [];
$filterUserId = (int) ($tpl->get('filterUserId') ?? 0);
$formName = (string) session('formTokenName');
$formValue = (string) session('formTokenValue');
$base = BASE_URL;

$oidcAvailable = (bool) $tpl->get('oidcAvailable');
$useOidc = (bool) $tpl->get('useOidc');
$minRole = (int) ($tpl->get('minRole') ?? 5);
$roles = $tpl->get('roles') ?? [];

$displayName = function ($first, $last, $username, $id) {
    $name = trim((string) $first.' '.(string) $last);
    if ($name === '') {
        $name = (string) $username;
    }
    if ($name === '') {
        $name = 'user '.(string) $id;
    }

    return $name;
};
?>

<div class="pageheader">
    <div class="pageicon"><span class="fa fa-key"></span></div>
    <div class="pagetitle">
        <h1>Personal Access Tokens (Admin)</h1>
        <h5>View and revoke any user's personal access tokens.</h5>
    </div>
</div>

<div class="maincontent">
    <div class="maincontentinner">

        <?php echo $tpl->displayNotification(); ?>

        <div class="box" style="margin-bottom:20px;">
            <h4 class="widgettitle title-light"><span class="fa fa-fw fa-cog"></span> Issuance policy</h4>
            <form method="post" action="<?php echo htmlspecialchars($base); ?>/personalAccessTokenAuth/admin">
                <input type="hidden" name="<?php echo htmlspecialchars($formName); ?>" value="<?php echo htmlspecialchars($formValue); ?>" />
                <input type="hidden" name="saveSettings" value="1" />

                <?php if ($oidcAvailable) { ?>
                    <div class="form-group">
                        <label class="checkbox">
                            <input type="checkbox" name="useOidc" value="1" <?php echo $useOidc ? 'checked' : ''; ?> />
                            Use AdvancedOidc plugin integration to gate token issuance
                        </label>
                        <span class="help-block">
                            When enabled, only users whose IdP roles include one of
                            <code>OIDC_PAT_ISSUE_ROLES</code> may issue tokens (the Leantime role
                            below is ignored). Users without that entitlement have their tokens
                            revoked on next login.
                        </span>
                    </div>
                <?php } else { ?>
                    <p class="text-muted">
                        <span class="fa fa-info-circle"></span>
                        The <strong>AdvancedOidc</strong> plugin is not installed, so OIDC-based
                        gating is unavailable. Issuance is gated on the Leantime role below.
                    </p>
                <?php } ?>

                <div class="form-group">
                    <label>Minimum role allowed to issue tokens (standard mode)</label>
                    <select name="minRole" class="form-control" style="max-width:280px;">
                        <?php foreach ($roles as $key => $name) {
                            $key = (int) $key; ?>
                            <option value="<?php echo $key; ?>"<?php echo $key === $minRole ? ' selected' : ''; ?>>
                                <?php echo htmlspecialchars(ucfirst((string) $name)).' ('.$key.')'; ?>
                            </option>
                        <?php } ?>
                    </select>
                    <span class="help-block">Used when OIDC integration is off. A user's role must rank at least this high to create a token.</span>
                </div>

                <p class="stdformbutton"><button class="btn btn-primary" type="submit">Save settings</button></p>
            </form>
        </div>

        <form method="get" action="<?php echo htmlspecialchars($base); ?>/personalAccessTokenAuth/admin" class="form-inline" style="margin-bottom:15px;">
            <label style="margin-right:8px;">Filter by user</label>
            <select name="userId" class="form-control" onchange="this.form.submit();">
                <option value="0">All users</option>
                <?php foreach ($users as $u) {
                    $u = (array) $u;
                    $uid = (int) ($u['id'] ?? 0);
                    $name = $displayName($u['firstname'] ?? '', $u['lastname'] ?? '', $u['username'] ?? '', $uid);
                    $email = trim((string) ($u['username'] ?? ''));
                    $label = ($email !== '' && $email !== $name) ? $name.' ('.$email.')' : $name;
                    echo '<option value="'.$uid.'"'.($uid === $filterUserId ? ' selected' : '').'>'.htmlspecialchars($label).'</option>';
                } ?>
            </select>
        </form>

        <table class="table">
            <thead>
                <tr><th>User</th><th>Label</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr>
            </thead>
            <tbody>
                <?php if (empty($tokens)) { ?>
                    <tr><td colspan="6">No tokens.</td></tr>
                <?php } else {
                    foreach ($tokens as $t) {
                        $t = (array) $t;
                        $id = (string) ($t['id'] ?? '');
                        $uname = $displayName($t['firstname'] ?? '', $t['lastname'] ?? '', $t['username'] ?? '', $t['tokenable_id'] ?? '');
                        $uemail = trim((string) ($t['username'] ?? '')); ?>
                        <tr>
                            <td>
                                <?php echo htmlspecialchars($uname);
                                if ($uemail !== '' && $uemail !== $uname) {
                                    echo '<br><small class="text-muted">'.htmlspecialchars($uemail).'</small>';
                                } ?>
                            </td>
                            <td><?php echo htmlspecialchars((string) ($t['name'] ?? '')); ?></td>
                            <td><?php echo htmlspecialchars((string) ($t['created_at'] ?? '')); ?></td>
                            <td><?php echo htmlspecialchars((string) ($t['last_used_at'] ?? 'never')); ?></td>
                            <td><?php echo htmlspecialchars((string) ($t['expires_at'] ?? 'never')); ?></td>
                            <td>
                                <form method="post" action="<?php echo htmlspecialchars($base); ?>/personalAccessTokenAuth/admin" style="display:inline;" onsubmit="return confirm('Revoke this token?');">
                                    <input type="hidden" name="<?php echo htmlspecialchars($formName); ?>" value="<?php echo htmlspecialchars($formValue); ?>" />
                                    <input type="hidden" name="revokeToken" value="<?php echo htmlspecialchars($id); ?>" />
                                    <input type="hidden" name="filterUserId" value="<?php echo $filterUserId; ?>" />
                                    <button class="btn btn-danger" type="submit">Revoke</button>
                                </form>
                            </td>
                        </tr>
                <?php }
                } ?>
            </tbody>
        </table>

    </div>
</div>
