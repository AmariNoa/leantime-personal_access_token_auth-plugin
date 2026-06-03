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

        <form method="get" action="<?php echo htmlspecialchars($base); ?>/personalAccessTokenAuth/admin" class="form-inline" style="margin-bottom:15px;">
            <label style="margin-right:8px;">Filter by user</label>
            <select name="userId" class="form-control" onchange="this.form.submit();">
                <option value="0">All users</option>
                <?php foreach ($users as $u) {
                    $u = (array) $u;
                    $uid = (int) ($u['id'] ?? 0);
                    $name = $displayName($u['firstname'] ?? '', $u['lastname'] ?? '', $u['username'] ?? '', $uid);
                    echo '<option value="'.$uid.'"'.($uid === $filterUserId ? ' selected' : '').'>'.htmlspecialchars($name).'</option>';
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
                        $uname = $displayName($t['firstname'] ?? '', $t['lastname'] ?? '', $t['username'] ?? '', $t['tokenable_id'] ?? ''); ?>
                        <tr>
                            <td><?php echo htmlspecialchars($uname); ?></td>
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
