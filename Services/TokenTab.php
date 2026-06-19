<?php

/**
 * SPDX-FileCopyrightText: 2026 AmariNoa
 * SPDX-License-Identifier: AGPL-3.0-only
 */

namespace Leantime\Plugins\PersonalAccessTokenAuth\Services;

/**
 * Renders the "Personal Access Tokens" tab injected into the Account Settings
 * page (editOwn). The tab header and content are echoed inline via the
 * editOwn.blade.php `tabs` / `tabsContent` template events. Forms post to the
 * plugin's Tokens controller, which creates/revokes and redirects back here.
 */
class TokenTab
{
    private function e(string $v): string
    {
        return htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
    }

    /** Whether the current user is allowed to see/use the token tab at all. */
    private function mayIssue(): bool
    {
        return app()->make(IssuancePolicy::class)->currentUserMayIssue();
    }

    /** Tab header <li> (with icon), echoed into the editOwn tab list. */
    public function renderTabHeader(): void
    {
        // Hide the whole tab from users who may not issue tokens (the content
        // pane hides in lockstep, so no orphan header remains).
        if (! $this->mayIssue()) {
            return;
        }

        echo '<li><a href="#patTokens"><span class="fa fa-fw fa-key"></span> Personal Access Tokens</a></li>';
    }

    /** Tab content pane, echoed into the editOwn tab content area. */
    public function renderTabContent(): void
    {
        // Hidden for ineligible users; also purge any tokens they still hold
        // (defensive trigger for non-OIDC logins that never hit the login hook).
        if (! $this->mayIssue()) {
            app()->make(IssuancePolicy::class)->enforceForCurrentUser();

            return;
        }

        $accessToken = app()->make(\Leantime\Domain\Auth\Services\AccessToken::class);
        $userId = (int) session('userdata.id');
        $tokens = $accessToken->getUserTokens($userId) ?? [];

        // One-time display of a freshly created token (set by the controller).
        $newToken = session('pat.newToken') ?? '';
        session(['pat.newToken' => null]);

        $formName = (string) session('formTokenName');
        $formValue = (string) session('formTokenValue');
        $action = BASE_URL.'/personalAccessTokenAuth/tokens';

        echo '<div id="patTokens">';
        echo '<div class="row"><div class="col-md-12">';
        echo '<h4 class="widgettitle title-light">Personal Access Tokens</h4>';
        echo '<p>Tokens authenticate the API as your own account (Authorization: Bearer). '
            .'Use one as <code>LEANTIME_PAT</code> in your AI agent\'s MCP config.</p>';

        if (! empty($newToken)) {
            $tok = $this->e($newToken);
            echo '<div id="patModalOverlay" style="position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:9998;"></div>';
            echo '<div id="patModalBox" role="dialog" aria-modal="true" '
                .'style="position:fixed;z-index:9999;top:50%;left:50%;transform:translate(-50%,-50%);'
                .'background:#fff;color:#333;padding:24px;border-radius:8px;max-width:560px;width:90%;'
                .'box-shadow:0 10px 40px rgba(0,0,0,0.35);">';
            echo '<h4 class="widgettitle title-light" style="margin-top:0;"><span class="fa fa-key"></span> Personal access token created</h4>';
            echo '<p>Copy your token now. This is the only time it will be shown.</p>';
            echo '<input type="text" id="patNewTokenValue" value="'.$tok.'" readonly style="width:100%;" onclick="this.select();" />';
            echo '<p class="text-muted" style="margin-top:8px;">Set it as <code>LEANTIME_PAT</code> in your AI agent\'s MCP config.</p>';
            echo '<div style="margin-top:16px;text-align:right;">'
                .'<button class="btn btn-primary" type="button" onclick="leantime.snippets.copyUrl(\'patNewTokenValue\');">Copy token</button> '
                .'<button class="btn" type="button" onclick="var o=document.getElementById(\'patModalOverlay\');var b=document.getElementById(\'patModalBox\');if(o){o.remove();}if(b){b.remove();}">Close</button>'
                .'</div>';
            echo '</div>';
        }

        // Create form (autocomplete off so password managers don't treat the
        // label as a username on this account-settings page).
        echo '<form action="'.$this->e($action).'" method="post" autocomplete="off">';
        echo '<input type="hidden" name="'.$this->e($formName).'" value="'.$this->e($formValue).'" />';
        echo '<input type="hidden" name="createToken" value="1" />';
        echo '<div class="form-group"><label>Label</label>'
            .'<input type="text" name="label" class="form-control" placeholder="e.g. claude-code" maxlength="100" required '
            .'autocomplete="off" data-1p-ignore="true" data-lpignore="true" data-bwignore data-form-type="other" /></div>';
        echo '<div class="form-group"><label>Expires in (days)</label>'
            .'<input type="number" name="days" class="form-control" value="90" min="0" max="3650" '
            .'placeholder="leave blank for no expiry" />'
            .'<span class="help-block">Enter 0 or leave blank for no expiry (the token never expires).</span></div>';
        echo '<p class="stdformbutton"><button class="btn btn-primary" type="submit">Create token</button></p>';
        echo '</form>';

        // Existing tokens
        echo '<table class="table"><thead><tr>'
            .'<th>ID</th><th>Label</th><th>Created</th><th>Last used</th><th>Expires</th><th></th>'
            .'</tr></thead><tbody>';
        if (empty($tokens)) {
            echo '<tr><td colspan="6">No tokens yet.</td></tr>';
        } else {
            foreach ($tokens as $t) {
                $t = (array) $t;
                $id = (string) ($t['id'] ?? '');
                echo '<tr>'
                    .'<td>'.$this->e($id).'</td>'
                    .'<td>'.$this->e((string) ($t['name'] ?? '')).'</td>'
                    .'<td>'.$this->e((string) ($t['created_at'] ?? '')).'</td>'
                    .'<td>'.$this->e((string) ($t['last_used_at'] ?? 'never')).'</td>'
                    .'<td>'.$this->e((string) ($t['expires_at'] ?? 'never')).'</td>'
                    .'<td><form action="'.$this->e($action).'" method="post" style="display:inline;" '
                        .'onsubmit="return confirm(\'Revoke this token?\');">'
                        .'<input type="hidden" name="'.$this->e($formName).'" value="'.$this->e($formValue).'" />'
                        .'<input type="hidden" name="revokeToken" value="'.$this->e($id).'" />'
                        .'<button class="btn btn-danger" type="submit">Revoke</button>'
                    .'</form></td>'
                    .'</tr>';
            }
        }
        echo '</tbody></table>';
        echo '</div></div>';
        echo '</div>';
    }
}
