<!--
SPDX-FileCopyrightText: 2026 AmariNoa
SPDX-License-Identifier: AGPL-3.0-only
-->

# PersonalAccessTokenAuth (Leantime plugin)

Adds **Personal Access Token (PAT) authentication** to Leantime's JSON-RPC API.

Leantime core only authenticates `/api/jsonrpc` via the company API key
(`X-API-KEY`), which acts as a shared "bot" user. This plugin lets a request
authenticate with `Authorization: Bearer <token>` instead, running as the
**token's own (human) user** — useful for personal automations and AI agents
operating a person's account, or any home/CI server integrating as that user.

It is a clean-room implementation built entirely on Leantime's **own AGPL core
primitives** (`AccessToken` / `AccessTokenRepository` / Sanctum, `getBearerToken`,
`Api::setApiUserSession`). It does **not** use or copy the commercial
"Advanced Auth" marketplace plugin.

> **License:** AGPL-3.0-only. As a Leantime plugin it is a derivative work of
> Leantime (AGPL-3.0); if you serve it over a network you must offer the source
> to those users (AGPL §13). See `LICENSE`.

## How it works

`register.php` listens on the `before_api_request` event that Leantime's
`AuthCheck` middleware fires for every API request — after all plugins are
loaded and **before** the auth guards run. The listener
(`Services/BearerTokenAuthenticator`) reads the Bearer token, validates it
(sha256 lookup in `zp_access_tokens`, plus an expiry check), loads the owning
user, and calls `Api::setApiUserSession(...)`. The session guard then passes
and the request executes as that user.

Tokens are stored in the **core** `zp_access_tokens` table (already created by
Leantime's install schema) — no extra migration.

## Install

1. Copy this plugin into your Leantime install so the folder is named exactly
   **`PersonalAccessTokenAuth`** (the folder name must match the PHP namespace
   `Leantime\Plugins\PersonalAccessTokenAuth`):

   ```
   app/Plugins/PersonalAccessTokenAuth/
   ```

   e.g. `git clone <this repo> app/Plugins/PersonalAccessTokenAuth`

2. Enable it in Leantime: **Settings → Plugins → enable "PersonalAccessTokenAuth"**
   (or add it to your `LEANTIME_PLUGINS` config). Confirm it shows as enabled.

## Issuing a token

### Recommended: console command (this plugin)

```bash
php bin/leantime pat:create <USER_ID> "claude-code"
# optional expiry:
php bin/leantime pat:create <USER_ID> "ci-bot" --days=90
```

The plaintext token is printed **once** — store it immediately. Use it as the
MCP's `LEANTIME_PAT`, or send it directly as `Authorization: Bearer <token>`.

Manage tokens:

```bash
php bin/leantime pat:list <USER_ID>     # metadata only (value is hashed)
php bin/leantime pat:revoke <TOKEN_ID>  # delete a token
```

### Fallback: shell + SQL (no console needed)

The token is a 40-char random string stored as its sha256 hash, so you can mint
one directly:

```bash
TOKEN=$(openssl rand -hex 20)                                  # 40 hex chars
HASH=$(printf %s "$TOKEN" | sha256sum | cut -d' ' -f1)
# then INSERT (replace <USER_ID>):
#   INSERT INTO zp_access_tokens
#     (tokenable_type, tokenable_id, name, token, abilities, created_at)
#   VALUES
#     ('Leantime\\Domain\\Auth\\Services\\Auth', <USER_ID>, 'claude-code',
#      '<HASH>', '["*"]', NOW());
echo "PAT (store this): $TOKEN"
```

## Verify

```bash
curl -s https://YOUR_LEANTIME/api/jsonrpc \
  -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"leantime.rpc.Auth.getUserId","params":{},"id":1}'
# -> {"jsonrpc":"2.0","result":<the token owner's user id>,"id":1}
```

Without the plugin (or with an invalid token) the same Bearer-only request
returns `401 Unauthorized`.

## Restricting who may issue tokens

By default any logged-in user can create a token for their own account from the
**Account Settings → Personal Access Tokens** tab. Admins can restrict issuance
from **Company → Administration → Access Tokens** (the plugin's admin page),
which has an *Issuance policy* panel with two modes:

- **Standard mode (default).** Pick a **minimum Leantime role**; only users whose
  role ranks at least that high see the token tab and may create tokens. Users
  below the threshold have the tab hidden and any existing tokens revoked. The
  default is **readonly** (every role qualifies — no restriction), so upgrading
  does not revoke anyone's tokens; raise it to tighten issuance.
- **OIDC-connect mode.** Shown only when the companion
  [`AdvancedOidc`](https://github.com/AmariNoa/leantime-advanced_oidc-plugin)
  plugin (≥ 1.3.0) is installed. When enabled, issuance is gated **solely on the
  IdP role** — the Leantime role is ignored. At login AdvancedOidc checks its
  `OIDC_PAT_ISSUE_ROLES` against the user's verified IdP roles and records the
  result in the session; this plugin reads it to show/hide the tab and authorize
  creation. A user **without** the entitlement has the tab hidden and their
  existing tokens **revoked on their next login**.

Notes and limitations:

- **Enforcement is server-side** (the create endpoint rejects ineligible users),
  so hiding the tab is not the only guard.
- **The CLI (`pat:create`) is not gated** — it is run by a trusted server admin
  and bypasses both modes by design.
- **OIDC-connect needs a session.** A user who signs in without OIDC (e.g.
  password) has no entitlement signal and is therefore denied (fail-closed); the
  defensive revoke runs when they open the account page.
- **Role-change latency.** Losing the IdP role removes issuance and revokes
  tokens at the **next login**, not instantly. Already-issued tokens keep working
  until then — PAT *authentication* does not re-check IdP roles.

## Security notes

- A token grants the **full access of its user** (abilities default to `*`).
  Issue per-person, label them, and revoke when no longer needed.
- Prefer setting an expiry (`--days`).
- Tokens are transmitted as Bearer credentials — only use over HTTPS.
