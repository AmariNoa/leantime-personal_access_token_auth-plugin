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

## Security notes

- A token grants the **full access of its user** (abilities default to `*`).
  Issue per-person, label them, and revoke when no longer needed.
- Prefer setting an expiry (`--days`).
- Tokens are transmitted as Bearer credentials — only use over HTTPS.
