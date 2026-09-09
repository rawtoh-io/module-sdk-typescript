# @rawtoh/module-sdk

What a TypeScript module needs to talk to a Rawtoh hub. Used by the
first-party modules (board, twitch, obs); published to npm from this repo.

```ts
import { enroll, HubConnection, getRawtohApiUrl } from "@rawtoh/module-sdk"
import {
  authRoutes,
  createAuthMiddleware,
  hubAuthHeaders,
} from "@rawtoh/module-sdk/hono"
```

- **Identity** — `enroll(apiUrl, token)` redeems an enrollment token into an
  Ed25519 key pair; `signChallenge` answers `session.challenge`.
- **Hub connection** — `HubConnection` (register, reconnect with backoff,
  `event.subscribe` table, `emit`) over `WsClient` (JSON-RPC 2.0 + ping).
- **User login** (`/hono`) — `createAuthMiddleware()` gives `requireAuth` /
  `resolveOrg`; `authRoutes(appUrl)` mounts login, callback, me and logout;
  `hubAuthHeaders(c)` calls the hub API as the current user.

## Sign-in modes

| `RAWTOH_CLIENT_ID` | Mode     | How                                                                                                                |
| ------------------ | -------- | ------------------------------------------------------------------------------------------------------------------ |
| unset              | `cookie` | Module on a subdomain of the hub's `COOKIE_DOMAIN`; the hub cookie is forwarded to `GET /api/me`. No OAuth client. |
| set                | `oidc`   | Self-hosted elsewhere: authorization code + PKCE, tokens in the module's session.                                  |

Env: `RAWTOH_ISSUER` (hub `/api/auth`), `RAWTOH_APP_URL` (hub sign-in page,
defaults to the issuer origin), `RAWTOH_WS_URL`. OIDC only:
`RAWTOH_CLIENT_ID`, `RAWTOH_CLIENT_SECRET`, `RAWTOH_REDIRECT_URI`,
`RAWTOH_SCOPES`, `RAWTOH_RESOURCE`.

## Release

```bash
bun test && bun run typecheck
npm publish   # `files` ships src/ only
```
