// Cookie SSO. The hub's Better-Auth cookie is scoped to its bare domain, so a
// module served on a sibling subdomain receives it on every browser request;
// forwarding it to `GET /api/me` gives the same identity + organizations[]
// shape the OIDC userinfo endpoint returns, with no OAuth client at all.

import { getRawtohApiUrl, type UserInfo } from "./oidc"

/**
 * How users sign in: `cookie` unless an OAuth client is configured. Modules
 * on the hub domain leave RAWTOH_CLIENT_ID unset; self-hosted ones set it.
 */
export const authMode: "cookie" | "oidc" = process.env.RAWTOH_CLIENT_ID
  ? "oidc"
  : "cookie"

/** Hub SPA (its sign-in page), `RAWTOH_APP_URL`. Same origin as the API in production. */
export function getRawtohAppUrl(): string {
  return process.env.RAWTOH_APP_URL || getRawtohApiUrl()
}

// ponytail: per-cookie cache, 30 s; a hub-side revocation lags by that much.
const ME_TTL = 30_000
const meCache = new Map<string, { user: UserInfo; until: number }>()

/** Who the forwarded hub cookie belongs to, or null when the hub says 401. */
export async function fetchUserByCookie(
  cookie: string
): Promise<UserInfo | null> {
  const hit = meCache.get(cookie)
  if (hit && hit.until > Date.now()) return hit.user

  const res = await fetch(`${getRawtohApiUrl()}/api/me`, {
    headers: { cookie },
  })
  if (res.status === 401) return null
  if (!res.ok) throw new Error(`Rawtoh /api/me failed (${res.status})`)

  const me = (await res.json()) as {
    user: { id: string; name: string; email: string; image: string | null }
    organizations: Array<{
      id: string
      name: string
      slug: string
      logo: string | null
      role: string
    }>
  }
  const user: UserInfo = {
    sub: me.user.id,
    name: me.user.name,
    email: me.user.email,
    picture: me.user.image ?? undefined,
    organizations: me.organizations.map(({ logo, ...o }) => ({
      ...o,
      logo: logo ?? undefined,
    })),
  }
  if (meCache.size > 1000) meCache.clear()
  meCache.set(cookie, { user, until: Date.now() + ME_TTL })
  return user
}

/**
 * End the hub session — it is the only session there is. `origin` is the
 * module's own origin: Better-Auth wants one on cookie-bearing POSTs, and the
 * hub trusts `*.<COOKIE_DOMAIN>`.
 */
export async function signOutHub(
  cookie: string,
  origin: string
): Promise<void> {
  meCache.delete(cookie)
  const res = await fetch(`${getRawtohApiUrl()}/api/auth/sign-out`, {
    method: "POST",
    headers: { cookie, origin },
  })
  if (!res.ok && res.status !== 401) {
    throw new Error(`Rawtoh sign-out failed (${res.status})`)
  }
}
