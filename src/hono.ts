// Hono glue for a module's own web UI: session shape, auth middleware and the
// login routes every module mounts identically. Both sign-in modes live
// behind the same `user` variable, so route code never knows which one runs.

import type { SessionEnv } from "@hono/session"
import { Hono, type Context } from "hono"
import { createMiddleware } from "hono/factory"
import {
  buildAuthorizeUrl,
  exchangeCode,
  fetchUserInfo,
  getOIDCConfig,
  getRedirectUri,
  refreshAccessToken,
  type AuthRequest,
  type TokenSet,
  type UserInfo,
} from "./oidc"
import { authMode, fetchUserByCookie, getRawtohAppUrl, signOutHub } from "./sso"

/** What the SDK keeps in the session (OIDC mode only). Modules extend it with their own fields. */
export type RawtohSessionData = {
  tokens?: TokenSet
  token_expires_at?: number
  user?: UserInfo
  sub?: string
  auth?: AuthRequest
  returnTo?: string
}

export type RawtohAuthEnv<S extends RawtohSessionData = RawtohSessionData> =
  SessionEnv<S> & {
    Variables: {
      user: UserInfo
    }
  }

const TOKEN_REFRESH_MARGIN = 60

/**
 * `requireAuth` rejects anonymous calls (and, in OIDC mode, refreshes an
 * expiring access token); `resolveOrg(role?)` checks `:orgId` against the
 * user's organizations.
 */
export function createAuthMiddleware<S extends RawtohSessionData>() {
  const requireAuth = createMiddleware<RawtohAuthEnv<S>>(async (c, next) => {
    if (authMode === "cookie") {
      const cookie = c.req.header("cookie")
      const user = cookie ? await fetchUserByCookie(cookie) : null
      if (!user) return c.json({ error: "Unauthorized" }, 401)
      c.set("user", user)
      return next()
    }

    const session = c.get("session")
    const data = await session.get()
    if (!data?.user || !data?.tokens || !data?.sub) {
      return c.json({ error: "Unauthorized" }, 401)
    }

    const now = Math.floor(Date.now() / 1000)
    const expiresAt = data.token_expires_at ?? 0

    if (now >= expiresAt - TOKEN_REFRESH_MARGIN && data.tokens.refresh_token) {
      try {
        const config = await getOIDCConfig()
        const tokens = await refreshAccessToken(
          config,
          data.tokens.refresh_token
        )
        const user = await fetchUserInfo(config, tokens.access_token, data.sub)
        const token_expires_at =
          Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 3600)
        await session.update((prev) => ({
          ...(prev ?? data),
          tokens,
          token_expires_at,
          user,
        }))
        c.set("user", user)
      } catch (err) {
        console.error("[auth] Token refresh failed:", err)
        return c.json({ error: "Unauthorized" }, 401)
      }
    } else {
      c.set("user", data.user)
    }

    await next()
  })

  function resolveOrg(role?: "owner") {
    return createMiddleware<RawtohAuthEnv<S>>(async (c, next) => {
      const user = c.get("user")
      const orgId = c.req.param("orgId")
      const org = user.organizations?.find((o) => o.id === orgId)
      if (!org) {
        return c.json({ error: "Organization not found" }, 404)
      }
      if (role && org.role !== role) {
        return c.json({ error: "Access denied" }, 403)
      }
      await next()
    })
  }

  return { requireAuth, resolveOrg }
}

/**
 * Headers to call the hub API as the current user: the forwarded cookie, or
 * the OIDC bearer token. Null when the session holds neither.
 */
export async function hubAuthHeaders<S extends RawtohSessionData>(
  c: Context<RawtohAuthEnv<S>>
): Promise<Record<string, string> | null> {
  if (authMode === "cookie") {
    const cookie = c.req.header("cookie")
    return cookie ? { cookie } : null
  }
  const token = (await c.get("session").get())?.tokens?.access_token
  return token ? { Authorization: `Bearer ${token}` } : null
}

export interface AuthRoutesOptions {
  /**
   * Runs with the signed-in user: after the OIDC callback, and on every
   * `GET /api/auth/me` in cookie mode (there is no callback to hook there).
   * Keep it idempotent.
   */
  onLogin?: (user: UserInfo) => Promise<void> | void
}

// Relative paths only — never an open redirect to an external origin.
function safePath(returnTo?: string): string | undefined {
  return returnTo?.startsWith("/") && !returnTo.startsWith("//")
    ? returnTo
    : undefined
}

/**
 * `GET /api/auth/login?returnTo=`, `GET /callback`, `GET /api/auth/me`,
 * `POST /api/auth/logout`. `appUrl` is the module's SPA origin, where the
 * browser lands after login.
 */
export function authRoutes<S extends RawtohSessionData>(
  appUrl: string,
  opts: AuthRoutesOptions = {}
): Hono<RawtohAuthEnv<S>> {
  const auth = new Hono<RawtohAuthEnv<S>>()
  const landing = (returnTo?: string) =>
    new URL(safePath(returnTo) ?? "/", appUrl).toString()

  auth.get("/api/auth/login", async (c) => {
    const returnTo = safePath(c.req.query("returnTo"))

    if (authMode === "cookie") {
      const redirect = encodeURIComponent(landing(returnTo))
      return c.json({ url: `${getRawtohAppUrl()}/signin?redirect=${redirect}` })
    }

    const session = c.get("session")
    const config = await getOIDCConfig()
    const { url, auth: authRequest } = await buildAuthorizeUrl(config)
    await session.update((prev) => ({ ...prev!, auth: authRequest, returnTo }))
    return c.json({ url: url.toString() })
  })

  auth.get("/callback", async (c) => {
    const session = c.get("session")
    const error = c.req.query("error")
    if (error) {
      return c.redirect(`${appUrl}?error=${encodeURIComponent(error)}`)
    }

    const code = c.req.query("code")
    const state = c.req.query("state")
    if (!code || !state) {
      return c.redirect(`${appUrl}?error=missing_params`)
    }

    const data = await session.get()
    const savedAuth = data?.auth
    if (!savedAuth) {
      return c.redirect(`${appUrl}?error=invalid_state`)
    }

    try {
      const config = await getOIDCConfig()
      const callbackUrl = new URL(getRedirectUri())
      callbackUrl.search = new URL(c.req.url).search
      const { tokens, sub } = await exchangeCode(config, callbackUrl, {
        expectedState: savedAuth.state,
        expectedNonce: savedAuth.nonce,
        pkceCodeVerifier: savedAuth.codeVerifier,
      })

      const user = await fetchUserInfo(config, tokens.access_token, sub)
      await opts.onLogin?.(user)
      const token_expires_at =
        Math.floor(Date.now() / 1000) + (tokens.expires_in ?? 3600)
      // The PKCE request is spent; a fresh login always starts a new one.
      await session.update((prev) => ({
        ...prev!,
        auth: undefined,
        returnTo: undefined,
        tokens,
        user,
        sub,
        token_expires_at,
      }))
      return c.redirect(landing(data?.returnTo))
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.error("[auth] Token exchange error:", msg)
      return c.redirect(`${appUrl}?error=token_exchange`)
    }
  })

  auth.get("/api/auth/me", async (c) => {
    if (authMode === "cookie") {
      const cookie = c.req.header("cookie")
      const user = cookie
        ? await fetchUserByCookie(cookie).catch(() => null)
        : null
      if (user) await opts.onLogin?.(user)
      return c.json({ user })
    }

    const data = await c.get("session").get()
    return c.json({ user: data?.user ?? null })
  })

  auth.post("/api/auth/logout", async (c) => {
    const cookie = c.req.header("cookie")
    if (authMode === "cookie" && cookie) {
      await signOutHub(cookie, new URL(appUrl).origin)
    }
    c.get("session").delete()
    return c.json({ ok: true })
  })

  return auth
}
