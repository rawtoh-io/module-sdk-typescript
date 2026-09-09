// Ed25519 enrollment and challenge signing.
//
// A module generates its own key pair and never sends the private half
// anywhere. Enrollment binds the public half to a Rawtoh instance once; from
// then on, connecting means signing a nonce the hub issues.
//
// The signed byte format is a protocol contract with the hub
// (`packages/module-auth` there). Changing it here alone locks every module out.

import { fromBase64Url, toBase64Url } from "./base64url"

const CHALLENGE_CONTEXT = "rawtoh-module-register:v1"

/** What a module keeps per enrolled instance. */
export interface RawtohIdentity {
  instanceId: string
  /** Ed25519 private key, PKCS#8, base64url. Never leaves the module. */
  privateKey: string
}

export interface EnrollResult extends RawtohIdentity {
  instanceName: string
  organizationId: string
  moduleSlug: string
}

/**
 * Redeem an enrollment token: generate a key pair, hand the hub the public
 * half, keep the private half. The token is spent by the time this returns —
 * on failure the caller needs a fresh one rather than a retry.
 */
export async function enroll(
  apiUrl: string,
  enrollmentToken: string
): Promise<EnrollResult> {
  const token = enrollmentToken.trim()

  const pair = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair
  const publicKey = toBase64Url(
    new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))
  )

  const res = await fetch(`${apiUrl}/api/module-enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, public_key: publicKey }),
  })

  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string }
    throw new Error(body.error || `Enrollment failed (${res.status})`)
  }

  const data = (await res.json()) as {
    instance_id: string
    instance_name: string
    organization_id: string
    module_slug: string
  }

  return {
    instanceId: data.instance_id,
    privateKey: toBase64Url(
      new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))
    ),
    instanceName: data.instance_name,
    organizationId: data.organization_id,
    moduleSlug: data.module_slug,
  }
}

/** Sign a `session.challenge` nonce with the instance's private key. */
export async function signChallenge(
  identity: RawtohIdentity,
  nonce: string
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    fromBase64Url(identity.privateKey),
    "Ed25519",
    false,
    ["sign"]
  )
  const message = new TextEncoder().encode(
    `${CHALLENGE_CONTEXT}\n${identity.instanceId}\n${nonce}`
  )
  return toBase64Url(
    new Uint8Array(await crypto.subtle.sign("Ed25519", key, message))
  )
}
