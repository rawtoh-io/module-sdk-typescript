import { describe, expect, test } from "bun:test"
import { fromBase64Url, toBase64Url } from "./base64url"
import { signChallenge } from "./identity"

// The signed bytes are the contract with the hub's `packages/module-auth`.
describe("signChallenge", () => {
  test("produces a signature the hub can verify over the v1 format", async () => {
    const pair = (await crypto.subtle.generateKey("Ed25519", true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair
    const identity = {
      instanceId: "inst_123",
      privateKey: toBase64Url(
        new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))
      ),
    }

    const signature = fromBase64Url(await signChallenge(identity, "n0nce"))
    expect(signature.length).toBe(64)

    const message = new TextEncoder().encode(
      "rawtoh-module-register:v1\ninst_123\nn0nce"
    )
    expect(
      await crypto.subtle.verify("Ed25519", pair.publicKey, signature, message)
    ).toBe(true)
    expect(
      await crypto.subtle.verify(
        "Ed25519",
        pair.publicKey,
        signature,
        new TextEncoder().encode("rawtoh-module-register:v1\ninst_123\nother")
      )
    ).toBe(false)
  })
})
