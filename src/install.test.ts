import { afterEach, describe, expect, test } from "bun:test"
import { InstallError, installInstance } from "./identity"

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

function mockFetch(
  responses: Record<string, Response>,
  calls: Array<{ url: string; body: unknown }>
) {
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    calls.push({ url, body: init?.body ? JSON.parse(String(init.body)) : null })
    const path = new URL(url).pathname
    return responses[path] ?? new Response("{}", { status: 500 })
  }) as typeof fetch
}

describe("installInstance", () => {
  test("creates the instance by slug, then enrolls it", async () => {
    const calls: Array<{ url: string; body: unknown }> = []
    mockFetch(
      {
        "/api/o/org1/module-instance": Response.json({ enrollmentToken: "rth_e_x" }),
        "/api/module-enroll": Response.json({
          instance_id: "inst1",
          instance_name: "main",
          organization_id: "org1",
          module_slug: "cron",
        }),
      },
      calls
    )

    const identity = await installInstance(
      "https://hub.test",
      { Authorization: "Bearer t" },
      "org1",
      { slug: "cron", name: "main" }
    )

    expect(identity.instanceId).toBe("inst1")
    expect(identity.privateKey.length).toBeGreaterThan(0)
    expect(calls[0].body).toEqual({ slug: "cron", name: "main" })
    expect((calls[1].body as { token: string }).token).toBe("rth_e_x")
  })

  test.each([
    [401, "session_expired"],
    [404, "not_found"],
    [403, "failed"],
  ] as const)("maps HTTP %d to %s", async (status, code) => {
    mockFetch(
      { "/api/o/org1/module-instance": Response.json({ error: "nope" }, { status }) },
      []
    )
    const err = await installInstance("https://hub.test", {}, "org1", {
      slug: "cron",
      name: "main",
    }).catch((e) => e)
    expect(err).toBeInstanceOf(InstallError)
    expect(err.code).toBe(code)
  })
})
