import { signChallenge, type RawtohIdentity } from "./identity"
import { WsClient } from "./ws"

// Close codes sent by the hub. Mirrors `apps/rpc/src/close-codes.ts`.
/** The user asked to disconnect this module. Do not reconnect. */
export const CLOSE_DISCONNECT_REQUESTED = 4000
/** The instance was re-enrolled against another key pair. Do not reconnect. */
export const CLOSE_KEY_ROTATED = 4001

export type DisconnectReason = "disconnect-requested" | "key-rotated"

export interface HubConnectionOptions {
  /** WebSocket URL of the hub (`RAWTOH_WS_URL`). */
  url: string
  identity: RawtohIdentity
  /** Shown in log lines, e.g. the account name. */
  label?: string
  /**
   * Register the module's JSON-RPC methods on a fresh socket. Called before
   * `session.challenge`, so the hub's subscribe phase finds them.
   */
  onOpen: (client: WsClient, hub: HubConnection) => void
  /** The socket dropped; subscriptions are already cleared. */
  onDisconnect?: () => void
  /**
   * Connection state changed. `reason` is set when the hub refused
   * reconnection and the loop has stopped for good.
   */
  onStatus?: (connected: boolean, reason: DisconnectReason | null) => void
}

/**
 * One enrolled instance's connection to the hub: challenge/response
 * registration, reconnect with exponential backoff, and the subscription
 * table `event.subscribe` fills in.
 */
export class HubConnection {
  /** Subscription id → event name, as returned by the module on `event.subscribe`. */
  readonly subscriptions = new Map<string, string>()
  client: WsClient | null = null
  /** Why the hub last refused reconnection, until the next `start()`. */
  reason: DisconnectReason | null = null
  private stopping = false

  constructor(private readonly opts: HubConnectionOptions) {}

  get connected(): boolean {
    return !this.stopping && this.client !== null
  }

  /**
   * The first attempt runs in-band so callers get immediate feedback; the
   * reconnect loop then continues in the background.
   */
  async start(): Promise<void> {
    await this.connectOnce()
    this.reason = null
    this.opts.onStatus?.(true, null)
    void this.loop()
  }

  /** Close the socket and stop reconnecting. */
  stop(): void {
    this.stopping = true
    this.client?.terminate()
    this.client = null
    this.reason = null
  }

  /**
   * Push an event to the hub for every subscription on `eventName`.
   * `emittedBy` is the rawtoh user id behind the event, when a human is in the loop.
   */
  emit(eventName: string, result: unknown, emittedBy?: string): void {
    if (!this.client) return
    for (const [subscription, name] of this.subscriptions) {
      if (name !== eventName) continue
      this.client.notify(
        "event.subscription",
        emittedBy
          ? { subscription, result, emitted_by: emittedBy }
          : { subscription, result }
      )
    }
  }

  private log(message: string): void {
    const tag = this.opts.label ? `ws:${this.opts.label}` : "ws"
    console.log(`[${tag}] ${message}`)
  }

  private async connectOnce(): Promise<void> {
    const { url, identity } = this.opts
    this.log(`Connecting to ${url}...`)
    const client = await WsClient.connect(url)
    this.opts.onOpen(client, this)

    // The hub issues a nonce, we sign it with the key generated at enrollment.
    // Both calls must land inside the hub's 5s registration window.
    const challenge = (await client.request("session.challenge", {
      instance_id: identity.instanceId,
    })) as { nonce?: string }
    if (!challenge?.nonce) {
      client.close()
      throw new Error("Hub returned no challenge")
    }

    const result = await client.request("session.register", {
      instance_id: identity.instanceId,
      signature: await signChallenge(identity, challenge.nonce),
    })
    if (result !== true) {
      client.close()
      throw new Error("Registration rejected")
    }

    this.log("Registered successfully")
    this.client = client
  }

  private async loop(): Promise<void> {
    let delaySecs = 1

    while (!this.stopping) {
      const client = this.client
      if (!client) return

      const code = await client.waitClosed()
      this.log(`Disconnected (code: ${code})`)
      this.client = null
      this.subscriptions.clear()
      this.opts.onDisconnect?.()

      if (code === CLOSE_KEY_ROTATED || code === CLOSE_DISCONNECT_REQUESTED) {
        this.reason =
          code === CLOSE_KEY_ROTATED ? "key-rotated" : "disconnect-requested"
        this.log(`Close code ${code} — not reconnecting`)
      }
      if (!this.stopping) this.opts.onStatus?.(false, this.reason)
      if (this.reason) return

      while (!this.stopping) {
        this.log(`Reconnecting in ${delaySecs}s...`)
        await new Promise((r) => setTimeout(r, delaySecs * 1000))
        delaySecs = Math.min(delaySecs * 2, 64)
        if (this.stopping) return

        try {
          await this.connectOnce()
          delaySecs = 1
          this.opts.onStatus?.(true, null)
          break
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          console.error(
            `[ws:${this.opts.label ?? ""}] Connection error: ${msg}`
          )
          this.client = null
        }
      }
    }
  }
}
