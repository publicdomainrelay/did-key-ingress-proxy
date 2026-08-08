import { upgradeWebSocket } from "@hono/hono/deno";
import { cors } from "@hono/hono/cors";
import { createFactory } from "@hono/hono/factory";
import { createStructuredLogger } from "@publicdomainrelay/logger";
const log = createStructuredLogger("relay");
import {
  hostnameOnly,
  hostnameToDid,
  didToSubdomain,
  SUBSCRIBE_NSID,
  GET_NONCE_NSID,
} from "@publicdomainrelay/did-key-ingress-proxy-common";
import { RelayState } from "@publicdomainrelay/did-key-ingress-proxy-abc";
import {
  createNonceStore,
  verifyServiceAuth,
} from "@publicdomainrelay/did-key-ingress-proxy-xrpc";

function encodeBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function decodeBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export interface RelayFactoryOptions {
  hostname: string;
  serviceId?: string;
  relayTimeoutMs?: number;
  /** How often to probe each registered subscriber for liveness (ms). */
  keepaliveMs?: number;
  /** How long a keepalive probe may take before the subscriber is evicted (ms). */
  keepaliveTimeoutMs?: number;
  reconnectGraceMs?: number;
  nonceTtlMs?: number;
  /**
   * Extra base hostnames accepted on the control endpoints (getNonce,
   * subscribe). Lets a subscriber that reaches the relay via a different
   * address (e.g. a container dialing the host gateway IP) still register,
   * while data routing stays keyed to `hostname`. Default: none.
   */
  additionalHosts?: string[];
  /**
   * If non-empty, only these DIDs may register as subscribers on the relay.
   * Empty (default) means any DID with a valid registration is accepted.
   */
  allowedDids?: string[];
  /**
   * Resolve a non-did:key DID (e.g. did:plc) to its atproto signing key
   * (a did:key string). When omitted, only did:key DIDs are accepted.
   */
  resolveDidKey?: (did: string) => Promise<string>;
}

export function createRelayFactory(opts: RelayFactoryOptions) {
  const hostname = opts.hostname;
  const additionalHosts = opts.additionalHosts ?? [];
  const allowAllHosts = additionalHosts.includes("*");
  const allowedDids = opts.allowedDids ?? [];
  // HTTP/2 requests carry :authority instead of a Host header; Deno exposes
  // the authority via the request URL, so fall back to that before assuming
  // the configured hostname.
  const isControlHost = (host: string): boolean =>
    allowAllHosts || host === hostname || additionalHosts.includes(host);
  const serviceId = opts.serviceId ?? "xrpc_relay";
  const relayTimeoutMs = opts.relayTimeoutMs ?? 30_000;
  const reconnectGraceMs = opts.reconnectGraceMs ?? 10_000;
  const nonceTtlMs = opts.nonceTtlMs ?? 60_000;

  const state = new RelayState({
    relayTimeoutMs,
    reconnectGraceMs,
    onSendFrame: (ws, frame) => { ws.send(frame); },
    onCloseConnection: (ws, code, reason) => { ws.close(code, reason); },
  });
  const nonceStore = createNonceStore({ ttlMs: nonceTtlMs, resolveDidKey: opts.resolveDidKey });

  // -- Subscriber keepalive --------------------------------------------------
  // Probe each registered subscriber periodically with a lightweight request.
  // Any response (even 404) proves the connection is alive; a timeout is
  // handled by RelayState.dispatchRequest, which evicts the dead subscriber so
  // its client reconnects. Detects half-open WSS connections that would
  // otherwise fail silently (Deno's WebSocket has no WS-level ping).
  const keepaliveMs = opts.keepaliveMs ?? 5_000;
  const keepaliveTimeoutMs = opts.keepaliveTimeoutMs ?? 5_000;
  const keepaliveIntervals = new Map<string, ReturnType<typeof setInterval>>();

  function startSubscriberKeepalive(subdomain: string): void {
    if (keepaliveIntervals.has(subdomain)) return;
    const interval = setInterval(() => {
      const subWs = state.subscribers.get(subdomain);
      if (!subWs || subWs.readyState !== WebSocket.OPEN) {
        clearInterval(interval);
        keepaliveIntervals.delete(subdomain);
        return;
      }
      const requestId = crypto.randomUUID();
      state.dispatchRequest(subdomain, requestId, JSON.stringify({
        $type: `${SUBSCRIBE_NSID}#request`,
        requestId,
        method: "GET",
        path: "/xrpc/com.publicdomainrelay.temp.keepalive.ping",
        params: {},
        body: null,
        headers: {},
      }), keepaliveTimeoutMs).then(
        () => {}, // responded (any status) — alive
        () => {}, // timed out — dispatchRequest already evicted + closed it
      );
    }, keepaliveMs);
    keepaliveIntervals.set(subdomain, interval);
  }

  function stopSubscriberKeepalive(subdomain: string): void {
    const iv = keepaliveIntervals.get(subdomain);
    if (iv) {
      clearInterval(iv);
      keepaliveIntervals.delete(subdomain);
    }
  }

  return createFactory({
    initApp: (app) => {
      app.use("*", cors());

      app.get("/.well-known/did.json", (c, next) => {
        const host = hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host);
        if (host !== hostname && !additionalHosts.includes(host)) return next();
        return c.json({
          "@context": ["https://www.w3.org/ns/did/v1"],
          id: `did:web:${hostname}`,
          service: [{
            id: `#${serviceId}`,
            type: "XrpcRelay",
            serviceEndpoint: `https://${hostname}`,
          }],
        });
      });

      app.use("*", async (c, next) => {
        const method = c.req.method;
        const path = new URL(c.req.url).pathname;
        log.info("request", { component: "relay", method, path });
        await next();
        const status = c.res.status;
        if (status >= 400) {
          let responseBody: unknown;
          try {
            const text = await c.res.clone().text();
            try { responseBody = JSON.parse(text); } catch { responseBody = text; }
          } catch { responseBody = null; }
          log.error("response_error", { component: "relay", method, path, status, responseBody });
        }
      });

      app.post(`/xrpc/${GET_NONCE_NSID}`, async (c, next) => {
        if (!isControlHost(hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host))) return next();
        try {
          await verifyServiceAuth(c.req.header("Authorization"), hostnameToDid(hostname), GET_NONCE_NSID);
        } catch (err) {
          log.warn("auth_denied", { component: "relay", nsid: GET_NONCE_NSID, error: String(err) });
          return c.json({ error: "AuthenticationRequired", message: String(err) }, 401);
        }
        let input: { key?: string };
        try { input = await c.req.json(); } catch { input = {}; }
        if (!input.key || typeof input.key !== "string" || !input.key.startsWith("did:")) {
          return c.json({ error: "InvalidRequest", message: "key must be a DID" }, 400);
        }
        const nonce = nonceStore.issue(input.key);
        log.info("nonce_issued", { component: "relay", key: input.key });
        return c.json({ nonce, signatures: [] });
      });

      const wsSubscribeHandler = upgradeWebSocket((c) => {
        const serviceHost = hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host);
        const registrationParam = c.req.query("registration") ?? "";
        const clientDid = c.req.query("did") ?? "";
        const subdomain = didToSubdomain(clientDid);

        return {
          async onOpen(_evt, ws) {
            const raw = ws.raw as WebSocket;
            if (!clientDid.startsWith("did:")) {
              log.warn("missing_did", { component: "relay" });
              raw.close(1008, "did query param must be a DID");
              return;
            }
            let reg: { key?: string; nonce?: string; signatures?: Array<{ key?: string; signature?: string }> };
            try { reg = JSON.parse(registrationParam); } catch {
              log.warn("registration_malformed", { component: "relay", did: clientDid });
              raw.close(1008, "malformed registration");
              return;
            }
            const result = await nonceStore.verify(reg);
            if (!result.ok) {
              log.warn("registration_rejected", { component: "relay", did: clientDid, reason: result.reason });
              raw.close(1008, `registration rejected: ${result.reason}`);
              return;
            }
            if (result.key !== clientDid) {
              log.warn("did_mismatch", { component: "relay", did: clientDid, registrationKey: result.key });
              raw.close(1008, "did does not match registration key");
              return;
            }
            if (allowedDids.length && !allowedDids.includes(clientDid)) {
              log.warn("did_not_allowed", { component: "relay", did: clientDid });
              raw.close(1008, "DID not in allowlist");
              return;
            }
            state.subscribers.set(subdomain, raw);
            log.info("subscriber_connected", { component: "relay", subdomain, key: result.key });
            state.flushReconnectQueue(subdomain, raw);
            startSubscriberKeepalive(subdomain);
            raw.send(JSON.stringify({
              $type: `${SUBSCRIBE_NSID}#registered`,
              subdomain,
              ingressRef: `did:web:${subdomain}.${serviceHost}`,
            }));
          },

          onMessage(evt) {
            let msg: Record<string, unknown>;
            try { msg = JSON.parse(evt.data as string) as Record<string, unknown>; } catch { return; }
            const $type = msg.$type as string | undefined;
            if (!$type || !$type.startsWith(`${SUBSCRIBE_NSID}#`)) return;
            const kind = $type.slice($type.indexOf("#") + 1);
            switch (kind) {
              case "response": {
                const requestId = msg.requestId as string | undefined;
                if (!requestId) return;
                state.handleResponse(requestId, msg.status as number, msg.body, msg.contentType as string | undefined);
                break;
              }
              case "subscriptionOpen":
                break;
              case "subscriptionEvent": {
                const subId = msg.subscriptionId as string | undefined;
                if (!subId) return;
                const sub = state.activeSubscriptions.get(subId);
                if (!sub || sub.callerWs.readyState !== WebSocket.OPEN) return;
                sub.callerWs.send(JSON.stringify(msg.message));
                break;
              }
              case "subscriptionData": {
                const subId = msg.subscriptionId as string | undefined;
                if (!subId) return;
                const sub = state.activeSubscriptions.get(subId);
                if (!sub || sub.callerWs.readyState !== WebSocket.OPEN) return;
                const data = msg.data as string | undefined;
                if (typeof data !== "string") return;
                sub.callerWs.send(decodeBase64(data));
                break;
              }
              case "subscriptionClose": {
                const subId = msg.subscriptionId as string | undefined;
                if (!subId) return;
                const sub = state.activeSubscriptions.get(subId);
                if (sub && sub.callerWs.readyState === WebSocket.OPEN) {
                  sub.callerWs.close((msg.code as number) ?? 1000, msg.reason as string | undefined);
                }
                state.activeSubscriptions.delete(subId);
                break;
              }
            }
          },

          onClose() {
            state.subscribers.delete(subdomain);
            state.drainToReconnectQueue(subdomain);
            state.rejectSubscriberSubscriptions(subdomain);
            stopSubscriberKeepalive(subdomain);
            log.info("subscriber_disconnected", { component: "relay", subdomain });
          },

          onError() {
            state.subscribers.delete(subdomain);
            state.drainToReconnectQueue(subdomain);
            state.rejectSubscriberSubscriptions(subdomain);
            stopSubscriberKeepalive(subdomain);
          },
        };
      });

      app.get(`/xrpc/${SUBSCRIBE_NSID}`, async (c, next) => {
        if (!isControlHost(hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host))) return next();
        try {
          const serviceAuth = c.req.query("service_auth");
          await verifyServiceAuth(c.req.header("Authorization"), hostnameToDid(hostname), SUBSCRIBE_NSID, serviceAuth);
        } catch (err) {
          log.warn("auth_denied", { component: "relay", nsid: SUBSCRIBE_NSID, error: String(err) });
          return c.json({ error: "AuthenticationRequired", message: String(err) }, 401);
        }
        return wsSubscribeHandler(c, next);
      });

      const wsRelaySubscriptionHandler = upgradeWebSocket((c) => {
        const host = hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host);
        const subdomain = host.slice(0, -`.${hostname}`.length);
        const path = new URL(c.req.url).pathname;
        const nsid = path.startsWith("/xrpc/") ? path.slice("/xrpc/".length) : path;
        const params = Object.fromEntries(new URL(c.req.url).searchParams.entries());
        const subscriptionId = crypto.randomUUID();

        return {
          onOpen(_evt, ws) {
            const raw = ws.raw as WebSocket;
            raw.binaryType = "arraybuffer";
            const subWs = state.subscribers.get(subdomain);
            if (!subWs || subWs.readyState !== WebSocket.OPEN) {
              raw.close(4004, `no active subscriber for subdomain ${subdomain}`);
              return;
            }
            state.activeSubscriptions.set(subscriptionId, { callerWs: raw, subdomain, nsid });
            subWs.send(JSON.stringify({
              $type: `${SUBSCRIBE_NSID}#subscribe`,
              subscriptionId,
              nsid,
              params,
            }));
          },

          onMessage(evt) {
            const sub = state.activeSubscriptions.get(subscriptionId);
            if (!sub) return;
            const subWs = state.subscribers.get(subdomain);
            if (!subWs || subWs.readyState !== WebSocket.OPEN) return;
            const data = evt.data;
            let bytes: Uint8Array | null = null;
            if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
            else if (typeof data === "string") bytes = new TextEncoder().encode(data);
            if (!bytes) return;
            subWs.send(JSON.stringify({
              $type: `${SUBSCRIBE_NSID}#subscriptionData`,
              subscriptionId,
              data: encodeBase64(bytes),
            }));
          },

          onClose() {
            const sub = state.activeSubscriptions.get(subscriptionId);
            if (!sub) return;
            state.activeSubscriptions.delete(subscriptionId);
            const subWs = state.subscribers.get(sub.subdomain);
            if (subWs && subWs.readyState === WebSocket.OPEN) {
              subWs.send(JSON.stringify({
                $type: `${SUBSCRIBE_NSID}#subscriptionCancel`,
                subscriptionId,
                reason: "caller disconnected",
              }));
            }
          },

          onError() {
            state.activeSubscriptions.delete(subscriptionId);
          },
        };
      });

      app.get("/xrpc/*", async (c, next) => {
        const host = hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host);
        if (!host.endsWith(`.${hostname}`)) return next();
        if (c.req.header("upgrade")?.toLowerCase() !== "websocket") return next();
        return wsRelaySubscriptionHandler(c, next);
      });

      app.all("*", async (c) => {
        const rawHost = hostnameOnly(c.req.header("host") ?? new URL(c.req.url).host);
        const dataHosts = [hostname, ...additionalHosts];
        const hostMatch = dataHosts.some((h) => rawHost.endsWith(`.${h}`));
        if (!hostMatch) return c.notFound();

        const baseDot = `.${dataHosts.find((h) => rawHost.endsWith(`.${h}`))!}`;

        const subdomain = rawHost.slice(0, rawHost.length - baseDot.length);
        const path = new URL(c.req.url).pathname;

        let body: unknown = undefined;
        if (!["GET", "HEAD"].includes(c.req.method)) {
          try { body = await c.req.json(); } catch { body = null; }
        }

        const params = Object.fromEntries(new URL(c.req.url).searchParams.entries());
        const requestId = crypto.randomUUID();
        const headers: Record<string, string> = {};
        for (const [k, v] of c.req.raw.headers.entries()) headers[k] = v;
        const frame = JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#request`,
          requestId,
          method: c.req.method,
          path,
          params,
          body,
          headers,
        });

        let result;
        try {
          result = await state.dispatchRequest(subdomain, requestId, frame);
        } catch (err) {
          const msg = String(err);
          if (msg.includes("no active subscriber")) {
            return c.json({ error: "NotFound", message: msg }, 404);
          }
          log.error("relay_failed", { component: "relay", path, subdomain, error: msg });
          return c.json({ error: "RelayError", message: msg }, 502);
        }

        const ct = result.contentType ?? "application/json";
        const responseBody = typeof result.body === "string" ? result.body : JSON.stringify(result.body);
        return new Response(responseBody, { status: result.status, headers: { "content-type": ct } });
      });
    },
  });
}
