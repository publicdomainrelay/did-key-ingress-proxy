import { createStructuredLogger } from "@publicdomainrelay/logger";
import {
  hostnameOnly,
  didToSubdomain,
  SUBSCRIBE_NSID,
  GET_NONCE_NSID,
  TUNNEL_NSID,
  summarizeFrame,
} from "@publicdomainrelay/did-key-relay-common";
import type {
  SubscriberOptions,
  SubscriberHandle,
  CallerOptions,
  CallerHandle,
} from "@publicdomainrelay/did-key-relay-subscriber-abc";
import type { RelayRequest } from "@publicdomainrelay/did-key-relay-common";
const log = createStructuredLogger("subscriber");

export interface RelayRequestResult {
  status: number;
  body: unknown;
  contentType: string;
}

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

async function writeAll(conn: Deno.Conn, data: Uint8Array): Promise<void> {
  let off = 0;
  while (off < data.length) off += await conn.write(data.subarray(off));
}

function httpOrigin(host: string): string {
  if (host.includes(":") || host === "localhost") return `http://${host}`;
  return `https://${host}`;
}

function wsOrigin(host: string): string {
  if (host.includes(":") || host === "localhost") return `ws://${host}`;
  return `wss://${host}`;
}

export async function createSubscriber(
  opts: SubscriberOptions,
): Promise<SubscriberHandle> {
  const label = opts.label ?? "subscriber";
  const did = opts.keypair.did();
  const subdomain = didToSubdomain(did);
  const hostname = hostnameOnly(opts.dispatcherHost);
  const proxyRef = `did:web:${subdomain}.${hostname}`;

  // `ws` is reassigned on every reconnect; helpers/handlers below read the
  // current socket through this binding. Registration (nonce -> sign -> connect)
  // re-runs each attempt since the nonce is single-use.
  let ws!: WebSocket;
  let closed = false;
  let everRegistered = false;
  let reconnectAttempts = 0;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  const syntheticIntervals = new Set<ReturnType<typeof setInterval>>();

  interface TunnelState { conn?: Deno.Conn; queue: Uint8Array[]; closed: boolean; }
  const tunnels = new Map<string, TunnelState>();
  const wsSubs = new Map<string, WebSocket>();
  const directSubs = new Map<string, () => void>();

  function closeTunnel(subscriptionId: string): void {
    const t = tunnels.get(subscriptionId);
    if (t) {
      t.closed = true;
      tunnels.delete(subscriptionId);
      if (t.conn) { try { t.conn.close(); } catch { /* already closed */ } }
    }
    const localWs = wsSubs.get(subscriptionId);
    if (localWs) {
      wsSubs.delete(subscriptionId);
      try { localWs.close(); } catch { /* already closed */ }
    }
  }

  function startWsSubscription(
    subscriptionId: string,
    nsid: string,
    params: Record<string, string>,
  ): void {
    const target = opts.wsTarget?.();
    if (!target) return;
    const qs = new URLSearchParams(params ?? {}).toString();
    const url = `ws://${target.hostname}:${target.port}/xrpc/${nsid}${qs ? `?${qs}` : ""}`;
    let local: WebSocket;
    try {
      local = new WebSocket(url);
    } catch (err) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#subscriptionClose`,
          subscriptionId,
          code: 1011,
          reason: String(err),
        }));
      }
      return;
    }
    local.binaryType = "arraybuffer";
    wsSubs.set(subscriptionId, local);
    local.onopen = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ $type: `${SUBSCRIBE_NSID}#subscriptionOpen`, subscriptionId }));
      }
    };
    local.onmessage = (evt) => {
      if (ws.readyState !== WebSocket.OPEN) return;
      const data = evt.data;
      if (typeof data === "string") {
        let message: unknown;
        try { message = JSON.parse(data); } catch { return; }
        ws.send(JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#subscriptionEvent`,
          subscriptionId,
          message,
        }));
      } else if (data instanceof ArrayBuffer) {
        ws.send(JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#subscriptionData`,
          subscriptionId,
          data: encodeBase64(new Uint8Array(data)),
        }));
      }
    };
    local.onclose = (evt) => {
      wsSubs.delete(subscriptionId);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#subscriptionClose`,
          subscriptionId,
          code: evt.code || 1000,
          reason: evt.reason,
        }));
      }
    };
    local.onerror = () => { /* close follows */ };
  }

  function tunnelInbound(subscriptionId: string, bytes: Uint8Array): void {
    const t = tunnels.get(subscriptionId);
    if (!t) return;
    if (t.conn) writeAll(t.conn, bytes).catch(() => closeTunnel(subscriptionId));
    else t.queue.push(bytes); // conn not ready yet; flush on open
  }

  async function startTunnel(subscriptionId: string): Promise<void> {
    const target = opts.tunnelTarget!;
    // Register synchronously so inbound data frames (which can arrive before
    // Deno.connect resolves) are queued, not dropped.
    const t: TunnelState = { queue: [], closed: false };
    tunnels.set(subscriptionId, t);
    let conn: Deno.Conn;
    try {
      conn = await Deno.connect({ hostname: target.hostname, port: target.port });
    } catch (err) {
      tunnels.delete(subscriptionId);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#subscriptionClose`,
          subscriptionId,
          code: 1011,
          reason: String(err),
        }));
      }
      return;
    }
    if (t.closed) { try { conn.close(); } catch { /* ok */ } return; }
    t.conn = conn;
    try {
      for (const chunk of t.queue) await writeAll(conn, chunk);
    } catch { closeTunnel(subscriptionId); return; }
    t.queue.length = 0;
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ $type: `${SUBSCRIBE_NSID}#subscriptionOpen`, subscriptionId }));
    }
    const buf = new Uint8Array(64 * 1024);
    try {
      while (true) {
        const n = await conn.read(buf);
        if (n === null) break;
        if (ws.readyState !== WebSocket.OPEN) break;
        ws.send(JSON.stringify({
          $type: `${SUBSCRIBE_NSID}#subscriptionData`,
          subscriptionId,
          data: encodeBase64(buf.subarray(0, n)),
        }));
      }
    } catch { /* connection closed */ }
    closeTunnel(subscriptionId);
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ $type: `${SUBSCRIBE_NSID}#subscriptionClose`, subscriptionId, code: 1000 }));
    }
  }

  function handleFrame(msg: Record<string, unknown>): void {
    const $type = msg.$type as string | undefined;
    if (!$type?.startsWith(`${SUBSCRIBE_NSID}#`)) return;
    const kind = $type.slice($type.indexOf("#") + 1);
    switch (kind) {
      case "request": {
        if (opts.handleRequest) {
          const req: RelayRequest = {
            requestId: msg.requestId as string,
            method: msg.method as string,
            path: msg.path as string,
            params: (msg.params as Record<string, string>) ?? {},
            body: msg.body,
            headers: (msg.headers as Record<string, string>) ?? {},
          };
          opts.handleRequest(req).then(
            (result) => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                  $type: `${SUBSCRIBE_NSID}#response`,
                  requestId: msg.requestId,
                  status: result.status,
                  body: result.body,
                  contentType: result.contentType,
                }));
              }
            },
            (err) => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                  $type: `${SUBSCRIBE_NSID}#response`,
                  requestId: msg.requestId,
                  status: 500,
                  body: { error: "InternalError", message: String(err) },
                  contentType: "application/json",
                }));
              }
            },
          );
        }
        break;
      }
      case "subscribe": {
        const subNsid = msg.nsid as string | undefined;
        if (opts.tunnelTarget && subNsid === TUNNEL_NSID) {
          void startTunnel(msg.subscriptionId as string);
          break;
        }
        if (opts.wsTarget && subNsid && subNsid !== TUNNEL_NSID) {
          startWsSubscription(
            msg.subscriptionId as string,
            subNsid,
            (msg.params as Record<string, string>) ?? {},
          );
          break;
        }
        if (opts.directSubscriptionHandler && subNsid && subNsid !== TUNNEL_NSID) {
          const subscriptionId = msg.subscriptionId as string;
          const params = (msg.params as Record<string, string>) ?? {};
          const unsub = opts.directSubscriptionHandler(
            subscriptionId,
            subNsid,
            params,
            (event) => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                  $type: `${SUBSCRIBE_NSID}#subscriptionEvent`,
                  subscriptionId,
                  message: event,
                }));
              }
            },
            (data) => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({
                  $type: `${SUBSCRIBE_NSID}#subscriptionData`,
                  subscriptionId,
                  data: encodeBase64(data),
                }));
              }
            },
          );
          if (unsub) directSubs.set(subscriptionId, unsub);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              $type: `${SUBSCRIBE_NSID}#subscriptionOpen`,
              subscriptionId,
            }));
          }
          break;
        }
        if (opts.synthetic) {
          const subscriptionId = msg.subscriptionId as string;
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({
              $type: `${SUBSCRIBE_NSID}#subscriptionOpen`,
              subscriptionId,
            }));
          }
          let seq = 0;
          const interval = setInterval(() => {
            if (ws.readyState !== WebSocket.OPEN) {
              clearInterval(interval);
              syntheticIntervals.delete(interval);
              return;
            }
            ws.send(JSON.stringify({
              $type: `${SUBSCRIBE_NSID}#subscriptionEvent`,
              subscriptionId,
              message: {
                seq: seq++,
                time: new Date().toISOString(),
                event: "synthetic",
              },
            }));
          }, 5000);
          syntheticIntervals.add(interval);
        }
        break;
      }
      case "subscriptionData": {
        const subscriptionId = msg.subscriptionId as string | undefined;
        if (subscriptionId && typeof msg.data === "string") {
          tunnelInbound(subscriptionId, decodeBase64(msg.data));
        }
        break;
      }
      case "subscriptionCancel":
      case "subscriptionClose": {
        const subscriptionId = msg.subscriptionId as string | undefined;
        if (subscriptionId) {
          closeTunnel(subscriptionId);
          const directUnsub = directSubs.get(subscriptionId);
          if (directUnsub) { directSubs.delete(subscriptionId); try { directUnsub(); } catch { /* ignore */ } }
        }
        break;
      }
    }
  }

  // One full registration attempt: fetch a fresh single-use nonce, sign it,
  // open the dispatcher WebSocket, and resolve once `#registered` arrives. On
  // close after a prior successful registration, schedule a reconnect.
  function openOnce(): Promise<void> {
    return (async () => {
      const nonceToken = await opts.getServiceAuthToken(GET_NONCE_NSID);
      const nonceRes = await fetch(`${httpOrigin(opts.dispatcherHost)}/xrpc/${GET_NONCE_NSID}`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${nonceToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ key: did, signatures: [] }),
      });
      if (!nonceRes.ok) {
        const err = await nonceRes.text();
        throw new Error(`nonce request failed: ${nonceRes.status} ${err}`);
      }
      const { nonce } = await nonceRes.json() as { nonce: string };
      const sig = await opts.keypair.sign(decodeBase64(nonce));
      const registration = JSON.stringify({
        $type: "com.fedproxy.temp.xrpc.registration",
        key: did,
        nonce,
        signatures: [{ key: did, signature: encodeBase64(sig) }],
      });
      const subscribeToken = await opts.getServiceAuthToken(SUBSCRIBE_NSID);
      const wsUrl = `${wsOrigin(opts.dispatcherHost)}/xrpc/${SUBSCRIBE_NSID}?registration=${
        encodeURIComponent(registration)
      }&did=${encodeURIComponent(did)}&service_auth=${encodeURIComponent(subscribeToken)}`;

      ws = new WebSocket(wsUrl);

      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const timeout = setTimeout(() => {
          if (!settled) { settled = true; reject(new Error("registration timeout")); }
        }, 30_000);
        ws.onopen = () => {
          log.info("ws_open", { component: label, host: opts.dispatcherHost });
        };
        ws.onmessage = (evt) => {
          let msg: Record<string, unknown>;
          try { msg = JSON.parse(evt.data as string) as Record<string, unknown>; } catch { return; }
          if (msg.$type === `${SUBSCRIBE_NSID}#registered`) {
            clearTimeout(timeout);
            everRegistered = true;
            reconnectAttempts = 0;
            if (!settled) { settled = true; resolve(); }
            return;
          }
          handleFrame(msg);
        };
        ws.onerror = (evt) => {
          log.error("ws_error", { component: label, error: String(evt) });
          if (!settled) {
            settled = true;
            clearTimeout(timeout);
            reject(new Error("WebSocket error during registration"));
          }
        };
        ws.onclose = (evt) => {
          log.info("ws_close", { component: label, code: evt.code, reason: evt.reason });
          for (const iv of syntheticIntervals) clearInterval(iv);
          syntheticIntervals.clear();
          for (const id of [...wsSubs.keys()]) closeTunnel(id);
          for (const id of [...tunnels.keys()]) closeTunnel(id);
          for (const [id, unsub] of directSubs) { directSubs.delete(id); try { unsub(); } catch { /* ignore */ } }
          if (!settled) {
            settled = true;
            clearTimeout(timeout);
            reject(new Error("closed before registration"));
          }
          if (everRegistered) scheduleReconnect();
        };
      });
    })();
  }

  function scheduleReconnect(): void {
    if (closed || reconnectTimer) return;
    const delay = Math.min(1000 * 2 ** reconnectAttempts, 30_000);
    reconnectAttempts++;
    log.info("ws_reconnect_scheduled", { component: label, delayMs: delay, attempt: reconnectAttempts });
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      if (closed) return;
      openOnce().catch((err) => {
        log.warn("ws_reconnect_failed", { component: label, error: String(err) });
        scheduleReconnect();
      });
    }, delay);
  }

  await openOnce();
  return {
    subdomain,
    proxyRef,
    get ws() { return ws; },
    close() {
      closed = true;
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      try { ws?.close(); } catch { /* already closed */ }
    },
  };
}

export interface TunnelClientOptions {
  dispatcherHost: string;
  subscriberSubdomain: string;
  nsid?: string;
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

/**
 * Bridge a local byte stream to a remote TCP target through the relay tunnel.
 * Pipes `readable` -> relay -> subscriber's tunnelTarget, and the target's
 * bytes back into `writable`. Resolves when the tunnel closes. Usable as an
 * SSH `ProxyCommand` (stdin/stdout) or to bridge an accepted TCP conn.
 */
export function tunnelOverRelay(opts: TunnelClientOptions): Promise<void> {
  const nsid = opts.nsid ?? TUNNEL_NSID;
  const host = `${opts.subscriberSubdomain}.${opts.dispatcherHost}`;
  const url = `${wsOrigin(host)}/xrpc/${nsid}`;
  return new Promise<void>((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    const writer = opts.writable.getWriter();
    let settled = false;
    const finish = (err?: unknown) => {
      if (settled) return;
      settled = true;
      writer.close().catch(() => {});
      if (err) reject(err instanceof Error ? err : new Error(String(err)));
      else resolve();
    };
    ws.onopen = () => {
      (async () => {
        const reader = opts.readable.getReader();
        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            if (ws.readyState !== WebSocket.OPEN) break;
            ws.send(value);
          }
        } catch { /* upstream closed */ }
        try { ws.close(); } catch { /* already closing */ }
      })();
    };
    ws.onmessage = (evt) => {
      const data = evt.data;
      let bytes: Uint8Array | null = null;
      if (data instanceof ArrayBuffer) bytes = new Uint8Array(data);
      else if (typeof data === "string") bytes = new TextEncoder().encode(data);
      if (bytes) writer.write(bytes).catch(() => {});
    };
    ws.onerror = () => finish(new Error("tunnel websocket error"));
    ws.onclose = () => finish();
  });
}

export function createCaller(opts: CallerOptions): CallerHandle {
  const label = opts.label ?? "caller";
  const nsid = opts.nsid ?? "com.atproto.sync.subscribeRepos";
  const subdomain = opts.subscriberSubdomain ??
    (opts.subscriberDid ? didToSubdomain(opts.subscriberDid) : undefined);

  if (!subdomain) {
    throw new Error("subscriberDid or subscriberSubdomain required");
  }

  const hostname = hostnameOnly(opts.dispatcherHost);
  const url = new URL(
    `wss://${subdomain}.${opts.dispatcherHost}/xrpc/${nsid}`,
  );
  if (opts.cursor !== undefined) {
    url.searchParams.set("cursor", String(opts.cursor));
  }

  let eventIndex = 0;
  let closed = false;

  function connect(): WebSocket {
    const ws = new WebSocket(url);
    ws.onopen = () => {
      log.info("ws_open", { component: label, url: url.toString() });
    };
    ws.onmessage = (evt) => {
      let msg: unknown;
      try {
        msg = JSON.parse(evt.data as string);
      } catch {
        msg = evt.data;
      }
      const summary = summarizeFrame(msg);
      opts.onEvent?.(summary, eventIndex++);
    };
    ws.onerror = () => {
      log.error("ws_error", { component: label });
    };
    ws.onclose = (evt) => {
      log.info("ws_close", { component: label, code: evt.code, reason: evt.reason });
      if (!closed) {
        setTimeout(() => {
          if (!closed) connect();
        }, 5_000);
      }
    };
    return ws;
  }

  const ws = connect();

  return {
    close() {
      closed = true;
      ws.close();
    },
  };
}
