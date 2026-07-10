// Hermetic full-duplex tunnel test for the xrpc-dispatcher binary tunnel
// primitive: caller (tunnelOverRelay) -> relay -> subscriber (tunnelTarget)
// -> a local TCP echo server, and the echoed bytes back again.
//
// Proves raw byte streams (e.g. SSH-over-websocket) ride the xrpc relay,
// without containers. *.localhost resolves to loopback so the relay's
// Host-subdomain routing works for a raw WebSocket (which cannot set Host).
//
//   deno test -A test/tunnel_test.ts

import { assertEquals } from "@std/assert";
import { Secp256k1Keypair } from "@atproto/crypto";
import { createRelayFactory } from "@publicdomainrelay/hono-factory-did-key-ingress-proxy-xrpc";
import { createSubscriber, tunnelOverRelay } from "@publicdomainrelay/did-key-ingress-proxy-subscriber-xrpc";

function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

// A TCP echo server that flips ASCII case, so the bytes returned to the caller
// could only have come from the remote target (not a local loopback artifact).
function startCaseFlipEchoServer(): { port: number; close(): void } {
  const ln = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (ln.addr as Deno.NetAddr).port;
  (async () => {
    for await (const conn of ln) {
      (async () => {
        const buf = new Uint8Array(64 * 1024);
        try {
          while (true) {
            const n = await conn.read(buf);
            if (n === null) break;
            const out = buf.subarray(0, n).map((b) => {
              if (b >= 0x41 && b <= 0x5a) return b + 32;
              if (b >= 0x61 && b <= 0x7a) return b - 32;
              return b;
            });
            let off = 0;
            while (off < out.length) off += await conn.write(out.subarray(off));
          }
        } catch { /* closed */ }
        try { conn.close(); } catch { /* already closed */ }
      })();
    }
  })();
  return { port, close: () => ln.close() };
}

Deno.test({
  name: "[tunnel] full-duplex bytes ride the relay (caller <-> relay <-> subscriber <-> tcp)",
  sanitizeOps: false,
  sanitizeResources: false,
}, async () => {
  const cleanups: Array<() => void> = [];
  try {
    const relayApp = createRelayFactory({ hostname: "localhost" }).createApp();
    const relayCtl = new AbortController();
    const { promise: portReady, resolve: resolvePort } = Promise.withResolvers<number>();
    Deno.serve({ port: 0, hostname: "127.0.0.1", signal: relayCtl.signal, onListen: (addr) => resolvePort((addr as Deno.NetAddr).port) }, relayApp.fetch);
    const dispPort = await portReady;
    const ingressProxyHost = `localhost:${dispPort}`;
    cleanups.push(() => relayCtl.abort());

    const echo = startCaseFlipEchoServer();
    cleanups.push(() => echo.close());

    const keypair = await Secp256k1Keypair.create({ exportable: true });
    const did = keypair.did();
    const getServiceAuthToken = (nsid: string): Promise<string> => {
      const header = b64url({ alg: "ES256K", typ: "JWT" });
      const payload = b64url({ iss: did, aud: "did:web:localhost", lxm: nsid, exp: Math.floor(Date.now() / 1000) + 300 });
      return Promise.resolve(`${header}.${payload}.x`);
    };

    const sub = await createSubscriber({
      label: "tunnel-sub",
      keypair,
      getServiceAuthToken,
      ingressProxyHost,
      tunnelTarget: { hostname: "127.0.0.1", port: echo.port },
    });
    cleanups.push(() => { try { sub.ws.close(); } catch { /* ok */ } });

    // Caller side: drive a controllable readable, collect into a writable.
    let enqueue!: (b: Uint8Array) => void;
    let closeReadable!: () => void;
    const readable = new ReadableStream<Uint8Array>({
      start(c) {
        enqueue = (b) => c.enqueue(b);
        closeReadable = () => { try { c.close(); } catch { /* ok */ } };
      },
    });

    const received: Uint8Array[] = [];
    const expectedLen = 200_000; // > 64KiB subscriber buffer -> multiple frames
    let resolveGot!: () => void;
    const got = new Promise<void>((r) => { resolveGot = r; });
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        received.push(chunk);
        if (concat(received).length >= expectedLen) resolveGot();
      },
    });

    const tunnelDone = tunnelOverRelay({ ingressProxyHost, subscriberSubdomain: sub.subdomain, readable, writable });

    // Send a large payload of mixed-case ASCII; expect it back case-flipped.
    const payload = new Uint8Array(expectedLen);
    for (let i = 0; i < expectedLen; i++) {
      payload[i] = (i % 2 === 0) ? 0x41 + (i % 26) : 0x61 + (i % 26); // A.. / a..
    }
    enqueue(payload);

    await Promise.race([
      got,
      new Promise((_, rej) => setTimeout(() => rej(new Error("timed out waiting for tunnel echo")), 15_000)),
    ]);

    const out = concat(received).subarray(0, expectedLen);
    assertEquals(out.length, expectedLen, "received full payload length");
    const expected = payload.map((b) => {
      if (b >= 0x41 && b <= 0x5a) return b + 32;
      if (b >= 0x61 && b <= 0x7a) return b - 32;
      return b;
    });
    assertEquals(out, expected, "every byte round-tripped through the relay, case-flipped by the remote");

    closeReadable();
    await Promise.race([tunnelDone, new Promise((r) => setTimeout(r, 2000))]);
  } finally {
    for (const c of cleanups.reverse()) { try { c(); } catch { /* best effort */ } }
    await new Promise((r) => setTimeout(r, 200));
  }
});
