// Hermetic CLI test: exercises BOTH tunnel CLIs as real subprocesses (no
// container, no Deno API shortcuts), proving the entrypoints work end to end.
//
//   in-process relay  +  local TCP echo
//   subprocess: hono-did-key-ingress-proxy-tunnel-subscriber (the in-VM agent)
//   subprocess: hono-did-key-ingress-proxy-tunnel           (the ssh ProxyCommand)
//
// Bytes written to the tunnel-client's stdin come back on its stdout, having
// ridden the relay to the subscriber's tunnelTarget (the echo server) and back.
//
//   deno test -A test/tunnel_cli_test.ts

import { assertEquals } from "@std/assert";
import { Secp256k1Keypair } from "@atproto/crypto";
import { didToSubdomain } from "@publicdomainrelay/did-key-ingress-proxy-common";
import { createRelayFactory } from "@publicdomainrelay/hono-factory-did-key-ingress-proxy-xrpc";

const HERE = new URL(".", import.meta.url).pathname;
const TUNNEL_CLIENT_MOD = `${HERE}../hono-did-key-ingress-proxy-tunnel/mod.ts`;
const AGENT_MOD = `${HERE}../hono-did-key-ingress-proxy-tunnel-subscriber/mod.ts`;

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

function flipCase(b: number): number {
  if (b >= 0x41 && b <= 0x5a) return b + 32;
  if (b >= 0x61 && b <= 0x7a) return b - 32;
  return b;
}

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
            const out = buf.subarray(0, n).map(flipCase);
            let off = 0;
            while (off < out.length) off += await conn.write(out.subarray(off));
          }
        } catch { /* closed */ }
        try { conn.close(); } catch { /* ok */ }
      })();
    }
  })();
  return { port, close: () => ln.close() };
}

async function waitForLine(stdout: ReadableStream<Uint8Array>, needle: string, timeoutMs: number): Promise<boolean> {
  const reader = stdout.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const deadline = Date.now() + timeoutMs;
  try {
    while (Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value);
      if (buf.includes(needle)) return true;
    }
    return false;
  } finally {
    reader.releaseLock();
  }
}

Deno.test({
  name: "[tunnel-cli] subprocess CLIs bridge stdin/stdout over the relay to a TCP target",
  sanitizeOps: false,
  sanitizeResources: false,
}, async () => {
  const cleanups: Array<() => void | Promise<void>> = [];
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
    const privateKeyHex = Array.from(await keypair.export()).map((b) => b.toString(16).padStart(2, "0")).join("");
    const subdomain = didToSubdomain(keypair.did());

    // ── subprocess 1: the in-VM agent CLI ────────────────────────────────
    const agent = new Deno.Command("deno", {
      args: [
        "run", "-A", AGENT_MOD,
        "--ingress-proxy-host", ingressProxyHost,
        "--aud-host", "localhost",
        "--private-key-hex", privateKeyHex,
        "--target-host", "127.0.0.1",
        "--target-port", String(echo.port),
      ],
      stdout: "piped", stderr: "null",
    }).spawn();
    cleanups.push(() => { try { agent.kill("SIGKILL"); } catch { /* ok */ } });

    const registered = await waitForLine(agent.stdout, "tunnel_subscriber_ready", 30_000);
    assertEquals(registered, true, "agent CLI registered with the relay");

    // ── subprocess 2: the ssh-ProxyCommand tunnel client CLI ─────────────
    const client = new Deno.Command("deno", {
      args: [
        "run", "-A", TUNNEL_CLIENT_MOD,
        "--ingress-proxy-host", ingressProxyHost,
        "--subdomain", subdomain,
      ],
      stdin: "piped", stdout: "piped", stderr: "null",
    }).spawn();
    cleanups.push(() => { try { client.kill("SIGKILL"); } catch { /* ok */ } });

    const payload = new TextEncoder().encode("Tunnel-CLI-RoundTrip-0123456789");
    const writer = client.stdin.getWriter();
    await writer.write(payload);

    // Read echoed (case-flipped) bytes back from the client's stdout.
    const reader = client.stdout.getReader();
    const received: Uint8Array[] = [];
    const deadline = Date.now() + 15_000;
    while (concat(received).length < payload.length && Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value) received.push(value);
    }
    reader.releaseLock();

    const got = concat(received).subarray(0, payload.length);
    const expected = payload.map(flipCase);
    assertEquals(got, expected, "stdin bytes round-tripped through both CLIs + relay, case-flipped by the TCP target");

    await writer.close().catch(() => {});
  } finally {
    for (const c of cleanups.reverse()) { try { await c(); } catch { /* best effort */ } }
    await new Promise((r) => setTimeout(r, 200));
  }
});
