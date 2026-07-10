import { Command } from "@publicdomainrelay/cli-args-env";
import { Hono } from "@hono/hono";
import { cors } from "@hono/hono/cors";
import { Secp256k1Keypair } from "@atproto/crypto";
import { Agent, CredentialSession } from "@atproto/api";
import { IdResolver } from "@atproto/identity";
import { createLogger } from "@publicdomainrelay/logger";
import { hostnameOnly, DEFAULT_MARKET_SERVICE_ID, verifyServiceAuthExt } from "@publicdomainrelay/did-key-ingress-proxy-common";
import { createSubscriber } from "@publicdomainrelay/did-key-ingress-proxy-subscriber-xrpc";
import { createSubscriberFactory } from "@publicdomainrelay/hono-factory-did-key-ingress-proxy-subscriber-xrpc";
import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

const log = createLogger({ serviceName: "subscriber" });

let runtimeConfig = null;
try {
  const mod = await import("./config.json", { with: { type: "json" } });
  runtimeConfig = mod.default;
} catch { /* optional */ }

const { options } = await new Command(
  "CONFIG_PATH_HONO_DID_KEY_RELAY_SUBSCRIBER",
  cliArgsEnv,
  runtimeConfig,
).resolve();

const keypairPath = options.keypairPath as string;

function bytesToHex(bytes: Uint8Array): string { return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex: string): Uint8Array { const o = new Uint8Array(hex.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16); return o; }

async function getKeypair(): Promise<Secp256k1Keypair> {
  if (options.loadKeypair) {
    const state = JSON.parse(await Deno.readTextFile(keypairPath));
    const kp = await Secp256k1Keypair.import(hexToBytes(state.privateKeyHex));
    log.info("keypair_loaded", { component: "client", path: keypairPath, did: kp.did() });
    return kp;
  }
  const kp = await Secp256k1Keypair.create({ exportable: true });
  log.info("keypair_generated", { component: "client", did: kp.did() });
  if (options.saveKeypair) {
    const priv = bytesToHex(await kp.export());
    await Deno.writeTextFile(keypairPath, JSON.stringify({ privateKeyHex: priv, did: kp.did(), createdAt: new Date().toISOString() }, null, 2));
    log.info("keypair_saved", { component: "client", path: keypairPath });
  }
  return kp;
}

const keypair = await getKeypair();

if (!options.atprotoHandle || !options.atprotoPassword) {
  log.error("missing_credentials", { component: "client", message: "--atproto-handle and --atproto-password are required (or set ATPROTO_HANDLE / ATPROTO_PASSWORD env vars)" });
  Deno.exit(1);
}

const session = new CredentialSession(new URL(options.atprotoPds as string));
await session.login({ identifier: options.atprotoHandle as string, password: options.atprotoPassword as string });
const agent = new Agent(session);
log.info("session_created", { component: "client", did: session.did });

const ingressProxyHostname = hostnameOnly(options.ingressProxyHost as string);

async function getServiceAuthToken(nsid: string): Promise<string> {
  const res = await agent.com.atproto.server.getServiceAuth({ aud: `did:web:${ingressProxyHostname}`, lxm: nsid });
  return res.data.token;
}

const idResolver = new IdResolver();
let registeredSubdomain: string | undefined;

const app = new Hono();
app.use("*", cors());

app.get("/.well-known/did.json", (c) => {
  const subdomain = keypair.did().replaceAll(":", "-").toLowerCase();
  return c.json({
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: `did:web:${subdomain}.${options.ingressProxyHost}`,
    verificationMethod: [{
      id: `did:web:${subdomain}.${options.ingressProxyHost}#atproto`,
      type: "Multikey",
      controller: `did:web:${subdomain}.${options.ingressProxyHost}`,
      publicKeyMultibase: keypair.did().replace(/^did:key:/, ""),
    }],
    service: [{ id: `#${DEFAULT_MARKET_SERVICE_ID}`, type: "PDRTempMarket", serviceEndpoint: `https://${subdomain}.${options.ingressProxyHost}` }],
  });
});

app.use("/xrpc/*", async (c, next) => {
  if (!registeredSubdomain) return c.json({ error: "Unauthorized", message: "not yet registered" }, 401);
  const hostname = `${registeredSubdomain}.${options.ingressProxyHost}`;
  const nsid = c.req.path.slice("/xrpc/".length);
  try {
    const auth = await verifyServiceAuthExt({ authHeader: c.req.header("Authorization"), hostname, lxm: nsid, serviceIds: [DEFAULT_MARKET_SERVICE_ID], idResolver });
    c.set("callerDid" as never, auth.issuerDid);
    c.req.raw.headers.set("x-caller-did", auth.issuerDid);
  } catch (err) { return c.json({ error: "Unauthorized", message: String(err) }, 401); }
  await next();
});

app.post("/xrpc/com.publicdomainrelay.temp.market.submitBid", async (c) => {
  const callerDid = c.req.header("x-caller-did");
  let input: { uri?: string; cid?: string; record?: unknown };
  try { input = await c.req.json(); } catch { return c.json({ error: "InvalidRequest", message: "invalid JSON" }, 400); }
  if (!input.uri || !input.cid || !input.record) return c.json({ error: "InvalidRequest", message: "uri, cid, record required" }, 400);
  log.info("submitBid", { component: "handler", callerDid, uri: input.uri });
  return c.json({ ok: true });
});

app.all("/xrpc/*", (c) => c.json({ error: "MethodNotImplemented", nsid: c.req.path.replace("/xrpc/", "") }, 501));

const { handleRequest } = createSubscriberFactory({ app });

const sub = await createSubscriber({
  keypair,
  getServiceAuthToken,
  ingressProxyHost: options.ingressProxyHost as string,
  synthetic: true,
  handleRequest,
});

registeredSubdomain = sub.subdomain;
log.info("registered", { component: "client", subdomain: sub.subdomain, ingressRef: sub.ingressRef });

if (options.writeProxyRefHttpToPath) {
  const hostname = sub.ingressRef.replace(/^did:web:/, "");
  await Deno.writeTextFile(options.writeProxyRefHttpToPath as string, `https://${hostname}\n`);
  log.info("proxy_ref_written", { component: "client", path: options.writeProxyRefHttpToPath, url: `https://${hostname}` });
}
