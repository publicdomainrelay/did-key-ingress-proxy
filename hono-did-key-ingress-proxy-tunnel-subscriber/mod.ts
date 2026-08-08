// In-VM tunnel subscriber agent — the "relay client" that runs inside a
// provisioned VM/container. It dials the relay dispatcher (outbound), registers
// a subdomain derived from its keypair, and bridges inbound tunnel streams to a
// local TCP target (its own sshd on 127.0.0.1:22). This is the fedproxy-client
// replacement: SSH-over-websocket rides the xrpc relay instead.
//
// Built with `deno compile` so it runs in a minimal VM image with no Deno.
//
//   tunnel-subscriber --ingress-proxy-host <gw:port> --aud-host <relay-hostname> \
//     --private-key-from-sshd-host-key /etc/ssh/ssh_host_ed25519_key \
//     [--target-host 127.0.0.1] [--target-port 22]

import { Secp256k1Keypair } from "@atproto/crypto";
import { createSubscriber } from "@publicdomainrelay/did-key-ingress-proxy-subscriber-xrpc";
import { parseOpenSshEd25519Pem, deriveSecp256k1FromSeed } from "@publicdomainrelay/tunnel-subscriber-common";

function arg(name: string): string | undefined {
  const i = Deno.args.indexOf(name);
  return i >= 0 ? Deno.args[i + 1] : undefined;
}

function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

const ingressProxyHost = arg("--ingress-proxy-host");
const audHost = arg("--aud-host");
const sshdHostKeyPath = arg("--private-key-from-sshd-host-key");
const fqdnFile = arg("--fqdn-file");
const targetHost = arg("--target-host") ?? "127.0.0.1";
const targetPort = Number(arg("--target-port") ?? "22");

if (!ingressProxyHost || !audHost || !sshdHostKeyPath) {
  console.error("usage: tunnel-subscriber --ingress-proxy-host <host:port> --aud-host <relay-hostname> --private-key-from-sshd-host-key <path> [--target-host h] [--target-port p]");
  Deno.exit(2);
}

const pem = await Deno.readTextFile(sshdHostKeyPath);
const ed25519Seed = parseOpenSshEd25519Pem(pem);
const secp256k1Bytes = await deriveSecp256k1FromSeed(ed25519Seed);
const keypair = await Secp256k1Keypair.import(secp256k1Bytes);
const did = keypair.did();

const getServiceAuthToken = async (nsid: string): Promise<string> => {
  const header = b64url({ alg: "ES256K", typ: "JWT" });
  const payload = b64url({ iss: did, aud: `did:web:${audHost}`, lxm: nsid, exp: Math.floor(Date.now() / 1000) + 600 });
  const signingInput = `${header}.${payload}`;
  const sigBytes = await keypair.sign(new TextEncoder().encode(signingInput));
  const sig = btoa(String.fromCharCode(...sigBytes)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${signingInput}.${sig}`;
};

const sub = await createSubscriber({
  label: "vm-tunnel",
  keypair,
  getServiceAuthToken,
  ingressProxyHost,
  tunnelTarget: { hostname: targetHost, port: targetPort },
  // Respond to any HTTP-style request (e.g. the relay's keepalive probe) so the
  // connection is treated as alive. The tunnel-subscriber only serves the ssh
  // tunnel; everything else is 404.
  handleRequest: async (req) => ({
    status: 404,
    body: { error: "NotFound", message: `tunnel subscriber: ${req.method} ${req.path} not served` },
    contentType: "application/json",
  }),
});

const guestFqdn = `${sub.subdomain}.${ingressProxyHost}`;
console.log(JSON.stringify({ event: "tunnel_subscriber_ready", did, subdomain: sub.subdomain, ingressRef: sub.ingressRef, fqdn: guestFqdn }));

// Write FQDN so guest-onnetwork.service can read it.
if (fqdnFile) {
  try { await Deno.writeTextFile(fqdnFile, guestFqdn + "\n"); } catch { /* best-effort */ }
}

await new Promise<void>(() => {}); // run until killed
