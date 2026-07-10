// In-VM tunnel subscriber agent — the "relay client" that runs inside a
// provisioned VM/container. It dials the relay dispatcher (outbound), registers
// a subdomain derived from its keypair, and bridges inbound tunnel streams to a
// local TCP target (its own sshd on 127.0.0.1:22). This is the fedproxy-client
// replacement: SSH-over-websocket rides the xrpc relay instead.
//
// Built with `deno compile` so it runs in a minimal VM image with no Deno.
//
//   tunnel-subscriber --ingress-proxy-host <gw:port> --aud-host <relay-hostname> \
//     --private-key-hex <hex> [--target-host 127.0.0.1] [--target-port 22]

import { Secp256k1Keypair } from "@atproto/crypto";
import { createSubscriber } from "@publicdomainrelay/did-key-ingress-proxy-subscriber-xrpc";

function arg(name: string): string | undefined {
  const i = Deno.args.indexOf(name);
  return i >= 0 ? Deno.args[i + 1] : undefined;
}

function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

const ingressProxyHost = arg("--ingress-proxy-host");
const audHost = arg("--aud-host");
const privateKeyHex = arg("--private-key-hex");
const targetHost = arg("--target-host") ?? "127.0.0.1";
const targetPort = Number(arg("--target-port") ?? "22");

if (!ingressProxyHost || !audHost || !privateKeyHex) {
  console.error("usage: tunnel-subscriber --ingress-proxy-host <host:port> --aud-host <relay-hostname> --private-key-hex <hex> [--target-host h] [--target-port p]");
  Deno.exit(2);
}

const keypair = await Secp256k1Keypair.import(privateKeyHex);
const did = keypair.did();

// The relay verifies the registration nonce signature with this keypair (real
// crypto); the service-auth JWT itself is claims-only, so aud/lxm/exp suffice.
const getServiceAuthToken = (nsid: string): Promise<string> =>
  Promise.resolve(
    `${b64url({ alg: "ES256K", typ: "JWT" })}.${
      b64url({ iss: did, aud: `did:web:${audHost}`, lxm: nsid, exp: Math.floor(Date.now() / 1000) + 600 })
    }.x`,
  );

const sub = await createSubscriber({
  label: "vm-tunnel",
  keypair,
  getServiceAuthToken,
  ingressProxyHost,
  tunnelTarget: { hostname: targetHost, port: targetPort },
});

console.log(JSON.stringify({ event: "tunnel_subscriber_ready", did, subdomain: sub.subdomain, ingressRef: sub.ingressRef }));

await new Promise<void>(() => {}); // run until killed
