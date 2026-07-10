// xrpc-dispatcher tunnel client — bridges stdin/stdout to a remote TCP target
// through the relay tunnel. Designed to be an SSH ProxyCommand:
//
//   ssh -o ProxyCommand='deno run -A jsr:.../hono-did-key-ingress-proxy-tunnel/mod.ts \
//        --ingress-proxy-host relay.example.com --subdomain <sub>' user@vm
//
// The relay routes by Host subdomain to the subscriber registered under
// <subdomain>, whose tunnelTarget pipes to its local sshd.

import { tunnelOverRelay } from "@publicdomainrelay/did-key-ingress-proxy-subscriber-xrpc";

function arg(name: string): string | undefined {
  const i = Deno.args.indexOf(name);
  return i >= 0 ? Deno.args[i + 1] : undefined;
}

const ingressProxyHost = arg("--ingress-proxy-host");
const subdomain = arg("--subdomain");
const nsid = arg("--nsid");

if (!ingressProxyHost || !subdomain) {
  console.error("usage: tunnel --ingress-proxy-host <host[:port]> --subdomain <sub> [--nsid <nsid>]");
  Deno.exit(2);
}

await tunnelOverRelay({
  ingressProxyHost,
  subscriberSubdomain: subdomain,
  nsid,
  readable: Deno.stdin.readable,
  writable: Deno.stdout.writable,
});
