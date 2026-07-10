import { Command } from "@publicdomainrelay/cli-args-env";
import { createLogger } from "@publicdomainrelay/logger";
import { createServe } from "@publicdomainrelay/serve";
import { createRelayFactory } from "@publicdomainrelay/hono-factory-did-key-ingress-proxy-xrpc";
import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

const logger = createLogger({ serviceName: "relay" });

let runtimeConfig = null;
try {
  const mod = await import("./config.json", { with: { type: "json" } });
  runtimeConfig = mod.default;
} catch { /* optional */ }

const { options } = await new Command(
  "CONFIG_PATH_HONO_DID_KEY_RELAY_RELAYER",
  cliArgsEnv,
  runtimeConfig,
).resolve();

const configuredExtra = ((options.additionalHosts as string) || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// "*" means allow all — skip auto-detection.
let additionalHosts: string[];
if (configuredExtra.includes("*")) {
  additionalHosts = ["*"];
} else {
  // Always accept 127.0.0.1 + auto-detect container/docker gateway so the guest
  // can reach the relay control endpoints.  macOS container uses 192.168.64.1,
  // Docker uses 172.17.0.1.  The gateway is the host address the guest dials.
  const defaultHosts: string[] = ["127.0.0.1"];
  try {
    const { createContainerBackend } = await import("@publicdomainrelay/container-backend-container");
    const be = createContainerBackend();
    if (await be.isRunning()) {
      defaultHosts.push(await be.defaultGateway());
    }
  } catch { /* container backend not available */ }
  try {
    const { createDockerBackend } = await import("@publicdomainrelay/container-backend-docker");
    const be = createDockerBackend();
    if (await be.isRunning()) {
      defaultHosts.push(await be.defaultGateway());
    }
  } catch { /* docker not available */ }

  additionalHosts = [...new Set([...defaultHosts, ...configuredExtra])];
}

const allowedDids = ((options.allowedDids as string) || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const app = createRelayFactory({
  hostname: options.hostname as string,
  serviceId: options.serviceId as string | undefined,
  relayTimeoutMs: options.relayTimeoutMs as number | undefined,
  reconnectGraceMs: options.reconnectGraceMs as number | undefined,
  nonceTtlMs: options.nonceTtlMs as number | undefined,
  additionalHosts: additionalHosts.length ? additionalHosts : undefined,
  allowedDids: allowedDids.length ? allowedDids : undefined,
}).createApp();

const unixSocket = options.unixSocket as string | undefined;
const serve = createServe({
  logger,
  unix: unixSocket ? { socketPath: unixSocket } : undefined,
  tcp: unixSocket ? undefined : { port: options.port as number },
});
serve.app.route("/", app as never);

function shutdown() {
  serve.shutdown();
  Deno.exit();
}
Deno.addSignalListener("SIGINT", shutdown);
Deno.addSignalListener("SIGTERM", shutdown);

await serve.beginServe();
