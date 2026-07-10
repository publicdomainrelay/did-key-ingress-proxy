import type { RelayRequest } from "@publicdomainrelay/did-key-ingress-proxy-common";
import type { RelayRequestResult } from "@publicdomainrelay/did-key-ingress-proxy-subscriber-xrpc";

export interface FetchApp {
  fetch(req: Request): Response | Promise<Response>;
}

export interface SubscriberFactoryOptions {
  app: FetchApp;
  baseOrigin?: string;
}

export interface SubscriberFactory {
  handleRequest(req: RelayRequest): Promise<RelayRequestResult>;
}

export function createSubscriberFactory(opts: SubscriberFactoryOptions): SubscriberFactory {
  const origin = opts.baseOrigin ?? "https://subscriber.local";

  return {
    async handleRequest(req: RelayRequest): Promise<RelayRequestResult> {
      const url = new URL(req.path, origin);
      for (const [k, v] of Object.entries(req.params ?? {})) url.searchParams.set(k, v);

      const init: RequestInit = { method: req.method, headers: req.headers };
      if (!["GET", "HEAD"].includes(req.method) && req.body != null) {
        init.body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
      }

      const res = await opts.app.fetch(new Request(url, init));
      const contentType = res.headers.get("content-type") ?? "application/json";
      const body = contentType.includes("application/json")
        ? await res.json().catch(() => null)
        : await res.text();

      return { status: res.status, body, contentType };
    },
  };
}
