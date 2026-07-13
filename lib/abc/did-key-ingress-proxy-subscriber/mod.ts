import type { RelayRequest } from "@publicdomainrelay/did-key-ingress-proxy-common";

export interface SubscriberOptions {
  label?: string;
  keypair: {
    did(): string;
    sign(data: Uint8Array): Promise<Uint8Array>;
  };
  getServiceAuthToken: (nsid: string) => Promise<string>;
  ingressProxyHost: string;
  /**
   * Force https/wss to the ingress proxy even for localhost/hosts-with-port
   * (which otherwise default to plaintext for local dev). Set when the local
   * dispatcher serves TLS with a self-signed cert (trust via DENO_CERT).
   */
  tls?: boolean;
  synthetic?: boolean;
  handleRequest?: (
    req: RelayRequest,
  ) => Promise<{ status: number; body: unknown; contentType: string }>;
  /**
   * When set, inbound relay subscriptions for the tunnel NSID open a TCP
   * connection to this target and pipe bytes full-duplex over the relay
   * (raw byte stream, e.g. SSH-over-websocket).
   */
  tunnelTarget?: { hostname: string; port: number };
  /**
   * When set, inbound relay subscriptions for any non-tunnel NSID open a
   * WebSocket to this local serve and forward its frames back over the relay
   * (server-push streaming, e.g. com.atproto.sync.subscribeRepos). Read lazily
   * so the local serve's bound port can be resolved after it starts listening.
   */
  wsTarget?: () => { hostname: string; port: number } | undefined;
  /**
   * When set, inbound relay subscriptions for any non-tunnel NSID call this
   * handler directly instead of opening a loopback WebSocket to wsTarget.
   * The handler receives (subscriptionId, nsid, params, onEvent, onData) and
   * must return an unsubscribe function. Frames are forwarded over the relay
   * WebSocket. Use when the firehose source is in-process (no TCP needed).
   */
  directSubscriptionHandler?: (
    subscriptionId: string,
    nsid: string,
    params: Record<string, string>,
    onEvent: (event: unknown) => void,
    onData: (data: Uint8Array) => void,
  ) => (() => void) | void;
}

export interface SubscriberHandle {
  subdomain: string;
  ingressRef: string;
  /** Current dispatcher WebSocket. Replaced transparently on reconnect. */
  ws: WebSocket;
  /** Stop the subscriber: cancel any pending reconnect and close the socket. */
  close(): void;
}

export interface CallerOptions {
  label?: string;
  ingressProxyHost: string;
  subscriberDid?: string;
  subscriberSubdomain?: string;
  nsid?: string;
  cursor?: number;
  onEvent?: (summary: Record<string, unknown>, eventIndex: number) => void;
}

export interface CallerHandle {
  close(): void;
}
