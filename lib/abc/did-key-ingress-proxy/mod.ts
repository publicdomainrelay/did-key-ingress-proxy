import type { RelayResponse } from "@publicdomainrelay/did-key-ingress-proxy-common";

export type SendFrame = (ws: WebSocket, frame: string) => void;
export type CloseConnection = (ws: WebSocket, code: number, reason: string) => void;

export interface RelayStateOptions {
  relayTimeoutMs: number;
  reconnectGraceMs: number;
  onSendFrame: SendFrame;
  onCloseConnection: CloseConnection;
}

interface ActiveSubscription {
  callerWs: WebSocket;
  subdomain: string;
  nsid: string;
}

interface PendingRequest {
  resolve: (result: RelayResponse) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface ReconnectEntry {
  raw: WebSocket;
  queue: Array<{ requestId: string; frame: string; resolve: (r: RelayResponse) => void; reject: (e: Error) => void }>;
}

export class RelayState {
  readonly subscribers = new Map<string, WebSocket>();
  readonly activeSubscriptions = new Map<string, ActiveSubscription>();
  readonly relayTimeoutMs: number;
  readonly reconnectGraceMs: number;

  private pendingRequests = new Map<string, PendingRequest>();
  private reconnectQueues = new Map<string, ReconnectEntry>();
  private onSendFrame: SendFrame;
  private onCloseConnection: CloseConnection;

  constructor(opts: RelayStateOptions) {
    this.relayTimeoutMs = opts.relayTimeoutMs;
    this.reconnectGraceMs = opts.reconnectGraceMs;
    this.onSendFrame = opts.onSendFrame;
    this.onCloseConnection = opts.onCloseConnection;
  }

  handleResponse(
    requestId: string,
    status: number,
    body: unknown,
    contentType?: string,
  ): void {
    const pending = this.pendingRequests.get(requestId);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pendingRequests.delete(requestId);
    pending.resolve({ status, body, contentType });
  }

  dispatchRequest(
    subdomain: string,
    requestId: string,
    frame: string,
    timeoutMs?: number,
  ): Promise<RelayResponse> {
    const subWs = this.subscribers.get(subdomain);
    if (!subWs || subWs.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error(`no active subscriber for subdomain ${subdomain}`));
    }
    const t = timeoutMs ?? this.relayTimeoutMs;
    return new Promise<RelayResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        // The subscriber didn't respond within the relay timeout — almost
        // certainly a half-open/dead connection (Deno's WebSocket has no
        // WS-level ping, so the death is otherwise silent). Evict it: closing
        // the socket fires the client's onclose, which schedules a reconnect
        // and re-register. Without this, every request to a dead subscriber
        // hangs for relayTimeoutMs forever.
        const deadWs = this.subscribers.get(subdomain);
        if (deadWs) {
          this.subscribers.delete(subdomain);
          this.rejectSubscriberSubscriptions(subdomain);
          this.onCloseConnection(deadWs, 1011, `subscriber unresponsive after ${t}ms`);
        }
        reject(new Error(`relay timeout after ${t}ms`));
      }, t);
      this.pendingRequests.set(requestId, { resolve, reject, timer });
      this.onSendFrame(subWs, frame);
    });
  }

  drainToReconnectQueue(subdomain: string): void {
    const entry = this.reconnectQueues.get(subdomain);
    if (!entry) return;
  }

  flushReconnectQueue(subdomain: string, raw: WebSocket): void {
    const entry = this.reconnectQueues.get(subdomain);
    if (!entry) return;
    for (const { frame, resolve, reject } of entry.queue) {
      const frameParsed = JSON.parse(frame) as { requestId: string };
      const requestId = frameParsed.requestId;
      const timer = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        // The subscriber didn't respond within the relay timeout — almost
        // certainly a half-open/dead connection (Deno's WebSocket has no
        // WS-level ping, so the death is otherwise silent). Evict it: closing
        // the socket fires the client's onclose, which schedules a reconnect
        // and re-register. Without this, every request to a dead subscriber
        // hangs for relayTimeoutMs forever.
        const deadWs = this.subscribers.get(subdomain);
        if (deadWs) {
          this.subscribers.delete(subdomain);
          this.rejectSubscriberSubscriptions(subdomain);
          this.onCloseConnection(deadWs, 1011, `subscriber unresponsive after ${this.relayTimeoutMs}ms`);
        }
        reject(new Error(`relay timeout after ${this.relayTimeoutMs}ms`));
      }, this.relayTimeoutMs);
      this.pendingRequests.set(requestId, { resolve, reject, timer });
      this.onSendFrame(raw, frame);
    }
    this.reconnectQueues.delete(subdomain);
  }

  rejectSubscriberSubscriptions(subdomain: string): void {
    for (const [subId, sub] of this.activeSubscriptions) {
      if (sub.subdomain === subdomain) {
        if (sub.callerWs.readyState === WebSocket.OPEN) {
          this.onCloseConnection(sub.callerWs, 4004, "subscriber disconnected");
        }
        this.activeSubscriptions.delete(subId);
      }
    }
  }
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
  key?: string;
}

export interface NonceStore {
  issue(key: string): string;
  verify(reg: {
    key?: string;
    nonce?: string;
    signatures?: Array<{ key?: string; signature?: string }>;
  }): Promise<VerifyResult>;
}
