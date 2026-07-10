export const SUBSCRIBE_NSID = "com.fedproxy.temp.xrpc.subscribe";
export const GET_NONCE_NSID = "com.fedproxy.temp.xrpc.getRegistrationNonce";
export const TUNNEL_NSID = "com.fedproxy.temp.xrpc.tunnel";

export const DEFAULT_MARKET_SERVICE_ID = "pdr_temp_market";

export { hostnameOnly, hostnameToDid, didToSubdomain } from "@publicdomainrelay/hostname-helpers";

export interface RelayRequestFrame {
  requestId: string;
  method: string;
  path: string;
  params: Record<string, string>;
  body: unknown;
  headers: Record<string, string>;
}

export interface RelayResponse {
  status: number;
  body: unknown;
  contentType?: string;
}

export interface RelayRequest {
  requestId: string;
  method: string;
  path: string;
  params: Record<string, string>;
  body: unknown;
  headers: Record<string, string>;
}

export function inferFrameType(frame: unknown): string {
  if (typeof frame === "object" && frame !== null) {
    const rec = frame as Record<string, unknown>;
    return (rec.$type ?? rec._type ?? "unknown") as string;
  }
  return "unknown";
}

export function summarizeFrame(frame: unknown): Record<string, unknown> {
  if (typeof frame !== "object" || frame === null) {
    return { _type: "unknown", raw: String(frame) };
  }
  const rec = frame as Record<string, unknown>;
  const summary: Record<string, unknown> = {
    _type: inferFrameType(frame),
  };
  for (const k of ["seq", "event", "time", "did", "operation", "commit"]) {
    if (k in rec) summary[k] = rec[k];
  }
  return summary;
}

export function decodeJwtPayload(token: string): Record<string, unknown> {
  const payloadB64 = token.split(".")[1];
  if (!payloadB64) throw new Error("malformed JWT");
  const json = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(json);
}

export function verifyServiceAuth(
  authHeader: string | null | undefined,
  audDid: string,
  lxm: string,
  serviceAuth?: string,
): void {
  // WebSocket clients cannot set request headers, so the subscribe handshake
  // carries the service-auth token as a `service_auth` query param instead.
  let token: string;
  if (authHeader) {
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
      throw new Error("Authorization header must be Bearer <token>");
    }
    token = parts[1];
  } else if (serviceAuth) {
    token = serviceAuth;
  } else {
    throw new Error("missing Authorization header");
  }
  let payload: Record<string, unknown>;
  try {
    payload = decodeJwtPayload(token);
  } catch {
    throw new Error("failed to decode service auth JWT");
  }
  if (payload.aud !== audDid) {
    throw new Error(
      `aud mismatch: expected ${audDid}, got ${payload.aud}`,
    );
  }
  if (payload.lxm !== lxm) {
    throw new Error(`lxm mismatch: expected ${lxm}, got ${payload.lxm}`);
  }
  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    throw new Error("service auth token expired");
  }
}

export interface VerifyServiceAuthOptions {
  authHeader: string | null | undefined;
  hostname: string;
  lxm: string;
  serviceIds?: string[];
  idResolver?: unknown;
}

export interface VerifyServiceAuthResult {
  issuerDid: string;
}

export async function verifyServiceAuthExt(
  opts: VerifyServiceAuthOptions,
): Promise<VerifyServiceAuthResult> {
  if (!opts.authHeader) {
    throw new Error("missing Authorization header");
  }
  const parts = opts.authHeader.split(" ");
  if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer") {
    throw new Error("Authorization header must be Bearer <token>");
  }
  const token = parts[1];

  let payload: Record<string, unknown>;
  try {
    payload = decodeJwtPayload(token);
  } catch {
    throw new Error("failed to decode service auth JWT");
  }

  const audDid = `did:web:${opts.hostname}`;
  if (payload.aud !== audDid) {
    throw new Error(`aud mismatch: expected ${audDid}, got ${payload.aud}`);
  }

  if (payload.lxm !== opts.lxm) {
    throw new Error(`lxm mismatch: expected ${opts.lxm}, got ${payload.lxm}`);
  }

  if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) {
    throw new Error("service auth token expired");
  }

  const issuerDid = payload.iss as string;
  if (!issuerDid?.startsWith("did:")) {
    throw new Error("invalid issuer DID in service auth token");
  }

  return { issuerDid };
}
