import { verifyJwt } from "@atproto/xrpc-server";

export const SUBSCRIBE_NSID = "com.fedproxy.temp.xrpc.subscribe";
export const GET_NONCE_NSID = "com.fedproxy.temp.xrpc.getRegistrationNonce";
export const TUNNEL_NSID = "com.fedproxy.temp.xrpc.tunnel";

export const DEFAULT_MARKET_SERVICE_ID = "pdr_temp_market";

export { hostnameOnly, hostnameToDid, didToSubdomain } from "@publicdomainrelay/hostname-helpers";

/** Resolve a non-did:key DID (e.g. did:plc) to its atproto signing key (a did:key string). */
export type ResolveDidKey = (did: string) => Promise<string>;

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

async function verifyServiceAuthJwt(
  token: string,
  audDid: string,
  lxm: string,
  resolveDidKey?: ResolveDidKey,
): Promise<Record<string, unknown>> {
  const payload = await verifyJwt(token, null, lxm, async (did: string) => {
    if (did.startsWith("did:key:")) return did;
    if (!resolveDidKey) throw new Error(`cannot resolve signing key for ${did}`);
    return await resolveDidKey(did);
  }) as Record<string, unknown>;
  if (payload.aud !== audDid) {
    throw new Error(`aud mismatch: expected ${audDid}, got ${payload.aud}`);
  }
  return payload;
}

export async function verifyServiceAuth(
  authHeader: string | null | undefined,
  audDid: string,
  lxm: string,
  serviceAuth?: string,
  resolveDidKey?: ResolveDidKey,
): Promise<void> {
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
  await verifyServiceAuthJwt(token, audDid, lxm, resolveDidKey);
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

  const idResolver = opts.idResolver as
    | { did: { resolveAtprotoKey(did: string): Promise<string> } }
    | undefined;
  const payload = await verifyServiceAuthJwt(
    parts[1],
    `did:web:${opts.hostname}`,
    opts.lxm,
    idResolver ? (did: string) => idResolver.did.resolveAtprotoKey(did) : undefined,
  );

  const issuerDid = payload.iss as string;
  if (!issuerDid?.startsWith("did:")) {
    throw new Error("invalid issuer DID in service auth token");
  }

  return { issuerDid };
}
