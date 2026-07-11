import type { NonceStore, VerifyResult } from "@publicdomainrelay/did-key-ingress-proxy-abc";
import { verifySignature } from "@atproto/crypto";
export { verifyServiceAuth, verifyServiceAuthExt } from "@publicdomainrelay/did-key-ingress-proxy-common";
export type { VerifyServiceAuthOptions, VerifyServiceAuthResult } from "@publicdomainrelay/did-key-ingress-proxy-common";

interface NonceEntry {
  key: string;
  nonce: string;
  expiresAt: number;
}

export interface NonceStoreOpts {
  ttlMs: number;
  /** Resolve a non-did:key DID to its atproto signing key (did:key). */
  resolveDidKey?: (did: string) => Promise<string>;
}

export function createNonceStore(opts: NonceStoreOpts): NonceStore {
  const { ttlMs, resolveDidKey } = opts;
  const entries = new Map<string, NonceEntry>();

  const purgeInterval = setInterval(() => {
    const now = Date.now();
    for (const [nonce, entry] of entries) {
      if (entry.expiresAt < now) entries.delete(nonce);
    }
  }, Math.min(ttlMs, 30_000));

  Deno.unrefTimer?.(purgeInterval);

  function encodeBase64(bytes: Uint8Array): string {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function decodeBase64(s: string): Uint8Array {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function generateNonce(): string {
    const bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    return encodeBase64(bytes);
  }

  return {
    issue(key: string): string {
      const nonce = generateNonce();
      entries.set(nonce, {
        key,
        nonce,
        expiresAt: Date.now() + ttlMs,
      });
      return nonce;
    },

    async verify(reg): Promise<VerifyResult> {
      if (!reg || typeof reg !== "object") {
        return { ok: false, reason: "invalid registration" };
      }
      if (!reg.key || typeof reg.key !== "string") {
        return { ok: false, reason: "missing key" };
      }
      if (!reg.nonce || typeof reg.nonce !== "string") {
        return { ok: false, reason: "missing nonce" };
      }
      const entry = entries.get(reg.nonce);
      if (!entry) {
        return { ok: false, reason: "unknown or expired nonce" };
      }
      if (entry.key !== reg.key) {
        return { ok: false, reason: "nonce was issued for a different key" };
      }
      if (entry.expiresAt < Date.now()) {
        entries.delete(reg.nonce);
        return { ok: false, reason: "nonce expired" };
      }
      const sigs = Array.isArray(reg.signatures) ? reg.signatures : [];
      if (sigs.length === 0) {
        return { ok: false, reason: "no signatures provided" };
      }
      const nonceBytes = decodeBase64(reg.nonce);
      let sigVerified = false;
      for (const sig of sigs) {
        if (!sig?.key || !sig?.signature) continue;
        try {
          // did:key → verify directly. did:plc etc → resolve via callback → verify.
          const keyDid = sig.key.startsWith("did:key:")
            ? sig.key
            : resolveDidKey ? await resolveDidKey(sig.key).catch(() => null) : null;
          if (!keyDid) continue;
          if (await verifySignature(keyDid, nonceBytes, decodeBase64(sig.signature))) {
            sigVerified = true;
            break;
          }
        } catch { /* try next signature */ }
      }
      if (!sigVerified) {
        return { ok: false, reason: "no signature verifies over the nonce" };
      }
      entries.delete(reg.nonce);
      return { ok: true, key: reg.key };
    },
  };
}
