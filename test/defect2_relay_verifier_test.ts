import { assert, assertEquals, assertRejects } from "@std/assert";
import { Secp256k1Keypair } from "@atproto/crypto";
import { GET_NONCE_NSID, verifyServiceAuth, verifyServiceAuthExt } from "@publicdomainrelay/did-key-ingress-proxy-common";

const HOSTNAME = "relay.test";

function b64url(input: string | Uint8Array): string {
  const s = typeof input === "string" ? btoa(input) : btoa(String.fromCharCode(...input));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function mintServiceAuth(
  kp: Secp256k1Keypair | null,
  iss: string,
  aud: string,
  lxm: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const signingInput = `${b64url(JSON.stringify({ typ: "JWT", alg: "ES256K" }))}.${
    b64url(JSON.stringify({ iss, aud, lxm, iat: now, exp: now + 300 }))
  }`;
  const sig = kp ? await kp.sign(new TextEncoder().encode(signingInput)) : new Uint8Array(64).fill(7);
  return `${signingInput}.${b64url(sig)}`;
}

Deno.test("defect2: a token signed by nobody must not authenticate", async () => {
  const victimDid = "did:plc:victimvictimvictim";
  const forged = await mintServiceAuth(null, victimDid, `did:web:${HOSTNAME}`, GET_NONCE_NSID);
  const token = `Bearer ${forged}`;

  let accepted = false;
  try {
    await verifyServiceAuth(token, `did:web:${HOSTNAME}`, GET_NONCE_NSID);
    accepted = true;
  } catch { /* rejected */ }
  console.log("[defect2] verifyServiceAuth accepted unsigned token =", accepted);

  let issuerSeen: unknown = null;
  try {
    issuerSeen = await verifyServiceAuthExt({
      authHeader: token,
      hostname: HOSTNAME,
      lxm: GET_NONCE_NSID,
      serviceIds: ["pdr_temp_market"],
    });
  } catch { /* rejected */ }
  console.log("[defect2] verifyServiceAuthExt resolved identity =", JSON.stringify(issuerSeen));

  assertEquals(accepted, false);
  assertEquals(issuerSeen, null);
});

Deno.test("defect2 control: a genuinely signed did:key token still authenticates", async () => {
  const kp = await Secp256k1Keypair.create();
  const token = `Bearer ${await mintServiceAuth(kp, kp.did(), `did:web:${HOSTNAME}`, GET_NONCE_NSID)}`;

  await verifyServiceAuth(token, `did:web:${HOSTNAME}`, GET_NONCE_NSID);

  const sameIssuer = await verifyServiceAuthExt({
    authHeader: token,
    hostname: HOSTNAME,
    lxm: GET_NONCE_NSID,
    serviceIds: ["pdr_temp_market"],
  });
  assertEquals(sameIssuer.issuerDid, kp.did());

  await assertRejects(async () => {
    await verifyServiceAuth(token, `did:web:${HOSTNAME}`, "com.example.other");
  });
  assert(true);
});
