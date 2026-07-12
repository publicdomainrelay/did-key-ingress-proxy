// Parse OpenSSH Ed25519 private key + HKDF derivation utilities.
// Zero I/O — pure byte manipulation and WebCrypto.

const OPENSSH_MAGIC = new TextEncoder().encode("openssh-key-v1\0");

function readUint32(buf: Uint8Array, offset: number): number {
  return new DataView(buf.buffer, buf.byteOffset + offset, 4).getUint32(0, false);
}

function readString(buf: Uint8Array, offset: number): { value: Uint8Array; next: number } {
  const len = readUint32(buf, offset);
  const start = offset + 4;
  return { value: buf.subarray(start, start + len), next: start + len };
}

function decodeUtf8(buf: Uint8Array): string {
  return new TextDecoder().decode(buf);
}

function decodeBase64(pem: string): Uint8Array {
  const b64 = pem
    .replace(/-----[A-Z ]+-----/g, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Parse an OpenSSH "new" format Ed25519 private key and extract the 32-byte seed.
 *
 * Format (binary after base64 decode):
 *   "openssh-key-v1\0"  (15 bytes magic)
 *   cipher name          (4-byte length-prefixed string)
 *   kdf name             (4-byte length-prefixed string)
 *   kdf options          (4-byte length-prefixed string)
 *   number of keys       (uint32)
 *   public key blob      (4-byte length-prefixed bytes)
 *   private key blob     (4-byte length-prefixed bytes):
 *     check bytes (uint32)
 *     check bytes (uint32, same value)
 *     key type (4-byte length-prefixed string)
 *     public key (4-byte length-prefixed bytes)
 *     private+public concatenated (4-byte length-prefixed bytes)
 *       → first 32 bytes = Ed25519 seed
 *     comment (4-byte length-prefixed string)
 *     padding
 */
export function parseOpenSshEd25519Seed(raw: Uint8Array): Uint8Array {
  // Verify magic
  for (let i = 0; i < OPENSSH_MAGIC.length; i++) {
    if (raw[i] !== OPENSSH_MAGIC[i]) {
      throw new Error("not an OpenSSH private key (bad magic)");
    }
  }
  let pos = OPENSSH_MAGIC.length;

  // Skip cipher name, kdf name, kdf options
  const cipher = readString(raw, pos);
  pos = cipher.next;
  const kdf = readString(raw, pos);
  pos = kdf.next;
  const kdfOpts = readString(raw, pos);
  pos = kdfOpts.next;

  if (decodeUtf8(cipher.value) !== "none") {
    throw new Error(`encrypted OpenSSH keys not supported (cipher: ${decodeUtf8(cipher.value)})`);
  }

  // Number of keys
  const numKeys = readUint32(raw, pos);
  pos += 4;
  if (numKeys !== 1) {
    throw new Error(`expected 1 key, got ${numKeys}`);
  }

  // Skip public key blob
  const pubBlob = readString(raw, pos);
  pos = pubBlob.next;

  // Read private key blob
  const privBlob = readString(raw, pos);
  let pp = 0;

  // Check bytes (two identical uint32)
  const check1 = readUint32(privBlob.value, pp);
  pp += 4;
  const check2 = readUint32(privBlob.value, pp);
  pp += 4;
  if (check1 !== check2) {
    throw new Error("OpenSSH private key check bytes mismatch — file may be corrupted");
  }

  // Key type
  const keyType = readString(privBlob.value, pp);
  pp = keyType.next;
  if (decodeUtf8(keyType.value) !== "ssh-ed25519") {
    throw new Error(`expected ssh-ed25519 key, got ${decodeUtf8(keyType.value)}`);
  }

  // Public key (32 bytes)
  const edPub = readString(privBlob.value, pp);
  pp = edPub.next;

  // Private key + public key concatenated (64 bytes total, first 32 = seed)
  const privPub = readString(privBlob.value, pp);
  if (privPub.value.length < 32) {
    throw new Error(`private key too short: ${privPub.value.length} bytes`);
  }

  // First 32 bytes are the Ed25519 seed
  return privPub.value.subarray(0, 32);
}

/**
 * Read an OpenSSH Ed25519 private key from its PEM-armored file content,
 * returning the raw 32-byte seed.
 */
export function parseOpenSshEd25519Pem(pem: string): Uint8Array {
  return parseOpenSshEd25519Seed(decodeBase64(pem));
}

/**
 * Derive a 32-byte secp256k1 private key from an Ed25519 seed via HKDF-SHA256.
 *
 * Deterministic: same seed always yields the same secp256k1 key bytes.
 * Domain-separated by salt to allow rotation if scheme changes.
 */
export async function deriveSecp256k1FromSeed(seed: Uint8Array): Promise<Uint8Array> {
  const salt = new TextEncoder().encode("tunnel-subscriber-v1");
  const info = new TextEncoder().encode("secp256k1-key");

  // Import the seed as HKDF key material
  const ikm = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(seed),
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );

  const derived = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info,
    },
    ikm,
    256, // 32 bytes
  );

  return new Uint8Array(derived);
}
