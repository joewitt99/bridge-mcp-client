// Shared encryption-at-rest helpers (factored out of src/dpop.ts in P04).
//
// Everything secret the bridge writes to BRIDGE_HOME — the DPoP private key and
// the OAuth tokens — is sealed with AES-256-GCM under a key derived (HKDF-SHA256)
// from a per-machine seed (<BRIDGE_HOME>/.seed, 32 random bytes, chmod 600).
// Plaintext key/token material never touches disk. Never log what passes
// through here.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  randomBytes,
} from "node:crypto";

/** A sealed blob: AES-256-GCM iv, ciphertext, and auth tag (all base64). */
export interface Sealed {
  iv: string;
  ciphertext: string;
  tag: string;
}

const SEED_INFO = "okta-mcp-bridge seal v1";

/** Ensure BRIDGE_HOME exists with mode 0700. */
export function ensureBridgeHome(home: string): void {
  if (!existsSync(home)) mkdirSync(home, { recursive: true, mode: 0o700 });
  chmodSync(home, 0o700);
}

/** Read (or create chmod-600) the 32-byte per-machine seed under BRIDGE_HOME. */
function readSeed(home: string): Buffer {
  const seedPath = join(home, ".seed");
  if (!existsSync(seedPath)) {
    const seed = randomBytes(32);
    writeFileSync(seedPath, seed, { mode: 0o600 });
    chmodSync(seedPath, 0o600);
    return seed;
  }
  return readFileSync(seedPath);
}

/** Derive the AES-256 key from the seed via HKDF-SHA256. */
function deriveKey(home: string): Buffer {
  const seed = readSeed(home);
  const derived = hkdfSync("sha256", seed, Buffer.alloc(0), SEED_INFO, 32);
  return Buffer.from(derived);
}

/** Serialize and seal a JSON value. Creates the seed on first use. */
export function sealJson(home: string, obj: unknown): Sealed {
  ensureBridgeHome(home);
  const key = deriveKey(home);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: tag.toString("base64"),
  };
}

/** Open a sealed blob back into a JSON value. */
export function openJson<T>(home: string, sealed: Sealed): T {
  const key = deriveKey(home);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(sealed.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8")) as T;
}
