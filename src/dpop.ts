// DPoP key manager + proof factory (RFC 9449 / RFC 7638).
//
// Produces DPoP proof JWTs that satisfy the Okta MCP Adapter contract exactly:
//   header  { typ:"dpop+jwt", alg, jwk:<public JWK> }
//   payload { jti, htm, htu(canonical), iat, ath?, nonce? }
// and Okta's /token DPoP checks. The same key is reused for the /token exchange
// (P04) and for per-request proofs to the adapter (P05) so the minted token's
// cnf.jkt matches the proof's jkt.
//
// Secrets at rest: the DPoP private key is encrypted (AES-256-GCM) with a key
// derived from a per-machine seed and written chmod 600. Never log key/proof
// material — only thumbprints and lengths. The seal/seed helpers live in
// src/crypto.ts (shared with the token store).
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
  SignJWT,
  type JWK,
  type KeyLike,
} from "jose";
import type { Config, DpopAlg } from "./config.ts";
import { logger as defaultLogger, type Logger } from "./logger.ts";
import { ensureBridgeHome, openJson, sealJson, type Sealed } from "./crypto.ts";

/** Private JWK members that must never appear in a public JWK / proof header. */
const PRIVATE_JWK_PARAMS = ["d", "p", "q", "dp", "dq", "qi", "k"] as const;

/** Strip all private parameters, yielding a public-only JWK. */
export function toPublicJwk(jwk: JWK): JWK {
  const pub = { ...jwk } as Record<string, unknown>;
  for (const param of PRIVATE_JWK_PARAMS) delete pub[param];
  return pub as unknown as JWK;
}

/**
 * Canonicalize an `htu` so it byte-matches the value the adapter/Okta recompute:
 * lower-case scheme + host, strip default ports (443/https, 80/http), DROP the
 * query and fragment, keep the path.
 */
export function canonicalHtu(raw: string): string {
  const u = new URL(raw);
  const scheme = u.protocol.toLowerCase(); // includes trailing ':'
  const host = u.hostname.toLowerCase();
  let port = u.port;
  if ((scheme === "https:" && port === "443") || (scheme === "http:" && port === "80")) {
    port = "";
  }
  const authority = port ? `${host}:${port}` : host;
  return `${scheme}//${authority}${u.pathname}`;
}

/** base64url(SHA-256(utf8 bytes)) with no padding. */
function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("base64url");
}

export interface CreateProofOptions {
  htm: string;
  htu: string;
  accessToken?: string;
  nonce?: string;
}

type EncryptedKeyFile = { alg: DpopAlg } & Sealed;

export class DpopKeyManager {
  private constructor(
    private readonly alg: DpopAlg,
    private readonly privateKey: KeyLike,
    private readonly publicJWK: JWK,
    private cachedJkt?: string,
  ) {}

  /**
   * Build a key manager per config.DPOP_KEY_MODE:
   *   "persistent" — load <BRIDGE_HOME>/dpop-key.json if present, else generate + persist.
   *   "ephemeral"  — generate in-memory only (re-login each start).
   */
  static async create(config: Config, logger: Logger = defaultLogger): Promise<DpopKeyManager> {
    const alg = config.DPOP_ALG;

    if (config.DPOP_KEY_MODE === "persistent") {
      ensureBridgeHome(config.BRIDGE_HOME);
      const keyPath = join(config.BRIDGE_HOME, "dpop-key.json");
      if (existsSync(keyPath)) {
        const privateJwk = loadEncryptedKey(config.BRIDGE_HOME, keyPath);
        const privateKey = (await importJWK(privateJwk, alg)) as KeyLike;
        const publicJWK = toPublicJwk(privateJwk);
        const mgr = new DpopKeyManager(alg, privateKey, publicJWK);
        logger.info("dpop.key.loaded", { jkt: await mgr.jkt() });
        return mgr;
      }
      // Persistence requires extractable keys so the private JWK can be sealed.
      const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
      const privateJwk = await exportJWK(privateKey);
      const publicJWK = await exportJWK(publicKey);
      saveEncryptedKey(config.BRIDGE_HOME, keyPath, alg, privateJwk);
      const mgr = new DpopKeyManager(alg, privateKey, publicJWK);
      logger.info("dpop.key.generated", { jkt: await mgr.jkt() });
      return mgr;
    }

    // ephemeral: in-memory only. (Could use extractable:false for stronger
    // hygiene since we never export the private key in this mode.)
    const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: false });
    const publicJWK = await exportJWK(publicKey);
    const mgr = new DpopKeyManager(alg, privateKey as KeyLike, publicJWK);
    logger.info("dpop.key.generated", { jkt: await mgr.jkt(), ephemeral: true });
    return mgr;
  }

  /** The public JWK only (no private parameters). */
  publicJwk(): JWK {
    return { ...this.publicJWK };
  }

  /** RFC 7638 thumbprint (SHA-256) of the public JWK. */
  async jkt(): Promise<string> {
    if (this.cachedJkt === undefined) {
      this.cachedJkt = await calculateJwkThumbprint(this.publicJWK, "sha256");
    }
    return this.cachedJkt;
  }

  /** Build and sign a DPoP proof JWT. */
  async createProof(opts: CreateProofOptions, logger: Logger = defaultLogger): Promise<string> {
    const htu = canonicalHtu(opts.htu);
    const payload: Record<string, unknown> = {
      jti: randomUUID(),
      htm: opts.htm.toUpperCase(),
      htu,
      iat: Math.floor(Date.now() / 1000),
    };
    if (opts.accessToken !== undefined) payload.ath = sha256Base64Url(opts.accessToken);
    if (opts.nonce !== undefined) payload.nonce = opts.nonce;

    const proof = await new SignJWT(payload)
      .setProtectedHeader({ typ: "dpop+jwt", alg: this.alg, jwk: this.publicJWK })
      .sign(this.privateKey);

    logger.debug("dpop.proof.created", {
      htm: payload.htm,
      htu,
      jkt: await this.jkt(),
      has_ath: opts.accessToken !== undefined,
      has_nonce: opts.nonce !== undefined,
    });
    return proof;
  }
}

// --- key file persistence (encryption lives in src/crypto.ts) ----------------

function saveEncryptedKey(home: string, keyPath: string, alg: DpopAlg, privateJwk: JWK): void {
  const file: EncryptedKeyFile = { alg, ...sealJson(home, privateJwk) };
  writeFileSync(keyPath, JSON.stringify(file), { mode: 0o600 });
  chmodSync(keyPath, 0o600);
}

function loadEncryptedKey(home: string, keyPath: string): JWK {
  const file = JSON.parse(readFileSync(keyPath, "utf8")) as EncryptedKeyFile;
  return openJson<JWK>(home, file);
}
