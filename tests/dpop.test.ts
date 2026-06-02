import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, statSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from "jose";
import type { Config } from "../src/config.ts";
import { DpopKeyManager, canonicalHtu, toPublicJwk } from "../src/dpop.ts";

let home: string;

function cfg(overrides: Partial<Config> = {}): Config {
  return {
    ADAPTER_BASE_URL: "https://adapter.example.com",
    OKTA_CLIENT_ID: "cid",
    AGENT_ID: "agent-1",
    OKTA_REDIRECT_PORT: 0,
    OKTA_SCOPES: "openid offline_access",
    DPOP_ALG: "ES256",
    DPOP_KEY_MODE: "persistent",
    BRIDGE_HOME: home,
    HTTP_TIMEOUT_MS: 30000,
    LOG_LEVEL: "error",
    ...overrides,
  };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "okta-mcp-bridge-"));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe("createProof", () => {
  test("header is typ dpop+jwt, alg ES256, with an embedded public JWK", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const proof = await mgr.createProof({ htm: "post", htu: "https://adapter.example.com/" });
    const header = decodeProtectedHeader(proof) as { typ?: string; alg?: string; jwk?: JWK };
    expect(header.typ).toBe("dpop+jwt");
    expect(header.alg).toBe("ES256");
    expect(header.jwk).toBeDefined();
    expect(header.jwk?.kty).toBe("EC");
    expect(header.jwk?.crv).toBe("P-256");
  });

  test("embedded jwk has NO private parameters", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const proof = await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/" });
    const header = decodeProtectedHeader(proof) as { jwk?: Record<string, unknown> };
    for (const param of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
      expect(header.jwk?.[param]).toBeUndefined();
    }
  });

  test("payload has jti, upper-cased htm, canonical htu, and iat", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const before = Math.floor(Date.now() / 1000);
    const proof = await mgr.createProof({
      htm: "post",
      htu: "https://Adapter.Example.com:443/?q=1#frag",
    });
    const payload = decodeJwt(proof);
    expect(typeof payload.jti).toBe("string");
    expect((payload.jti as string).length).toBeGreaterThan(0);
    expect(payload.htm).toBe("POST");
    expect(payload.htu).toBe("https://adapter.example.com/");
    expect(typeof payload.iat).toBe("number");
    expect(payload.iat as number).toBeGreaterThanOrEqual(before);
  });

  test("ath is present and correct when an accessToken is provided", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const token = "access-token-xyz";
    const proof = await mgr.createProof({
      htm: "POST",
      htu: "https://adapter.example.com/",
      accessToken: token,
    });
    const payload = decodeJwt(proof) as { ath?: string };
    const expected = createHash("sha256").update(token, "utf8").digest("base64url");
    expect(payload.ath).toBe(expected);
  });

  test("ath is absent when no accessToken is provided", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const proof = await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/" });
    const payload = decodeJwt(proof) as { ath?: string };
    expect(payload.ath).toBeUndefined();
  });

  test("nonce is included only when provided", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const without = decodeJwt(
      await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/" }),
    ) as { nonce?: string };
    expect(without.nonce).toBeUndefined();

    const withNonce = decodeJwt(
      await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/", nonce: "abc123" }),
    ) as { nonce?: string };
    expect(withNonce.nonce).toBe("abc123");
  });

  test("jti is unique across two proofs", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const a = decodeJwt(await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/" }));
    const b = decodeJwt(await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/" }));
    expect(a.jti).not.toBe(b.jti);
  });

  test("signature verifies against the embedded public key", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const proof = await mgr.createProof({ htm: "POST", htu: "https://adapter.example.com/" });
    const header = decodeProtectedHeader(proof) as { jwk: JWK };
    const publicKey = await importJWK(header.jwk, "ES256");
    const result = await compactVerify(proof, publicKey);
    expect(result.protectedHeader.typ).toBe("dpop+jwt");
  });
});

describe("canonicalHtu", () => {
  test("drops query + fragment, strips :443, lower-cases host", () => {
    expect(canonicalHtu("https://Host.EXAMPLE.com:443/?q=1#f")).toBe("https://host.example.com/");
  });

  test("strips :80 for http and keeps the path", () => {
    expect(canonicalHtu("http://Host.example.com:80/token")).toBe("http://host.example.com/token");
  });

  test("keeps a non-default port", () => {
    expect(canonicalHtu("https://host.example.com:8443/cb?x=1")).toBe(
      "https://host.example.com:8443/cb",
    );
  });
});

describe("toPublicJwk", () => {
  test("removes all private parameters", () => {
    const full: JWK = { kty: "EC", crv: "P-256", x: "X", y: "Y", d: "SECRET" };
    const pub = toPublicJwk(full);
    expect(pub.d).toBeUndefined();
    expect(pub.x).toBe("X");
    expect(pub.y).toBe("Y");
  });
});

describe("key persistence", () => {
  test("persistent mode: a second manager loads the SAME jkt from disk", async () => {
    const first = await DpopKeyManager.create(cfg());
    const second = await DpopKeyManager.create(cfg());
    expect(await second.jkt()).toBe(await first.jkt());
  });

  test("ephemeral mode: a second manager has a DIFFERENT jkt", async () => {
    const first = await DpopKeyManager.create(cfg({ DPOP_KEY_MODE: "ephemeral" }));
    const second = await DpopKeyManager.create(cfg({ DPOP_KEY_MODE: "ephemeral" }));
    expect(await second.jkt()).not.toBe(await first.jkt());
  });

  test("dpop-key.json and .seed are chmod 600", async () => {
    await DpopKeyManager.create(cfg());
    const keyMode = statSync(join(home, "dpop-key.json")).mode & 0o777;
    const seedMode = statSync(join(home, ".seed")).mode & 0o777;
    expect(keyMode).toBe(0o600);
    expect(seedMode).toBe(0o600);
  });

  test("the key file is not the plaintext exported JWK", async () => {
    const mgr = await DpopKeyManager.create(cfg());
    const raw = readFileSync(join(home, "dpop-key.json"), "utf8");
    // No private 'd' member and no public 'x' coordinate appear in plaintext.
    expect(raw).not.toContain('"d"');
    expect(raw).not.toContain('"x"');
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    expect(parsed.ciphertext).toBeDefined();
    expect(parsed.iv).toBeDefined();
    expect(parsed.tag).toBeDefined();

    // ...and the round-tripped key is usable: same jkt after reload.
    const reloaded = await DpopKeyManager.create(cfg());
    expect(await reloaded.jkt()).toBe(await mgr.jkt());
    expect(existsSync(join(home, "dpop-key.json"))).toBe(true);
  });
});
