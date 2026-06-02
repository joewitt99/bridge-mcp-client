import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, statSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SignJWT, decodeJwt } from "jose";
import type { Config } from "../src/config.ts";
import { DpopKeyManager, canonicalHtu } from "../src/dpop.ts";
import { TokenStore, type TokenSet } from "../src/store.ts";
import { DpopTokenClient } from "../src/oauth/token.ts";
import type { Endpoints } from "../src/oauth/discovery.ts";
import { logger as baseLogger, type Logger } from "../src/logger.ts";

const TOKEN_ENDPOINT = "https://okta.example.com/oauth2/v1/token";
const endpoints: Endpoints = {
  issuer: "https://okta.example.com",
  authorizationEndpoint: "https://okta.example.com/oauth2/v1/authorize",
  tokenEndpoint: TOKEN_ENDPOINT,
};

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

/** Mint a fake (HS256) access-token JWT; the client decodes without verifying. */
const SECRET = new TextEncoder().encode("test-secret-test-secret-test-secret-xx");
async function mintToken(claims: Record<string, unknown>): Promise<string> {
  return await new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .sign(SECRET);
}

interface RecordedCall {
  url: string;
  init: RequestInit;
}

/** Sequenced mock fetch: each handler maps to one call (last handler repeats). */
function mockFetch(handlers: Array<() => Response | Promise<Response>>): {
  fetch: typeof fetch;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const fn = (async (url: Parameters<typeof fetch>[0], init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const h = handlers[Math.min(calls.length - 1, handlers.length - 1)]!;
    return await h();
  }) as unknown as typeof fetch;
  return { fetch: fn, calls };
}

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

/** Decode the DPoP proof JWT a recorded call carried. */
function proofOf(call: RecordedCall): Record<string, unknown> {
  const headers = call.init.headers as Record<string, string>;
  return decodeJwt(headers.DPoP!) as Record<string, unknown>;
}

function bodyParams(call: RecordedCall): URLSearchParams {
  return new URLSearchParams(call.init.body as string);
}

/** A logger that records emitted event names per level. */
function recordingLogger(): { logger: Logger; events: Record<string, string[]> } {
  const events: Record<string, string[]> = { info: [], warn: [], error: [], debug: [] };
  const make = (): Logger => ({
    log: (level, event) => events[level]!.push(event),
    debug: (event) => events.debug!.push(event),
    info: (event) => events.info!.push(event),
    warn: (event) => events.warn!.push(event),
    error: (event) => events.error!.push(event),
    withCorrelation: () => make(),
  });
  return { logger: make(), events };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "okta-mcp-bridge-tok-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

async function setup(handlers: Array<() => Response | Promise<Response>>, logger?: Logger) {
  const km = await DpopKeyManager.create(cfg(), baseLogger);
  const store = new TokenStore(home);
  const { fetch, calls } = mockFetch(handlers);
  const client = new DpopTokenClient(cfg(), endpoints, km, store, logger ?? baseLogger, {
    fetch,
  });
  return { km, store, client, calls };
}

const CODE = { code: "the-code", redirectUri: "http://127.0.0.1:5555/callback", verifier: "v".repeat(43) };

describe("DpopTokenClient nonce handshake", () => {
  test("first /token use_dpop_nonce → retry succeeds in exactly two fetches, second proof has the nonce", async () => {
    const { km, client, calls } = await setup([
      () => jsonResponse({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": "nonce-1" }),
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
          scope: "openid offline_access",
        }),
    ]);
    await client.exchangeCode(CODE);
    expect(calls.length).toBe(2);
    expect(proofOf(calls[0]!).nonce).toBeUndefined();
    expect(proofOf(calls[1]!).nonce).toBe("nonce-1");
  });

  test("token-request proof has htm POST and canonical htu == tokenEndpoint", async () => {
    const { km, client, calls } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    await client.exchangeCode(CODE);
    const proof = proofOf(calls[0]!);
    expect(proof.htm).toBe("POST");
    expect(proof.htu).toBe(canonicalHtu(TOKEN_ENDPOINT));
  });

  test("a later use_dpop_nonce triggers another single retry", async () => {
    const { km, client, store, calls } = await setup([
      // exchange: challenge then success
      () => jsonResponse({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": "nonce-1" }),
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
          refresh_token: "rt-1",
        }),
      // refresh: Okta rotated the nonce → challenge again, then success
      () => jsonResponse({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": "nonce-2" }),
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    const set = await client.exchangeCode(CODE);
    await client.refresh(set);
    expect(calls.length).toBe(4);
    expect(proofOf(calls[3]!).nonce).toBe("nonce-2");
    expect(store.load()).not.toBeNull();
  });
});

describe("DpopTokenClient exchange + binding", () => {
  test("exchangeCode persists a TokenSet with jkt == keyManager.jkt()", async () => {
    const { km, client, store } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    const set = await client.exchangeCode(CODE);
    expect(set.jkt).toBe(await km.jkt());
    const loaded = store.load();
    expect(loaded?.jkt).toBe(await km.jkt());
    expect(loaded?.accessToken).toBe(set.accessToken);
  });

  test("token_type != DPoP warns but does not throw", async () => {
    const { logger, events } = recordingLogger();
    const { km, client } = await setup(
      [
        async () =>
          jsonResponse({
            access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
            token_type: "Bearer",
            expires_in: 3600,
          }),
      ],
      logger,
    );
    await client.exchangeCode(CODE);
    expect(events.warn).toContain("oauth.token.not_dpop_bound");
  });

  test("cnf.jkt mismatch throws", async () => {
    const { client } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: "WRONG-THUMBPRINT" } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    await expect(client.exchangeCode(CODE)).rejects.toThrow(/cnf\.jkt/);
  });

  test("absent cnf does not throw", async () => {
    const { client } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ sub: "user" }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    const set = await client.exchangeCode(CODE);
    expect(set.accessToken).toBeDefined();
  });

  test("tokens.json is chmod 600 and not plaintext", async () => {
    const { km, client } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    const set = await client.exchangeCode(CODE);
    const path = join(home, "tokens.json");
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const raw = readFileSync(path, "utf8");
    expect(raw).not.toContain(set.accessToken);
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    expect(parsed.ciphertext).toBeDefined();
    expect(parsed.iv).toBeDefined();
    expect(parsed.tag).toBeDefined();
  });
});

describe("DpopTokenClient refresh + getAccessToken", () => {
  test("refresh sends grant_type=refresh_token with a DPoP proof and persists", async () => {
    const { km, client, store, calls } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    const prior: TokenSet = {
      accessToken: "old",
      refreshToken: "rt-1",
      tokenType: "DPoP",
      expiresAt: 0,
      scope: "openid offline_access",
      jkt: await km.jkt(),
    };
    const next = await client.refresh(prior);
    const params = bodyParams(calls[0]!);
    expect(params.get("grant_type")).toBe("refresh_token");
    expect(params.get("refresh_token")).toBe("rt-1");
    expect((calls[0]!.init.headers as Record<string, string>).DPoP).toBeDefined();
    // refresh_token carried forward when not rotated
    expect(next.refreshToken).toBe("rt-1");
    expect(store.load()?.accessToken).toBe(next.accessToken);
  });

  test("getAccessToken: valid stored token → no network", async () => {
    const { km, client, store, calls } = await setup([
      () => jsonResponse({ error: "should_not_be_called" }, 500),
    ]);
    store.save({
      accessToken: "still-good",
      tokenType: "DPoP",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
      scope: "openid",
      jkt: await km.jkt(),
    });
    const token = await client.getAccessToken(async () => {
      throw new Error("authorizeFn must not run");
    });
    expect(token).toBe("still-good");
    expect(calls.length).toBe(0);
  });

  test("getAccessToken: expired with refresh_token → refreshes", async () => {
    const { km, client, store, calls } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    store.save({
      accessToken: "expired",
      refreshToken: "rt-9",
      tokenType: "DPoP",
      expiresAt: Math.floor(Date.now() / 1000) - 10,
      scope: "openid",
      jkt: await km.jkt(),
    });
    const token = await client.getAccessToken(async () => {
      throw new Error("authorizeFn must not run on refresh");
    });
    expect(token).not.toBe("expired");
    expect(bodyParams(calls[0]!).get("grant_type")).toBe("refresh_token");
  });

  test("getAccessToken: no stored token → authorizeFn + exchange", async () => {
    const { km, client, calls } = await setup([
      async () =>
        jsonResponse({
          access_token: await mintToken({ cnf: { jkt: await km.jkt() } }),
          token_type: "DPoP",
          expires_in: 3600,
        }),
    ]);
    let authorized = false;
    const token = await client.getAccessToken(async () => {
      authorized = true;
      return CODE;
    });
    expect(authorized).toBe(true);
    expect(token).toBeDefined();
    expect(bodyParams(calls[0]!).get("grant_type")).toBe("authorization_code");
  });
});
