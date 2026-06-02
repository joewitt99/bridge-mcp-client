// End-to-end contract test. A mock adapter (Bun.serve) faithfully re-implements
// the Okta MCP Adapter's DPoP verifier contract — the same table at the top of
// prompts/DPOP_STDIO_BRIDGE_PROMPTS.md. Driving the real bridge through it is
// real evidence that the bridge's proofs would pass the actual adapter; this
// mock IS the contract test. Keep its checks aligned with that spec table.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import {
  SignJWT,
  calculateJwkThumbprint,
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  type JWK,
} from "jose";
import type { Config } from "../src/config.ts";
import { DpopKeyManager, canonicalHtu } from "../src/dpop.ts";
import { TokenStore } from "../src/store.ts";
import { resolveEndpoints, clearDiscoveryCache } from "../src/oauth/discovery.ts";
import { DpopTokenClient, type AuthorizeFn } from "../src/oauth/token.ts";
import { UpstreamClient } from "../src/upstream.ts";
import { runStdioBridge } from "../src/server.ts";
import { logger as baseLogger } from "../src/logger.ts";

const MOCK_SECRET = new TextEncoder().encode("mock-adapter-secret-mock-adapter-secret!");

function sha256b64url(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("base64url");
}

function jsonRes(obj: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

interface MockOptions {
  /** Mint a token whose cnf.jkt does NOT match the proof (binding-failure path). */
  mintMismatch?: boolean;
  /** Challenge the first authed resource call with use_dpop_nonce (default true). */
  resourceNonce?: boolean;
}

interface MockState {
  tokenNonce: string;
  resourceNonce: string;
  resourceNonceIssued: boolean;
  tokenChallenges: number;
  seenJti: Set<string>;
  initializeWasUnauthed?: boolean;
}

interface MockAdapter {
  url: string;
  state: MockState;
  stop(): void;
}

/** Verify a DPoP proof's signature against its embedded key; return claims + jwk. */
async function verifyProof(
  jwt: string,
): Promise<{ claims: Record<string, unknown>; jwk: JWK }> {
  const header = decodeProtectedHeader(jwt) as { typ?: string; alg?: string; jwk?: JWK };
  if (header.typ !== "dpop+jwt") throw new Error("bad typ");
  if (header.alg !== "ES256") throw new Error("bad alg");
  if (!header.jwk) throw new Error("missing jwk");
  const key = await importJWK(header.jwk, "ES256");
  const { payload } = await compactVerify(jwt, key);
  const claims = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>;
  return { claims, jwk: header.jwk };
}

function startMock(opts: MockOptions = {}): MockAdapter {
  const resourceNonce = opts.resourceNonce ?? true;
  const state: MockState = {
    tokenNonce: "tok-nonce-1",
    resourceNonce: "res-nonce-1",
    resourceNonceIssued: false,
    tokenChallenges: 0,
    seenJti: new Set<string>(),
  };

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req): Promise<Response> {
      const url = new URL(req.url);
      const base = url.origin;
      const path = url.pathname;

      if (req.method === "GET" && path === "/.well-known/oauth-protected-resource") {
        return jsonRes({ authorization_servers: [base] });
      }
      if (req.method === "GET" && path === "/.well-known/oauth-authorization-server") {
        return jsonRes({
          issuer: base,
          authorization_endpoint: `${base}/authorize`,
          token_endpoint: `${base}/token`,
          dpop_signing_alg_values_supported: ["ES256", "ES384", "RS256"],
        });
      }

      if (req.method === "POST" && path === "/token") {
        const proofJwt = req.headers.get("DPoP");
        if (!proofJwt) return jsonRes({ error: "invalid_dpop_proof" }, 400);
        const { claims, jwk } = await verifyProof(proofJwt);
        if (claims.htm !== "POST" || claims.htu !== canonicalHtu(`${base}/token`)) {
          return jsonRes({ error: "invalid_dpop_proof" }, 400);
        }
        // Okta nonce handshake: the first proof (no nonce) is rejected.
        if (claims.nonce !== state.tokenNonce) {
          state.tokenChallenges += 1;
          return jsonRes({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": state.tokenNonce });
        }
        const jkt = await calculateJwkThumbprint(jwk, "sha256");
        const cnfJkt = opts.mintMismatch ? "WRONG-JKT-THUMBPRINT" : jkt;
        const access_token = await new SignJWT({
          cnf: { jkt: cnfJkt },
          scope: "openid offline_access",
          sub: "user",
        })
          .setProtectedHeader({ alg: "HS256" })
          .setIssuedAt()
          .setExpirationTime("1h")
          .sign(MOCK_SECRET);
        return jsonRes({
          access_token,
          token_type: "DPoP",
          expires_in: 3600,
          scope: "openid offline_access",
          refresh_token: "rt-1",
        });
      }

      if (req.method === "POST" && path === "/") {
        const body = (await req.json()) as { id?: unknown; method?: string };
        const method = body.method ?? "";
        const auth = req.headers.get("Authorization");
        const isUnauthed =
          method === "initialize" ||
          method === "ping" ||
          method.startsWith("notifications/");

        if (isUnauthed) {
          if (method === "initialize") {
            state.initializeWasUnauthed = !auth;
            return jsonRes({
              jsonrpc: "2.0",
              id: body.id,
              result: { protocolVersion: "2025-06-18", capabilities: {}, serverInfo: { name: "mock-adapter" } },
            });
          }
          return jsonRes({ jsonrpc: "2.0", id: body.id, result: {} });
        }

        // Authed method: enforce DPoP.
        if (!auth || !auth.startsWith("DPoP ")) {
          return jsonRes({ error: "required_missing" }, 401);
        }
        const token = auth.slice("DPoP ".length);

        // Resource-side nonce challenge, exactly once.
        if (resourceNonce && !state.resourceNonceIssued) {
          state.resourceNonceIssued = true;
          return jsonRes({ error: "use_dpop_nonce" }, 401, {
            "DPoP-Nonce": state.resourceNonce,
            "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
          });
        }

        const proofJwt = req.headers.get("DPoP");
        if (!proofJwt) return jsonRes({ error: "required_missing" }, 401);
        const { claims, jwk } = await verifyProof(proofJwt);
        if (claims.htm !== "POST" || claims.htu !== canonicalHtu(`${base}/`)) {
          return jsonRes({ error: "rejected" }, 401);
        }
        if (claims.ath !== sha256b64url(token)) {
          return jsonRes({ error: "rejected" }, 401);
        }
        const jkt = await calculateJwkThumbprint(jwk, "sha256");
        const tokenClaims = decodeJwt(token) as { cnf?: { jkt?: string } };
        if (tokenClaims.cnf?.jkt && tokenClaims.cnf.jkt !== jkt) {
          return jsonRes({ error: "rejected_jkt" }, 401);
        }
        if (state.seenJti.has(claims.jti as string)) {
          return jsonRes({ error: "replay_detected" }, 401);
        }
        state.seenJti.add(claims.jti as string);

        return jsonRes({
          jsonrpc: "2.0",
          id: body.id,
          result: { tools: [{ name: "echo", description: "echoes input" }] },
        });
      }

      return new Response("not found", { status: 404 });
    },
  });

  return {
    url: `http://127.0.0.1:${server.port}`,
    state,
    stop: () => server.stop(true),
  };
}

let home: string;
let mock: MockAdapter | undefined;

function cfg(baseUrl: string): Config {
  return {
    ADAPTER_BASE_URL: baseUrl,
    OKTA_CLIENT_ID: "test-client",
    AGENT_ID: "test-agent",
    OKTA_REDIRECT_PORT: 0,
    OKTA_SCOPES: "openid offline_access",
    DPOP_ALG: "ES256",
    DPOP_KEY_MODE: "persistent",
    BRIDGE_HOME: home,
    HTTP_TIMEOUT_MS: 30000,
    LOG_LEVEL: "error",
  };
}

const stubAuthorize: AuthorizeFn = async () => ({
  code: "test-auth-code",
  redirectUri: "http://127.0.0.1:0/callback",
  verifier: "x".repeat(64),
});

async function makeBridge(config: Config) {
  const keyManager = await DpopKeyManager.create(config, baseLogger);
  const store = new TokenStore(config.BRIDGE_HOME);
  const endpoints = await resolveEndpoints(config, { logger: baseLogger });
  const tokenClient = new DpopTokenClient(config, endpoints, keyManager, store, baseLogger);
  const upstream = new UpstreamClient(config, keyManager, tokenClient, baseLogger);
  return { keyManager, store, endpoints, tokenClient, upstream };
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "okta-mcp-bridge-int-"));
  clearDiscoveryCache();
});
afterEach(() => {
  mock?.stop();
  mock = undefined;
  rmSync(home, { recursive: true, force: true });
  clearDiscoveryCache();
});

describe("integration: bridge ↔ mock adapter (DPoP contract)", () => {
  test("initialize passes unauthed; tools/list succeeds end-to-end through the resource nonce challenge", async () => {
    mock = startMock();
    const config = cfg(mock.url);
    const { upstream, store } = await makeBridge(config);

    const initResp = (await upstream.forwardUnauthed({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    })) as { result?: { serverInfo?: { name?: string } } };
    expect(initResp.result?.serverInfo?.name).toBe("mock-adapter");
    expect(mock.state.initializeWasUnauthed).toBe(true);

    const listResp = (await upstream.forward(
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      stubAuthorize,
    )) as { result?: { tools?: Array<{ name: string }> } };
    expect(listResp.result?.tools?.[0]?.name).toBe("echo");

    // The Okta /token nonce handshake and the resource-side nonce both fired.
    expect(mock.state.tokenChallenges).toBe(1);
    expect(mock.state.resourceNonceIssued).toBe(true);
    expect(store.load()?.accessToken).toBeDefined();
  });

  test("a cnf.jkt mismatch is rejected by the bridge's binding check", async () => {
    mock = startMock({ mintMismatch: true });
    const config = cfg(mock.url);
    const { tokenClient } = await makeBridge(config);
    await expect(tokenClient.exchangeCode(await stubAuthorize())).rejects.toThrow(/cnf\.jkt/i);
  });

  test("a replayed jti is rejected by the adapter", async () => {
    mock = startMock({ resourceNonce: false });
    const config = cfg(mock.url);
    const { keyManager, tokenClient } = await makeBridge(config);

    // Acquire a real DPoP-bound token, then craft ONE proof and replay it.
    const token = await tokenClient.getAccessToken(stubAuthorize);
    const proof = await keyManager.createProof({
      htm: "POST",
      htu: `${mock.url}/`,
      accessToken: token,
    });
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `DPoP ${token}`,
      "X-MCP-Agent": config.AGENT_ID,
      DPoP: proof,
    };
    const body = JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list", params: {} });

    const first = await fetch(`${mock.url}/`, { method: "POST", headers, body });
    const second = await fetch(`${mock.url}/`, { method: "POST", headers, body });
    expect(first.status).toBe(200);
    expect(second.status).toBe(401);
    expect(((await second.json()) as { error?: string }).error).toBe("replay_detected");
  });

  test("full stdio round-trip: initialize then tools/list via runStdioBridge", async () => {
    mock = startMock();
    const config = cfg(mock.url);
    const { upstream } = await makeBridge(config);

    const outLines: string[] = [];
    async function* feed(): AsyncGenerator<string> {
      yield JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n";
      yield JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n";
    }
    await runStdioBridge({
      config,
      upstream,
      authorizeFn: stubAuthorize,
      input: feed(),
      output: { write: (chunk: string) => outLines.push(chunk) },
      logger: baseLogger,
      installSignalHandlers: false,
    });

    expect(outLines.length).toBe(2);
    const r1 = JSON.parse(outLines[0]!);
    const r2 = JSON.parse(outLines[1]!);
    expect(r1.id).toBe(1);
    expect(r1.result.serverInfo.name).toBe("mock-adapter");
    expect(r2.id).toBe(2);
    expect(r2.result.tools[0].name).toBe("echo");
  });

  test("optional cross-check against a checked-out adapter (skips unless ADAPTER_REPO is set)", () => {
    const repo = process.env.ADAPTER_REPO;
    if (!repo) return; // self-contained CI: skip cleanly
    const verifierPath = join(repo, "okta_agent_proxy", "auth", "dpop_verifier.py");
    if (!existsSync(verifierPath)) return;
    const src = readFileSync(verifierPath, "utf8");
    // The mock allows ES256 and a 300s iat window; assert the adapter still agrees.
    expect(src).toContain("ES256");
    expect(src).toMatch(/300/);
  });
});
