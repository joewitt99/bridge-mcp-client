import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { decodeJwt } from "jose";
import type { Config } from "../src/config.ts";
import { DpopKeyManager, canonicalHtu } from "../src/dpop.ts";
import { UpstreamClient, type TokenProvider } from "../src/upstream.ts";
import { logger as baseLogger } from "../src/logger.ts";

const ADAPTER = "https://adapter.example.com";
let home: string;

function cfg(overrides: Partial<Config> = {}): Config {
  return {
    ADAPTER_BASE_URL: ADAPTER,
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

interface RecordedCall {
  url: string;
  init: RequestInit;
}

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

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function headersOf(call: RecordedCall): Record<string, string> {
  return call.init.headers as Record<string, string>;
}

/** A TokenProvider stub that hands out a sequence of tokens. */
function stubTokens(...tokens: string[]): TokenProvider & { cleared: number; issued: string[] } {
  let i = 0;
  const issued: string[] = [];
  return {
    cleared: 0,
    issued,
    async getAccessToken() {
      const t = tokens[Math.min(i, tokens.length - 1)]!;
      i += 1;
      issued.push(t);
      return t;
    },
    clearStored() {
      this.cleared += 1;
    },
  };
}

const authorizeFn = async () => ({
  code: "c",
  redirectUri: "http://127.0.0.1:0/callback",
  verifier: "v",
});
const REQ = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

async function km(): Promise<DpopKeyManager> {
  return DpopKeyManager.create(cfg(), baseLogger);
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "okta-mcp-bridge-up-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe("UpstreamClient.forward auth headers", () => {
  test("attaches Authorization: DPoP, X-MCP-Agent, and a DPoP proof", async () => {
    const { fetch, calls } = mockFetch([() => jsonResponse({ jsonrpc: "2.0", id: 1, result: {} })]);
    const client = new UpstreamClient(cfg(), await km(), stubTokens("tok-abc"), baseLogger, { fetch });
    await client.forward(REQ, authorizeFn);
    const h = headersOf(calls[0]!);
    expect(h.Authorization).toBe("DPoP tok-abc");
    expect(h["X-MCP-Agent"]).toBe("agent-1");
    expect(h.DPoP).toBeDefined();
  });

  test("the proof has htm POST, canonical htu '<base>/', and ath matching the token", async () => {
    const { fetch, calls } = mockFetch([() => jsonResponse({ jsonrpc: "2.0", id: 1, result: {} })]);
    const client = new UpstreamClient(cfg(), await km(), stubTokens("tok-xyz"), baseLogger, { fetch });
    await client.forward(REQ, authorizeFn);
    const proof = decodeJwt(headersOf(calls[0]!).DPoP!) as Record<string, unknown>;
    expect(proof.htm).toBe("POST");
    expect(proof.htu).toBe(canonicalHtu(`${ADAPTER}/`));
    const expectedAth = createHash("sha256").update("tok-xyz", "utf8").digest("base64url");
    expect(proof.ath).toBe(expectedAth);
  });

  test("forwardUnauthed sends NO Authorization/DPoP/X-MCP-Agent headers", async () => {
    const { fetch, calls } = mockFetch([() => jsonResponse({ jsonrpc: "2.0", id: 1, result: {} })]);
    const client = new UpstreamClient(cfg(), await km(), stubTokens("tok"), baseLogger, { fetch });
    await client.forwardUnauthed({ jsonrpc: "2.0", id: 1, method: "initialize" });
    const h = headersOf(calls[0]!);
    expect(h.Authorization).toBeUndefined();
    expect(h.DPoP).toBeUndefined();
    expect(h["X-MCP-Agent"]).toBeUndefined();
  });
});

describe("UpstreamClient sessions + SSE", () => {
  test("captures Mcp-Session-Id from a response and sends it next time", async () => {
    const { fetch, calls } = mockFetch([
      () => jsonResponse({ jsonrpc: "2.0", id: 1, result: {} }, 200, { "Mcp-Session-Id": "sess-9" }),
      () => jsonResponse({ jsonrpc: "2.0", id: 2, result: {} }),
    ]);
    const client = new UpstreamClient(cfg(), await km(), stubTokens("t"), baseLogger, { fetch });
    await client.forward(REQ, authorizeFn);
    await client.forward({ ...REQ, id: 2 }, authorizeFn);
    expect(headersOf(calls[0]!)["Mcp-Session-Id"]).toBeUndefined();
    expect(headersOf(calls[1]!)["Mcp-Session-Id"]).toBe("sess-9");
  });

  test("parses an SSE response body (last data: line)", async () => {
    const sse =
      "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[\"a\"]}}\n\n";
    const { fetch } = mockFetch([
      () => new Response(sse, { status: 200, headers: { "Content-Type": "text/event-stream" } }),
    ]);
    const client = new UpstreamClient(cfg(), await km(), stubTokens("t"), baseLogger, { fetch });
    const res = (await client.forward(REQ, authorizeFn)) as { result?: { tools?: string[] } };
    expect(res.result?.tools).toEqual(["a"]);
  });
});

describe("UpstreamClient 401 recovery", () => {
  test("401 use_dpop_nonce caches the nonce and retries once (second proof has nonce)", async () => {
    const { fetch, calls } = mockFetch([
      () =>
        jsonResponse({ error: "use_dpop_nonce" }, 401, {
          "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
          "DPoP-Nonce": "rs-nonce-1",
        }),
      () => jsonResponse({ jsonrpc: "2.0", id: 1, result: {} }),
    ]);
    const tokens = stubTokens("tok-1");
    const client = new UpstreamClient(cfg(), await km(), tokens, baseLogger, { fetch });
    await client.forward(REQ, authorizeFn);
    expect(calls.length).toBe(2);
    expect(tokens.cleared).toBe(0);
    const proof0 = decodeJwt(headersOf(calls[0]!).DPoP!) as Record<string, unknown>;
    const proof1 = decodeJwt(headersOf(calls[1]!).DPoP!) as Record<string, unknown>;
    expect(proof0.nonce).toBeUndefined();
    expect(proof1.nonce).toBe("rs-nonce-1");
  });

  test("401 without nonce clears the token, re-acquires, and retries once", async () => {
    const { fetch, calls } = mockFetch([
      () => jsonResponse({ jsonrpc: "2.0", id: 1, error: { code: -32000, message: "unauthorized" } }, 401),
      () => jsonResponse({ jsonrpc: "2.0", id: 1, result: {} }),
    ]);
    const tokens = stubTokens("tok-old", "tok-new");
    const client = new UpstreamClient(cfg(), await km(), tokens, baseLogger, { fetch });
    await client.forward(REQ, authorizeFn);
    expect(calls.length).toBe(2);
    expect(tokens.cleared).toBe(1);
    expect(headersOf(calls[0]!).Authorization).toBe("DPoP tok-old");
    expect(headersOf(calls[1]!).Authorization).toBe("DPoP tok-new");
  });

  test("persistent 401 yields a JSON-RPC error -32001 (no throw)", async () => {
    const { fetch } = mockFetch([() => jsonResponse({ error: "denied" }, 401)]);
    const client = new UpstreamClient(cfg(), await km(), stubTokens("t1", "t2"), baseLogger, { fetch });
    const res = (await client.forward(REQ, authorizeFn)) as { error?: { code?: number }; id?: unknown };
    expect(res.error?.code).toBe(-32001);
    expect(res.id).toBe(1);
  });

  test("a timeout yields a JSON-RPC error (no throw)", async () => {
    // Never resolves; aborts when the send AbortController fires.
    const hangingFetch = ((url: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new DOMException("aborted", "AbortError")),
        );
      })) as unknown as typeof fetch;
    const client = new UpstreamClient(
      cfg({ HTTP_TIMEOUT_MS: 5 }),
      await km(),
      stubTokens("t"),
      baseLogger,
      { fetch: hangingFetch },
    );
    const res = (await client.forward(REQ, authorizeFn)) as { error?: { code?: number } };
    expect(res.error?.code).toBe(-32000);
  });

  test("forwardUnauthed maps a network error to a JSON-RPC error (no throw)", async () => {
    const failing = (() => Promise.reject(new Error("ECONNREFUSED"))) as unknown as typeof fetch;
    const client = new UpstreamClient(cfg(), await km(), stubTokens("t"), baseLogger, { fetch: failing });
    const res = (await client.forwardUnauthed({ jsonrpc: "2.0", id: 7, method: "initialize" })) as {
      error?: { code?: number };
      id?: unknown;
    };
    expect(res.error?.code).toBe(-32000);
    expect(res.id).toBe(7);
  });
});
