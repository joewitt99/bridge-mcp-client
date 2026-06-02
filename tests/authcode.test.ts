import { describe, expect, test } from "bun:test";
import type { Config } from "../src/config.ts";
import { authorize, type Opener } from "../src/oauth/authcode.ts";
import type { Endpoints } from "../src/oauth/discovery.ts";

const PORT = 0; // ephemeral loopback port (avoids cross-test collisions)
const LOOPBACK = /^http:\/\/127\.0\.0\.1:\d+\/callback$/;

function cfg(overrides: Partial<Config> = {}): Config {
  return {
    ADAPTER_BASE_URL: "https://adapter.example.com",
    OKTA_CLIENT_ID: "cid",
    AGENT_ID: "agent-1",
    OKTA_REDIRECT_PORT: PORT,
    OKTA_SCOPES: "openid offline_access",
    DPOP_ALG: "ES256",
    DPOP_KEY_MODE: "persistent",
    BRIDGE_HOME: "/tmp/unused",
    HTTP_TIMEOUT_MS: 30000,
    LOG_LEVEL: "error",
    ...overrides,
  };
}

const endpoints: Endpoints = {
  issuer: "https://okta.example.com",
  authorizationEndpoint: "https://okta.example.com/oauth2/v1/authorize",
  tokenEndpoint: "https://okta.example.com/oauth2/v1/token",
};

/** An opener that hits the loopback /callback with the given query overrides. */
function callbackOpener(
  params: (parsed: { state: string; redirectUri: string }) => Record<string, string>,
): Opener {
  return async (authUrl: string) => {
    const u = new URL(authUrl);
    const state = u.searchParams.get("state")!;
    const redirectUri = u.searchParams.get("redirect_uri")!;
    const cb = new URL(redirectUri);
    for (const [k, v] of Object.entries(params({ state, redirectUri }))) {
      cb.searchParams.set(k, v);
    }
    await fetch(cb.toString());
  };
}

describe("authorize", () => {
  test("the authorize URL carries PKCE + loopback params", async () => {
    let seen: URL | undefined;
    const opener: Opener = async (authUrl) => {
      seen = new URL(authUrl);
      const cb = new URL(seen.searchParams.get("redirect_uri")!);
      cb.searchParams.set("state", seen.searchParams.get("state")!);
      cb.searchParams.set("code", "abc");
      await fetch(cb.toString());
    };
    await authorize(cfg(), endpoints, { opener });
    expect(seen!.origin + seen!.pathname).toBe(
      "https://okta.example.com/oauth2/v1/authorize",
    );
    expect(seen!.searchParams.get("response_type")).toBe("code");
    expect(seen!.searchParams.get("client_id")).toBe("cid");
    expect(seen!.searchParams.get("redirect_uri")).toMatch(LOOPBACK);
    expect(seen!.searchParams.get("scope")).toBe("openid offline_access");
    expect(seen!.searchParams.get("code_challenge_method")).toBe("S256");
    expect(seen!.searchParams.get("code_challenge")).toBeTruthy();
    expect(seen!.searchParams.get("state")).toBeTruthy();
  });

  test("valid state + code resolves with code, redirectUri, verifier", async () => {
    const opener = callbackOpener(({ state }) => ({ state, code: "the-code" }));
    const result = await authorize(cfg(), endpoints, { opener });
    expect(result.code).toBe("the-code");
    expect(result.redirectUri).toMatch(LOOPBACK);
    expect(result.verifier.length).toBeGreaterThanOrEqual(43);
  });

  test("state mismatch rejects", async () => {
    const opener = callbackOpener(() => ({ state: "WRONG", code: "x" }));
    await expect(authorize(cfg(), endpoints, { opener })).rejects.toThrow(
      /state mismatch/,
    );
  });

  test("an ?error param rejects", async () => {
    const opener = callbackOpener(({ state }) => ({
      state,
      error: "access_denied",
      error_description: "user said no",
    }));
    await expect(authorize(cfg(), endpoints, { opener })).rejects.toThrow(
      /access_denied/,
    );
  });

  test("times out when no callback arrives", async () => {
    const opener: Opener = () => {
      /* never hits the callback */
    };
    await expect(
      authorize(cfg(), endpoints, { opener, timeoutMs: 50 }),
    ).rejects.toThrow(/timed out/);
  });
});
