import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import type { Config } from "../src/config.ts";
import {
  clearDiscoveryCache,
  resolveEndpoints,
} from "../src/oauth/discovery.ts";
import { logger } from "../src/logger.ts";

function cfg(overrides: Partial<Config> = {}): Config {
  return {
    ADAPTER_BASE_URL: "https://adapter.example.com",
    OKTA_CLIENT_ID: "cid",
    AGENT_ID: "agent-1",
    OKTA_REDIRECT_PORT: 0,
    OKTA_SCOPES: "openid offline_access",
    DPOP_ALG: "ES256",
    DPOP_KEY_MODE: "persistent",
    BRIDGE_HOME: "/tmp/unused",
    HTTP_TIMEOUT_MS: 30000,
    LOG_LEVEL: "error",
    ...overrides,
  };
}

/** A fetch stub that returns JSON keyed by URL substring. */
function stubFetch(routes: Record<string, unknown>): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0]) => {
    const url = String(input);
    for (const [needle, body] of Object.entries(routes)) {
      if (url.includes(needle)) {
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
    }
    return new Response("not found", { status: 404 });
  }) as unknown as typeof fetch;
}

const PRM = "oauth-protected-resource";
const AS = "oauth-authorization-server";
const OIDC = "openid-configuration";

beforeEach(() => clearDiscoveryCache());
afterEach(() => clearDiscoveryCache());

describe("resolveEndpoints", () => {
  test("PRM → AS metadata resolution", async () => {
    const fetch = stubFetch({
      [PRM]: { authorization_servers: ["https://as.example.com"] },
      [AS]: {
        issuer: "https://as.example.com",
        authorization_endpoint: "https://as.example.com/authorize",
        token_endpoint: "https://as.example.com/token",
        registration_endpoint: "https://as.example.com/register",
      },
    });
    const ep = await resolveEndpoints(cfg(), { fetch });
    expect(ep.issuer).toBe("https://as.example.com");
    expect(ep.authorizationEndpoint).toBe("https://as.example.com/authorize");
    expect(ep.tokenEndpoint).toBe("https://as.example.com/token");
    expect(ep.registrationEndpoint).toBe("https://as.example.com/register");
  });

  test("OKTA_ISSUER override pulls token_endpoint from openid-configuration", async () => {
    const fetch = stubFetch({
      [PRM]: { authorization_servers: ["https://as.example.com"] },
      [AS]: {
        issuer: "https://as.example.com",
        authorization_endpoint: "https://as.example.com/authorize",
        token_endpoint: "https://as.example.com/token",
      },
      [OIDC]: {
        issuer: "https://okta.example.com",
        authorization_endpoint: "https://okta.example.com/oauth2/v1/authorize",
        token_endpoint: "https://okta.example.com/oauth2/v1/token",
      },
    });
    const ep = await resolveEndpoints(
      cfg({ OKTA_ISSUER: "https://okta.example.com" }),
      { fetch },
    );
    expect(ep.issuer).toBe("https://okta.example.com");
    expect(ep.tokenEndpoint).toBe("https://okta.example.com/oauth2/v1/token");
    expect(ep.authorizationEndpoint).toBe(
      "https://okta.example.com/oauth2/v1/authorize",
    );
  });

  test("warns when DPOP_ALG is unsupported by the AS", async () => {
    const calls: string[] = [];
    const child = {
      ...logger,
      warn: (event: string) => calls.push(event),
    } as typeof logger;
    const fetch = stubFetch({
      [PRM]: { authorization_servers: ["https://as.example.com"] },
      [AS]: {
        issuer: "https://as.example.com",
        authorization_endpoint: "https://as.example.com/authorize",
        token_endpoint: "https://as.example.com/token",
        dpop_signing_alg_values_supported: ["RS256", "ES384"],
      },
    });
    await resolveEndpoints(cfg({ DPOP_ALG: "ES256" }), { fetch, logger: child });
    expect(calls).toContain("oauth.dpop.alg_unsupported");
  });

  test("does NOT warn when DPOP_ALG is supported", async () => {
    const calls: string[] = [];
    const child = {
      ...logger,
      warn: (event: string) => calls.push(event),
    } as typeof logger;
    const fetch = stubFetch({
      [PRM]: { authorization_servers: ["https://as.example.com"] },
      [AS]: {
        authorization_endpoint: "https://as.example.com/authorize",
        token_endpoint: "https://as.example.com/token",
        dpop_signing_alg_values_supported: ["ES256", "RS256"],
      },
    });
    await resolveEndpoints(cfg({ DPOP_ALG: "ES256" }), { fetch, logger: child });
    expect(calls).not.toContain("oauth.dpop.alg_unsupported");
  });

  test("caches resolved metadata for the process lifetime", async () => {
    let prmCalls = 0;
    const countingFetch = (async (input: Parameters<typeof fetch>[0]) => {
      const url = String(input);
      if (url.includes(PRM)) {
        prmCalls += 1;
        return new Response(
          JSON.stringify({ authorization_servers: ["https://as.example.com"] }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          authorization_endpoint: "https://as.example.com/authorize",
          token_endpoint: "https://as.example.com/token",
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    await resolveEndpoints(cfg(), { fetch: countingFetch });
    await resolveEndpoints(cfg(), { fetch: countingFetch });
    expect(prmCalls).toBe(1);
  });

  test("throws when the resource metadata has no authorization_servers", async () => {
    const fetch = stubFetch({ [PRM]: {} });
    await expect(resolveEndpoints(cfg(), { fetch })).rejects.toThrow(
      /authorization_servers/,
    );
  });
});
