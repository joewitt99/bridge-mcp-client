import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs, runCli } from "../src/cli.ts";
import { clearDiscoveryCache } from "../src/oauth/discovery.ts";
import { DpopKeyManager } from "../src/dpop.ts";
import { TokenStore } from "../src/store.ts";
import { logger as baseLogger } from "../src/logger.ts";

let home: string;
let stderrSpy: ReturnType<typeof spyOn>;
let stderrText: string;

function baseEnv(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    ADAPTER_BASE_URL: "https://adapter.example.com",
    OKTA_CLIENT_ID: "cid",
    AGENT_ID: "agent-1",
    BRIDGE_HOME: home,
    LOG_LEVEL: "error",
    ...overrides,
  };
}

/** Stub fetch serving discovery + a POST / initialize result. */
function reachableFetch(): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0]) => {
    const url = String(input);
    if (url.includes("well-known/oauth-protected-resource")) {
      return new Response(
        JSON.stringify({ authorization_servers: ["https://as.example.com"] }),
        { status: 200 },
      );
    }
    if (url.includes("well-known/oauth-authorization-server")) {
      return new Response(
        JSON.stringify({
          authorization_endpoint: "https://as.example.com/authorize",
          token_endpoint: "https://as.example.com/token",
        }),
        { status: 200 },
      );
    }
    // POST / — initialize round-trip
    return new Response(
      JSON.stringify({ jsonrpc: "2.0", id: 1, result: { capabilities: {} } }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as unknown as typeof fetch;
}

const unreachableFetch = (() => Promise.reject(new Error("ECONNREFUSED"))) as unknown as typeof fetch;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "okta-mcp-bridge-cli-"));
  clearDiscoveryCache();
  stderrText = "";
  stderrSpy = spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
    stderrText += String(chunk);
    return true;
  });
});

afterEach(() => {
  stderrSpy.mockRestore();
  rmSync(home, { recursive: true, force: true });
  clearDiscoveryCache();
});

describe("parseArgs", () => {
  test("defaults to serve", () => {
    expect(parseArgs([]).command).toBe("serve");
  });

  test("maps subcommands", () => {
    expect(parseArgs(["login"]).command).toBe("login");
    expect(parseArgs(["logout"]).command).toBe("logout");
    expect(parseArgs(["doctor"]).command).toBe("doctor");
  });

  test("recognizes --version/-v and --help/-h", () => {
    expect(parseArgs(["--version"]).command).toBe("version");
    expect(parseArgs(["-v"]).command).toBe("version");
    expect(parseArgs(["--help"]).command).toBe("help");
    expect(parseArgs(["-h"]).command).toBe("help");
  });

  test("maps flags to env overrides (--k v and --k=v)", () => {
    const parsed = parseArgs([
      "doctor",
      "--adapter-base-url",
      "https://x.example.com",
      "--agent-id=A2",
      "--alg",
      "ES384",
    ]);
    expect(parsed.command).toBe("doctor");
    expect(parsed.overrides).toEqual({
      ADAPTER_BASE_URL: "https://x.example.com",
      AGENT_ID: "A2",
      DPOP_ALG: "ES384",
    });
  });
});

describe("runCli version/help", () => {
  test("--version prints VERSION to stderr, exit 0", async () => {
    const code = await runCli(["bun", "idx", "--version"], { env: baseEnv() });
    expect(code).toBe(0);
    expect(stderrText).toContain("okta-mcp-bridge");
  });
});

describe("runCli doctor", () => {
  test("reachable adapter → exit 0 and reports endpoints", async () => {
    const code = await runCli(["bun", "idx", "doctor"], {
      env: baseEnv(),
      fetch: reachableFetch(),
      logger: baseLogger,
    });
    expect(code).toBe(0);
    expect(stderrText).toContain("token_endpoint");
    expect(stderrText).toContain("as.example.com");
    expect(stderrText).toContain("reachable");
  });

  test("unreachable adapter → non-zero exit", async () => {
    const code = await runCli(["bun", "idx", "doctor"], {
      env: baseEnv(),
      fetch: unreachableFetch,
      logger: baseLogger,
    });
    expect(code).toBe(1);
    expect(stderrText).toContain("UNREACHABLE");
  });

  test("a flag override is layered over env (adapter-base-url via flag)", async () => {
    const env = baseEnv({ ADAPTER_BASE_URL: undefined });
    const code = await runCli(
      ["bun", "idx", "doctor", "--adapter-base-url", "https://adapter.example.com"],
      { env, fetch: reachableFetch(), logger: baseLogger },
    );
    expect(code).toBe(0);
  });

  test("missing required config → exit 2", async () => {
    const code = await runCli(["bun", "idx", "doctor"], {
      env: { BRIDGE_HOME: home },
      fetch: reachableFetch(),
    });
    expect(code).toBe(2);
  });
});

describe("runCli logout", () => {
  test("clears the token store and the DPoP key file (persistent mode)", async () => {
    // Seed a key + a stored token.
    const km = await DpopKeyManager.create(
      {
        ADAPTER_BASE_URL: "https://adapter.example.com",
        OKTA_CLIENT_ID: "cid",
        AGENT_ID: "agent-1",
        OKTA_REDIRECT_PORT: 0,
        OKTA_SCOPES: "openid",
        DPOP_ALG: "ES256",
        DPOP_KEY_MODE: "persistent",
        BRIDGE_HOME: home,
        HTTP_TIMEOUT_MS: 30000,
        LOG_LEVEL: "error",
      },
      baseLogger,
    );
    const store = new TokenStore(home);
    store.save({
      accessToken: "tok",
      tokenType: "DPoP",
      expiresAt: 9_999_999_999,
      scope: "openid",
      jkt: await km.jkt(),
    });
    expect(existsSync(join(home, "tokens.json"))).toBe(true);
    expect(existsSync(join(home, "dpop-key.json"))).toBe(true);

    const code = await runCli(["bun", "idx", "logout"], {
      env: baseEnv({ DPOP_KEY_MODE: "persistent" }),
      logger: baseLogger,
    });
    expect(code).toBe(0);
    expect(existsSync(join(home, "tokens.json"))).toBe(false);
    expect(existsSync(join(home, "dpop-key.json"))).toBe(false);
  });
});
