import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import type { Config } from "../src/config.ts";
import { runStdioBridge, type UpstreamLike } from "../src/server.ts";

function cfg(): Config {
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
    LOG_LEVEL: "info",
  };
}

const authorizeFn = async () => ({ code: "c", redirectUri: "http://127.0.0.1:0/callback", verifier: "v" });

/** An upstream stub that records which methods went down each path. */
function recordingUpstream(): UpstreamLike & { authed: string[]; unauthed: string[] } {
  const authed: string[] = [];
  const unauthed: string[] = [];
  return {
    authed,
    unauthed,
    async forward(jsonRpc) {
      const m = jsonRpc as { id?: unknown; method?: string };
      authed.push(m.method ?? "");
      return { jsonrpc: "2.0", id: m.id, result: { authed: true } };
    },
    async forwardUnauthed(jsonRpc) {
      const m = jsonRpc as { id?: unknown; method?: string };
      unauthed.push(m.method ?? "");
      // Notifications (no id) get no response body.
      return m.id !== undefined ? { jsonrpc: "2.0", id: m.id, result: { unauthed: true } } : null;
    },
  };
}

async function* feed(lines: string[]): AsyncGenerator<string> {
  for (const line of lines) yield line + "\n";
}

let stdoutSpy: ReturnType<typeof spyOn>;
let stderrSpy: ReturnType<typeof spyOn>;
let stdoutLines: string[];
let stderrLines: string[];

beforeEach(() => {
  stdoutLines = [];
  stderrLines = [];
  stdoutSpy = spyOn(process.stdout, "write").mockImplementation((chunk: unknown) => {
    stdoutLines.push(String(chunk));
    return true;
  });
  stderrSpy = spyOn(process.stderr, "write").mockImplementation((chunk: unknown) => {
    stderrLines.push(String(chunk));
    return true;
  });
});

afterEach(() => {
  stdoutSpy.mockRestore();
  stderrSpy.mockRestore();
});

describe("runStdioBridge", () => {
  test("routes initialize unauthed and tools/list authed; responses are single JSON lines with matching ids", async () => {
    const upstream = recordingUpstream();
    await runStdioBridge({
      config: cfg(),
      upstream,
      authorizeFn,
      input: feed([
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
      ]),
      installSignalHandlers: false,
    });

    expect(upstream.unauthed).toEqual(["initialize"]);
    expect(upstream.authed).toEqual(["tools/list"]);

    // Exactly two stdout writes, each a single valid JSON-RPC line.
    expect(stdoutLines.length).toBe(2);
    for (const line of stdoutLines) {
      expect(line.endsWith("\n")).toBe(true);
      expect(line.indexOf("\n")).toBe(line.length - 1); // single line
    }
    const r1 = JSON.parse(stdoutLines[0]!);
    const r2 = JSON.parse(stdoutLines[1]!);
    expect(r1.id).toBe(1);
    expect(r1.result.unauthed).toBe(true);
    expect(r2.id).toBe(2);
    expect(r2.result.authed).toBe(true);
  });

  test("a notification (no id) yields no stdout response", async () => {
    const upstream = recordingUpstream();
    await runStdioBridge({
      config: cfg(),
      upstream,
      authorizeFn,
      input: feed([JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })]),
      installSignalHandlers: false,
    });
    expect(upstream.unauthed).toEqual(["notifications/initialized"]);
    expect(stdoutLines.length).toBe(0);
  });

  test("malformed JSON logs a parse_error to stderr and the bridge stays alive", async () => {
    const upstream = recordingUpstream();
    await runStdioBridge({
      config: cfg(),
      upstream,
      authorizeFn,
      input: feed([
        "this is not json",
        JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/list" }),
      ]),
      installSignalHandlers: false,
    });
    // The bad line was logged to stderr...
    expect(stderrLines.some((l) => l.includes("mcp.request.parse_error"))).toBe(true);
    // ...and the following valid request was still served.
    expect(upstream.authed).toEqual(["tools/list"]);
    expect(stdoutLines.length).toBe(1);
    expect(JSON.parse(stdoutLines[0]!).id).toBe(5);
  });

  test("nothing from logging leaks to stdout", async () => {
    const upstream = recordingUpstream();
    await runStdioBridge({
      config: cfg(),
      upstream,
      authorizeFn,
      input: feed([JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" })]),
      installSignalHandlers: false,
    });
    // Every stdout line parses as JSON-RPC; log records went to stderr only.
    for (const line of stdoutLines) {
      expect(() => JSON.parse(line)).not.toThrow();
      expect(JSON.parse(line).jsonrpc).toBe("2.0");
    }
    expect(stderrLines.some((l) => l.includes("bridge.shutdown"))).toBe(true);
  });
});
