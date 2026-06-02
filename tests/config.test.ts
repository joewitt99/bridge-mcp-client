import { test, expect } from "bun:test";
import { loadConfig } from "../src/config.ts";

const base = {
  ADAPTER_BASE_URL: "https://adapter.example.com",
  OKTA_CLIENT_ID: "client123",
  AGENT_ID: "agent123",
};

test("throws when ADAPTER_BASE_URL is missing", () => {
  expect(() =>
    loadConfig({ OKTA_CLIENT_ID: "c", AGENT_ID: "a" }),
  ).toThrow(/ADAPTER_BASE_URL/);
});

test("throws listing all missing required vars", () => {
  expect(() => loadConfig({})).toThrow(
    /ADAPTER_BASE_URL.*OKTA_CLIENT_ID.*AGENT_ID/,
  );
});

test("throws on a non-http(s) ADAPTER_BASE_URL", () => {
  expect(() =>
    loadConfig({ ...base, ADAPTER_BASE_URL: "ftp://nope" }),
  ).toThrow(/http\(s\)/);
});

test("throws on a malformed ADAPTER_BASE_URL", () => {
  expect(() =>
    loadConfig({ ...base, ADAPTER_BASE_URL: "not a url" }),
  ).toThrow(/valid URL/);
});

test("throws on a bad DPOP_ALG", () => {
  expect(() => loadConfig({ ...base, DPOP_ALG: "HS256" })).toThrow(/DPOP_ALG/);
});

test("throws on a bad DPOP_KEY_MODE", () => {
  expect(() =>
    loadConfig({ ...base, DPOP_KEY_MODE: "weird" }),
  ).toThrow(/DPOP_KEY_MODE/);
});

test("succeeds with a minimal valid env and applies defaults", () => {
  const cfg = loadConfig(base);
  expect(cfg.ADAPTER_BASE_URL).toBe("https://adapter.example.com");
  expect(cfg.OKTA_CLIENT_ID).toBe("client123");
  expect(cfg.AGENT_ID).toBe("agent123");
  expect(cfg.OKTA_ISSUER).toBeUndefined();
  expect(cfg.DPOP_ALG).toBe("ES256");
  expect(cfg.DPOP_KEY_MODE).toBe("persistent");
  expect(cfg.OKTA_SCOPES).toBe("openid offline_access");
  expect(cfg.OKTA_REDIRECT_PORT).toBe(0);
  expect(cfg.HTTP_TIMEOUT_MS).toBe(30000);
  expect(cfg.LOG_LEVEL).toBe("info");
  expect(cfg.BRIDGE_HOME).toContain(".okta-mcp-bridge");
});

test("honors explicit overrides", () => {
  const cfg = loadConfig({
    ...base,
    OKTA_ISSUER: "https://dev-1.okta.com",
    DPOP_ALG: "ES384",
    DPOP_KEY_MODE: "ephemeral",
    OKTA_SCOPES: "openid",
    OKTA_REDIRECT_PORT: "8765",
    HTTP_TIMEOUT_MS: "5000",
    BRIDGE_HOME: "/tmp/custom-home",
    LOG_LEVEL: "debug",
  });
  expect(cfg.OKTA_ISSUER).toBe("https://dev-1.okta.com");
  expect(cfg.DPOP_ALG).toBe("ES384");
  expect(cfg.DPOP_KEY_MODE).toBe("ephemeral");
  expect(cfg.OKTA_SCOPES).toBe("openid");
  expect(cfg.OKTA_REDIRECT_PORT).toBe(8765);
  expect(cfg.HTTP_TIMEOUT_MS).toBe(5000);
  expect(cfg.BRIDGE_HOME).toBe("/tmp/custom-home");
  expect(cfg.LOG_LEVEL).toBe("debug");
});
