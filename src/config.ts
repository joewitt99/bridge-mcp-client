import { homedir } from "node:os";
import { join } from "node:path";

export type DpopAlg = "ES256" | "ES384" | "RS256";
export type DpopKeyMode = "persistent" | "ephemeral";

export interface Config {
  /** The adapter's external base URL (e.g. https://adapter.example.com). */
  ADAPTER_BASE_URL: string;
  OKTA_CLIENT_ID: string;
  /** Sent as the X-MCP-Agent header. */
  AGENT_ID: string;
  /** If set, the token/authorize endpoints are taken from Okta directly. */
  OKTA_ISSUER?: string;
  /**
   * Override the `htu` claim on the /token DPoP proof (NOT the dialed URL). Use
   * when a BFF/proxy adapter relays the proof to Okta: the bridge still POSTs to
   * the adapter's token endpoint, but the proof's `htu` must match the URL the
   * verifier (Okta) recomputes — i.e. Okta's real token endpoint.
   */
  OKTA_TOKEN_DPOP_HTU?: string;
  /** Loopback redirect port; 0 = ephemeral. */
  OKTA_REDIRECT_PORT: number;
  OKTA_SCOPES: string;
  DPOP_ALG: DpopAlg;
  DPOP_KEY_MODE: DpopKeyMode;
  BRIDGE_HOME: string;
  HTTP_TIMEOUT_MS: number;
  LOG_LEVEL: string;
}

const VALID_ALGS: readonly DpopAlg[] = ["ES256", "ES384", "RS256"];
const VALID_KEY_MODES: readonly DpopKeyMode[] = ["persistent", "ephemeral"];

type Env = Record<string, string | undefined>;

function clean(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

/**
 * Build a typed Config from environment variables. Throws a clear error listing
 * any missing required vars or invalid values. (Flag overrides are layered on in
 * P06 by passing a merged env map.)
 */
export function loadConfig(env: Env = process.env): Config {
  const adapterBaseUrl = clean(env.ADAPTER_BASE_URL);
  const clientId = clean(env.OKTA_CLIENT_ID);
  const agentId = clean(env.AGENT_ID);

  const missing: string[] = [];
  if (!adapterBaseUrl) missing.push("ADAPTER_BASE_URL");
  if (!clientId) missing.push("OKTA_CLIENT_ID");
  if (!agentId) missing.push("AGENT_ID");
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variable(s): ${missing.join(", ")}`,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(adapterBaseUrl!);
  } catch {
    throw new Error(`ADAPTER_BASE_URL is not a valid URL: "${adapterBaseUrl}"`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(
      `ADAPTER_BASE_URL must be an absolute http(s) URL: "${adapterBaseUrl}"`,
    );
  }

  const alg = (clean(env.DPOP_ALG) ?? "ES256") as DpopAlg;
  if (!VALID_ALGS.includes(alg)) {
    throw new Error(
      `DPOP_ALG must be one of ${VALID_ALGS.join("/")}; got "${env.DPOP_ALG}"`,
    );
  }

  const keyMode = (clean(env.DPOP_KEY_MODE) ?? "persistent") as DpopKeyMode;
  if (!VALID_KEY_MODES.includes(keyMode)) {
    throw new Error(
      `DPOP_KEY_MODE must be one of ${VALID_KEY_MODES.join("/")}; got "${env.DPOP_KEY_MODE}"`,
    );
  }

  const redirectPort = clean(env.OKTA_REDIRECT_PORT)
    ? Number(env.OKTA_REDIRECT_PORT)
    : 0;
  if (
    !Number.isInteger(redirectPort) ||
    redirectPort < 0 ||
    redirectPort > 65535
  ) {
    throw new Error(
      `OKTA_REDIRECT_PORT must be an integer in [0, 65535]; got "${env.OKTA_REDIRECT_PORT}"`,
    );
  }

  const tokenDpopHtu = clean(env.OKTA_TOKEN_DPOP_HTU);
  if (tokenDpopHtu !== undefined) {
    let u: URL;
    try {
      u = new URL(tokenDpopHtu);
    } catch {
      throw new Error(`OKTA_TOKEN_DPOP_HTU is not a valid URL: "${tokenDpopHtu}"`);
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") {
      throw new Error(
        `OKTA_TOKEN_DPOP_HTU must be an absolute http(s) URL: "${tokenDpopHtu}"`,
      );
    }
  }

  const timeout = clean(env.HTTP_TIMEOUT_MS)
    ? Number(env.HTTP_TIMEOUT_MS)
    : 30000;
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error(
      `HTTP_TIMEOUT_MS must be a positive number; got "${env.HTTP_TIMEOUT_MS}"`,
    );
  }

  return {
    ADAPTER_BASE_URL: adapterBaseUrl!,
    OKTA_CLIENT_ID: clientId!,
    AGENT_ID: agentId!,
    OKTA_ISSUER: clean(env.OKTA_ISSUER),
    OKTA_TOKEN_DPOP_HTU: tokenDpopHtu,
    OKTA_REDIRECT_PORT: redirectPort,
    OKTA_SCOPES: clean(env.OKTA_SCOPES) ?? "openid offline_access",
    DPOP_ALG: alg,
    DPOP_KEY_MODE: keyMode,
    BRIDGE_HOME: clean(env.BRIDGE_HOME) ?? join(homedir(), ".okta-mcp-bridge"),
    HTTP_TIMEOUT_MS: timeout,
    LOG_LEVEL: clean(env.LOG_LEVEL) ?? "info",
  };
}
