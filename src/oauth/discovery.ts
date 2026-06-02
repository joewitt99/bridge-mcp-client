// OAuth endpoint discovery.
//
// Resolves the authorization server's endpoints in two hops:
//   1. RFC 9728 — GET <ADAPTER_BASE_URL>/.well-known/oauth-protected-resource
//      → authorization_servers[0] gives the AS base.
//   2. RFC 8414 — GET <AS base>/.well-known/oauth-authorization-server
//      → authorization_endpoint, token_endpoint, registration_endpoint?,
//        dpop_signing_alg_values_supported?
//
// OKTA_ISSUER override: the adapter enforces cnf.jkt equality, so the DPoP-bound
// token must be minted by the actual issuer (Okta). When OKTA_ISSUER is set we
// ALSO fetch <OKTA_ISSUER>/.well-known/openid-configuration and use ITS
// authorize/token endpoints — binding DPoP directly at Okta. Without the
// override we rely on the adapter's token endpoint forwarding the DPoP proof +
// nonce to Okta unchanged.
//
// Resolved metadata is cached in memory for the process lifetime.
import type { Config } from "../config.ts";
import { logger as defaultLogger, type Logger } from "../logger.ts";

export interface Endpoints {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  dpopAlgs?: string[];
}

export interface DiscoveryDeps {
  /** Injectable for tests; defaults to the global fetch. */
  fetch?: typeof fetch;
  logger?: Logger;
}

interface ProtectedResourceMetadata {
  authorization_servers?: string[];
}

interface AuthServerMetadata {
  issuer?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  registration_endpoint?: string;
  dpop_signing_alg_values_supported?: string[];
}

const cache = new Map<string, Endpoints>();

/** Clear the in-memory discovery cache (used by tests). */
export function clearDiscoveryCache(): void {
  cache.clear();
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "?";
  }
}

async function getJson<T>(
  doFetch: typeof fetch,
  url: string,
  what: string,
): Promise<T> {
  let res: Response;
  try {
    res = await doFetch(url, {
      headers: { Accept: "application/json" },
    });
  } catch (cause) {
    throw new Error(`Failed to fetch ${what} (${url}): ${String(cause)}`);
  }
  if (!res.ok) {
    throw new Error(`Failed to fetch ${what} (${url}): HTTP ${res.status}`);
  }
  return (await res.json()) as T;
}

/**
 * Resolve the OAuth endpoints for the configured adapter, honoring the optional
 * OKTA_ISSUER override. Results are cached per (ADAPTER_BASE_URL, OKTA_ISSUER).
 */
export async function resolveEndpoints(
  config: Config,
  deps: DiscoveryDeps = {},
): Promise<Endpoints> {
  const doFetch = deps.fetch ?? fetch;
  const logger = deps.logger ?? defaultLogger;

  const cacheKey = `${config.ADAPTER_BASE_URL}|${config.OKTA_ISSUER ?? ""}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  // 1. RFC 9728 — protected-resource metadata → authorization server base.
  const base = stripTrailingSlash(config.ADAPTER_BASE_URL);
  const prm = await getJson<ProtectedResourceMetadata>(
    doFetch,
    `${base}/.well-known/oauth-protected-resource`,
    "protected-resource metadata",
  );
  const asBase = prm.authorization_servers?.[0];
  if (!asBase) {
    throw new Error(
      "protected-resource metadata has no authorization_servers[0]",
    );
  }

  // 2. RFC 8414 — authorization-server metadata.
  const asMeta = await getJson<AuthServerMetadata>(
    doFetch,
    `${stripTrailingSlash(asBase)}/.well-known/oauth-authorization-server`,
    "authorization-server metadata",
  );
  if (!asMeta.authorization_endpoint || !asMeta.token_endpoint) {
    throw new Error(
      "authorization-server metadata missing authorization_endpoint/token_endpoint",
    );
  }

  let endpoints: Endpoints = {
    issuer: asMeta.issuer ?? stripTrailingSlash(asBase),
    authorizationEndpoint: asMeta.authorization_endpoint,
    tokenEndpoint: asMeta.token_endpoint,
    registrationEndpoint: asMeta.registration_endpoint,
    dpopAlgs: asMeta.dpop_signing_alg_values_supported,
  };

  // OKTA_ISSUER override: mint the DPoP-bound token at Okta directly.
  if (config.OKTA_ISSUER) {
    const oidc = await getJson<AuthServerMetadata>(
      doFetch,
      `${stripTrailingSlash(config.OKTA_ISSUER)}/.well-known/openid-configuration`,
      "Okta openid-configuration",
    );
    if (!oidc.authorization_endpoint || !oidc.token_endpoint) {
      throw new Error(
        "Okta openid-configuration missing authorization_endpoint/token_endpoint",
      );
    }
    endpoints = {
      issuer: oidc.issuer ?? stripTrailingSlash(config.OKTA_ISSUER),
      authorizationEndpoint: oidc.authorization_endpoint,
      tokenEndpoint: oidc.token_endpoint,
      registrationEndpoint:
        oidc.registration_endpoint ?? endpoints.registrationEndpoint,
      dpopAlgs:
        oidc.dpop_signing_alg_values_supported ?? endpoints.dpopAlgs,
    };
  }

  if (
    endpoints.dpopAlgs &&
    endpoints.dpopAlgs.length > 0 &&
    !endpoints.dpopAlgs.includes(config.DPOP_ALG)
  ) {
    logger.warn("oauth.dpop.alg_unsupported", {
      configured: config.DPOP_ALG,
      supported: endpoints.dpopAlgs,
    });
  }

  logger.info("oauth.discovery.resolved", {
    issuer_host: hostOf(endpoints.issuer),
    authorize_host: hostOf(endpoints.authorizationEndpoint),
    token_host: hostOf(endpoints.tokenEndpoint),
    override: Boolean(config.OKTA_ISSUER),
  });

  cache.set(cacheKey, endpoints);
  return endpoints;
}
