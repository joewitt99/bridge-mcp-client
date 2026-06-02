// DPoP token acquisition with Okta's nonce handshake, refresh, and the single
// getAccessToken() entry point the proxy layer calls ("login once, call many").
//
// Okta's /token requires a DPoP proof and a nonce handshake: the first call is
// rejected with error="use_dpop_nonce" + a DPoP-Nonce header; we retry once
// with that nonce in a fresh proof. Okta rotates the nonce (~daily), so a later
// use_dpop_nonce simply triggers the same single retry again — never a loop.
//
// The minted access token must be DPoP-bound by Okta: its cnf.jkt must equal
// the bridge key's thumbprint. We decode the token (without verifying its
// signature) and throw on a mismatch. Never log token material.
import { decodeJwt } from "jose";
import type { Config } from "../config.ts";
import { logger as defaultLogger, type Logger } from "../logger.ts";
import type { DpopKeyManager } from "../dpop.ts";
import type { TokenSet, TokenStore } from "../store.ts";
import type { Endpoints } from "./discovery.ts";

/** What authorizeFn (the injected P03 authorize) yields. */
export interface AuthCodeResult {
  code: string;
  redirectUri: string;
  verifier: string;
}

export type AuthorizeFn = () => Promise<AuthCodeResult>;

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
}

interface TokenHttpResult {
  status: number;
  json: TokenResponse | null;
  /** Raw response body (kept so non-JSON error bodies aren't lost). */
  raw: string;
  dpopNonce?: string;
  wwwAuthenticate?: string;
}

export interface TokenClientDeps {
  fetch?: typeof fetch;
}

export class DpopTokenClient {
  private nonce?: string;
  private readonly doFetch: typeof fetch;

  constructor(
    private readonly config: Config,
    private readonly endpoints: Endpoints,
    private readonly keyManager: DpopKeyManager,
    private readonly store: TokenStore,
    private readonly logger: Logger = defaultLogger,
    deps: TokenClientDeps = {},
  ) {
    this.doFetch = deps.fetch ?? fetch;
  }

  /** One POST to the token endpoint carrying a DPoP proof. */
  private async tokenRequest(
    params: Record<string, string>,
    opts: { nonce?: string } = {},
  ): Promise<TokenHttpResult> {
    const proof = await this.keyManager.createProof({
      htm: "POST",
      htu: this.endpoints.tokenEndpoint,
      nonce: opts.nonce,
    });
    // Safe to log: grant_type and client_id are public (client_id is in the
    // authorize URL too). The code, verifier, and refresh_token are NOT logged.
    this.logger.debug("oauth.token.request", {
      token_endpoint: this.endpoints.tokenEndpoint,
      grant_type: params.grant_type,
      client_id: params.client_id,
      has_code: Boolean(params.code),
      has_code_verifier: Boolean(params.code_verifier),
      has_refresh_token: Boolean(params.refresh_token),
      has_nonce: Boolean(opts.nonce),
    });
    const res = await this.doFetch(this.endpoints.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        DPoP: proof,
      },
      body: new URLSearchParams(params).toString(),
    });
    const raw = await res.text();
    let json: TokenResponse | null = null;
    if (raw) {
      try {
        json = JSON.parse(raw) as TokenResponse;
      } catch {
        json = null;
      }
    }
    return {
      status: res.status,
      json,
      raw,
      dpopNonce: res.headers.get("DPoP-Nonce") ?? undefined,
      wwwAuthenticate: res.headers.get("WWW-Authenticate") ?? undefined,
    };
  }

  private static isUseDpopNonce(res: TokenHttpResult): boolean {
    return (
      res.json?.error === "use_dpop_nonce" ||
      (res.wwwAuthenticate?.includes("use_dpop_nonce") ?? false)
    );
  }

  /**
   * Call the token endpoint with the cached nonce; on a use_dpop_nonce
   * challenge, cache the fresh DPoP-Nonce and retry exactly once.
   */
  private async withNonceRetry(
    params: Record<string, string>,
  ): Promise<TokenHttpResult> {
    let res = await this.tokenRequest(params, { nonce: this.nonce });
    if (DpopTokenClient.isUseDpopNonce(res)) {
      this.logger.info("oauth.nonce.challenge");
      if (res.dpopNonce) this.nonce = res.dpopNonce;
      res = await this.tokenRequest(params, { nonce: this.nonce });
    }
    return res;
  }

  /** Exchange an authorization code for a DPoP-bound token set. */
  async exchangeCode(result: AuthCodeResult): Promise<TokenSet> {
    const res = await this.withNonceRetry({
      grant_type: "authorization_code",
      code: result.code,
      redirect_uri: result.redirectUri,
      client_id: this.config.OKTA_CLIENT_ID,
      code_verifier: result.verifier,
    });
    return this.buildAndPersist(res, "acquired");
  }

  /** Refresh an existing token set (carrying a DPoP proof on the refresh too). */
  async refresh(set: TokenSet): Promise<TokenSet> {
    if (!set.refreshToken) throw new Error("cannot refresh: no refresh_token");
    const res = await this.withNonceRetry({
      grant_type: "refresh_token",
      refresh_token: set.refreshToken,
      client_id: this.config.OKTA_CLIENT_ID,
      scope: set.scope,
    });
    return this.buildAndPersist(res, "refreshed", set);
  }

  /** Drop the persisted token set, forcing the next getAccessToken to re-acquire. */
  clearStored(): void {
    this.store.clear();
  }

  /**
   * The single "login once, call many" entry point: return a valid stored token,
   * refresh an expired one, or run the full login (authorizeFn + exchangeCode).
   */
  async getAccessToken(authorizeFn: AuthorizeFn): Promise<string> {
    const existing = this.store.load();
    if (existing && !this.store.isExpired(existing)) return existing.accessToken;
    if (existing?.refreshToken) {
      const refreshed = await this.refresh(existing);
      return refreshed.accessToken;
    }
    const set = await this.exchangeCode(await authorizeFn());
    return set.accessToken;
  }

  private async buildAndPersist(
    res: TokenHttpResult,
    kind: "acquired" | "refreshed",
    previous?: TokenSet,
  ): Promise<TokenSet> {
    const body = res.json;
    const accessToken = body?.access_token;
    if (res.status < 200 || res.status >= 300 || !body || !accessToken) {
      // Surface the server's reason — token-endpoint ERROR bodies are diagnostic,
      // not secret (a non-2xx response carries no access/refresh token). We log
      // the full raw body on any error status so non-standard servers are visible.
      const isError = res.status < 200 || res.status >= 300;
      this.logger.error("oauth.token.request_failed", {
        status: res.status,
        token_endpoint: this.endpoints.tokenEndpoint,
        error: body?.error,
        error_description: body?.error_description,
        has_dpop_nonce: Boolean(res.dpopNonce),
        www_authenticate: res.wwwAuthenticate,
        body: isError ? res.raw.slice(0, 500) : undefined,
      });
      const detail = body?.error
        ? body.error_description
          ? `${body.error}: ${body.error_description}`
          : body.error
        : `HTTP ${res.status}`;
      throw new Error(`token request failed: ${detail}`);
    }
    const jkt = await this.keyManager.jkt();

    if (body.token_type !== "DPoP") {
      this.logger.warn("oauth.token.not_dpop_bound", {
        token_type: body.token_type ?? "(none)",
      });
    }

    // Decode (do NOT verify) and assert the token is bound to our key.
    try {
      const claims = decodeJwt(accessToken) as {
        cnf?: { jkt?: string };
      };
      const cnfJkt = claims.cnf?.jkt;
      if (cnfJkt && cnfJkt !== jkt) {
        this.logger.error("oauth.token.jkt_mismatch", { expected: jkt, got: cnfJkt });
        throw new Error("access token cnf.jkt does not match the bridge key");
      }
    } catch (err) {
      // Re-throw a real mismatch; tolerate a non-JWT/opaque token.
      if (err instanceof Error && err.message.includes("cnf.jkt")) throw err;
    }

    const now = Math.floor(Date.now() / 1000);
    const set: TokenSet = {
      accessToken,
      refreshToken: body.refresh_token ?? previous?.refreshToken,
      tokenType: body.token_type ?? "DPoP",
      expiresAt: now + (body.expires_in ?? 0),
      scope: body.scope ?? previous?.scope ?? this.config.OKTA_SCOPES,
      jkt,
    };
    this.store.save(set);
    this.logger.info(kind === "acquired" ? "oauth.token.acquired" : "oauth.token.refreshed", {
      jkt,
      expiresAt: set.expiresAt,
      scope: set.scope,
    });
    return set;
  }
}
