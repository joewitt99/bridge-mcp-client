// Upstream proxy: forwards MCP JSON-RPC to the adapter's POST / over HTTPS.
//
// Every authed call carries Authorization: DPoP <token>, X-MCP-Agent, and a
// fresh per-request DPoP proof (ath = sha256(token), htu = <ADAPTER_BASE_URL>/).
// It captures/reuses Mcp-Session-Id, parses SSE or JSON responses, and recovers
// once from a 401 — either a resource-side use_dpop_nonce challenge (cache the
// nonce, retry) or a stale token (clear it, re-acquire, retry). It never throws
// out of forward()/forwardUnauthed(): network/timeouts/auth failures are mapped
// to JSON-RPC error objects. Never log token/proof material.
import type { Config } from "./config.ts";
import { logger as defaultLogger, type Logger } from "./logger.ts";
import type { DpopKeyManager } from "./dpop.ts";
import type { AuthorizeFn } from "./oauth/token.ts";
import { withBackoff } from "./retry.ts";

/** The slice of DpopTokenClient the upstream needs (eases testing). */
export interface TokenProvider {
  getAccessToken(authorizeFn: AuthorizeFn): Promise<string>;
  clearStored(): void;
}

export interface UpstreamDeps {
  fetch?: typeof fetch;
  /** Transient-failure retries inside send() (default 2). */
  retries?: number;
  baseMs?: number;
}

interface SendResult {
  httpStatus: number;
  headers: Headers;
  json: unknown;
}

/** A JSON-RPC error object returned in place of a normal response. */
function rpcError(jsonRpc: unknown, code: number, message: string): unknown {
  const id =
    jsonRpc && typeof jsonRpc === "object"
      ? ((jsonRpc as { id?: unknown }).id ?? null)
      : null;
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function methodOf(jsonRpc: unknown): string {
  const m = (jsonRpc as { method?: unknown } | null)?.method;
  return typeof m === "string" ? m : "";
}

export class UpstreamClient {
  private mcpSessionId?: string;
  /** Resource-side DPoP nonce (defensive — the adapter usually won't send one). */
  private upstreamNonce?: string;
  private readonly doFetch: typeof fetch;
  private readonly base: string;
  private readonly retries: number;
  private readonly baseMs: number;

  constructor(
    private readonly config: Config,
    private readonly keyManager: DpopKeyManager,
    private readonly tokenClient: TokenProvider,
    private readonly logger: Logger = defaultLogger,
    deps: UpstreamDeps = {},
  ) {
    this.doFetch = deps.fetch ?? fetch;
    this.base = config.ADAPTER_BASE_URL.replace(/\/+$/, "");
    this.retries = deps.retries ?? 2;
    this.baseMs = deps.baseMs ?? 200;
  }

  /** Authed forward with single-retry recovery; never throws. */
  async forward(jsonRpc: unknown, authorizeFn: AuthorizeFn): Promise<unknown> {
    try {
      const token = await this.tokenClient.getAccessToken(authorizeFn);
      let resp = await this.send(jsonRpc, { authed: true, token });

      if (resp.httpStatus === 401) {
        if (UpstreamClient.isUseDpopNonce(resp)) {
          const nonce = resp.headers.get("DPoP-Nonce");
          if (nonce) this.upstreamNonce = nonce;
          this.logger.info("oauth.nonce.challenge", { side: "resource" });
          resp = await this.send(jsonRpc, { authed: true, token });
        } else {
          // Stale/invalid token: clear it and re-acquire (refresh or re-login).
          this.tokenClient.clearStored();
          const fresh = await this.tokenClient.getAccessToken(authorizeFn);
          resp = await this.send(jsonRpc, { authed: true, token: fresh });
        }
      }

      if (resp.httpStatus === 401) {
        this.logger.warn("mcp.request.upstream_unauthorized", {
          method: methodOf(jsonRpc),
        });
        return rpcError(jsonRpc, -32001, "upstream authorization failed");
      }
      return resp.json;
    } catch (err) {
      this.logger.error("mcp.request.upstream_error", { error: String(err) });
      return rpcError(jsonRpc, -32000, "upstream request failed");
    }
  }

  /** Unauthed forward (initialize/ping/notifications); never throws. */
  async forwardUnauthed(jsonRpc: unknown): Promise<unknown> {
    try {
      const resp = await this.send(jsonRpc, { authed: false });
      return resp.json;
    } catch (err) {
      this.logger.error("mcp.request.upstream_error", { error: String(err) });
      return rpcError(jsonRpc, -32000, "upstream request failed");
    }
  }

  private static isUseDpopNonce(resp: SendResult): boolean {
    const www = resp.headers.get("WWW-Authenticate") ?? "";
    const bodyErr = (resp.json as { error?: unknown } | null)?.error;
    return www.includes("use_dpop_nonce") || bodyErr === "use_dpop_nonce";
  }

  private async authHeaders(token: string): Promise<Record<string, string>> {
    return {
      Authorization: `DPoP ${token}`,
      "X-MCP-Agent": this.config.AGENT_ID,
      DPoP: await this.keyManager.createProof({
        htm: "POST",
        htu: `${this.base}/`,
        accessToken: token,
        nonce: this.upstreamNonce,
      }),
    };
  }

  /** One POST of a JSON-RPC message to the adapter. */
  private async send(
    jsonRpc: unknown,
    opts: { authed: boolean; token?: string },
  ): Promise<SendResult> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (this.mcpSessionId) headers["Mcp-Session-Id"] = this.mcpSessionId;
    if (opts.authed && opts.token) {
      Object.assign(headers, await this.authHeaders(opts.token));
    }

    this.logger.info("mcp.request.forwarded", {
      method: methodOf(jsonRpc),
      authed: opts.authed,
      has_session: Boolean(this.mcpSessionId),
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.HTTP_TIMEOUT_MS);
    const body = JSON.stringify(jsonRpc);
    let res: Response;
    try {
      res = await withBackoff(
        () =>
          this.doFetch(`${this.base}/`, {
            method: "POST",
            headers,
            body,
            signal: controller.signal,
          }),
        { retries: this.retries, baseMs: this.baseMs },
      );
    } finally {
      clearTimeout(timer);
    }

    const sid = res.headers.get("Mcp-Session-Id");
    if (sid && sid !== this.mcpSessionId) {
      this.mcpSessionId = sid;
      this.logger.info("mcp.session.established", { has_session: true });
    }

    return { httpStatus: res.status, headers: res.headers, json: await parseBody(res) };
  }
}

/** Parse the response body: last `data:` line for SSE, else JSON. */
async function parseBody(res: Response): Promise<unknown> {
  const contentType = res.headers.get("Content-Type") ?? "";
  const text = await res.text();
  if (!text) return null;
  if (contentType.includes("text/event-stream")) {
    const dataLines = text
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"));
    const last = dataLines[dataLines.length - 1];
    if (!last) return null;
    try {
      return JSON.parse(last.slice("data:".length).trim());
    } catch {
      return null;
    }
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
