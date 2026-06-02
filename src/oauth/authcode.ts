// PKCE authorization-code flow over a loopback redirect (RFC 8252).
//
// Runs the OAuth authorize step that yields an authorization `code`; the DPoP
// token exchange is P04. There is NO DPoP at the authorize step. The redirect
// lands on an ephemeral HTTP server bound to 127.0.0.1 only. Never log the
// code, verifier, or state.
import { createHash, randomBytes } from "node:crypto";
import type { Config } from "../config.ts";
import { logger as defaultLogger, type Logger } from "../logger.ts";
import type { Endpoints } from "./discovery.ts";

/** base64url(bytes) with no padding. */
function base64url(bytes: Buffer): string {
  return bytes.toString("base64url");
}

export interface Pkce {
  verifier: string;
  challenge: string;
}

/**
 * Generate a PKCE verifier/challenge pair. The verifier is a 43-char base64url
 * string (32 random bytes), within the RFC 7636 [43,128] range; the challenge
 * is base64url(sha256(verifier)) (S256).
 */
export function generatePkce(): Pkce {
  const verifier = base64url(randomBytes(32));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

/** Open a URL in the user's default browser. */
export type Opener = (url: string) => void | Promise<void>;

function defaultOpener(url: string): void {
  const cmd =
    process.platform === "darwin"
      ? ["open", url]
      : process.platform === "win32"
        ? ["cmd", "/c", "start", "", url]
        : ["xdg-open", url];
  Bun.spawn(cmd, { stdout: "ignore", stderr: "ignore", stdin: "ignore" });
}

export interface AuthorizeOptions {
  /** Injectable browser opener; defaults to the OS opener. */
  opener?: Opener;
  /** Reject after this many ms (default 300_000). */
  timeoutMs?: number;
  logger?: Logger;
}

export interface AuthorizeResult {
  code: string;
  redirectUri: string;
  verifier: string;
}

const CLOSE_PAGE = (message: string): string =>
  `<!doctype html><html><head><meta charset="utf-8"><title>okta-mcp-bridge</title></head>` +
  `<body style="font-family:system-ui;padding:2rem"><p>${message}</p>` +
  `<p>You may close this tab and return to your terminal.</p></body></html>`;

/**
 * Run the PKCE authorization-code flow. Starts a loopback server, opens the
 * authorize URL in the browser, and resolves with the captured code once the
 * redirect arrives. Rejects on state mismatch, an `error` param, or timeout.
 */
export function authorize(
  config: Config,
  endpoints: Endpoints,
  opts: AuthorizeOptions = {},
): Promise<AuthorizeResult> {
  const logger = opts.logger ?? defaultLogger;
  const opener = opts.opener ?? defaultOpener;
  const timeoutMs = opts.timeoutMs ?? 300_000;

  const { verifier, challenge } = generatePkce();
  const state = base64url(randomBytes(32));

  return new Promise<AuthorizeResult>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: config.OKTA_REDIRECT_PORT,
      fetch(req): Response {
        const url = new URL(req.url);
        if (url.pathname !== "/callback") {
          return new Response("Not found", { status: 404 });
        }
        const htmlHeaders = { "Content-Type": "text/html; charset=utf-8" };

        const errParam = url.searchParams.get("error");
        if (errParam) {
          const desc = url.searchParams.get("error_description") ?? "";
          settle(() =>
            reject(
              new Error(`authorization failed: ${errParam}${desc ? ` — ${desc}` : ""}`),
            ),
          );
          return new Response(CLOSE_PAGE("Authorization failed."), {
            status: 400,
            headers: htmlHeaders,
          });
        }

        if (url.searchParams.get("state") !== state) {
          settle(() => reject(new Error("authorization failed: state mismatch")));
          return new Response(CLOSE_PAGE("Authorization failed (state mismatch)."), {
            status: 400,
            headers: htmlHeaders,
          });
        }

        const code = url.searchParams.get("code");
        if (!code) {
          settle(() => reject(new Error("authorization failed: no code in callback")));
          return new Response(CLOSE_PAGE("Authorization failed (no code)."), {
            status: 400,
            headers: htmlHeaders,
          });
        }

        logger.info("oauth.authorize.code_received");
        settle(() => resolve({ code, redirectUri, verifier }));
        return new Response(CLOSE_PAGE("Authorization complete."), {
          headers: htmlHeaders,
        });
      },
    });

    const redirectUri = `http://127.0.0.1:${server.port}/callback`;

    function settle(action: () => void): void {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      action();
      // Let the in-flight response flush before stopping the server.
      setTimeout(() => server.stop(), 0);
    }

    timer = setTimeout(() => {
      logger.warn("oauth.authorize.failed", { reason: "timeout" });
      settle(() => reject(new Error("authorization timed out")));
    }, timeoutMs);

    const authUrl = new URL(endpoints.authorizationEndpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", config.OKTA_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("scope", config.OKTA_SCOPES);
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("code_challenge", challenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    logger.info("oauth.authorize.started", { redirect_port: server.port });

    Promise.resolve()
      .then(() => opener(authUrl.toString()))
      .catch((cause) => {
        // The opener is best-effort: fall back to manual instructions on stderr.
        logger.warn("oauth.authorize.opener_failed", { error: String(cause) });
        process.stderr.write(
          `\nOpen this URL in your browser to authorize:\n\n${authUrl.toString()}\n\n`,
        );
      });
  });
}
