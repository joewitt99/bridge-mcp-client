# DPoP stdio Bridge (`okta-mcp-bridge`) — Claude Code Implementation Prompts

**7 Prompts • Sequential Execution • Bun + TypeScript • Standalone Repo • June 2026**

---

## Overview

This document contains 7 sequential prompts for execution via the Claude Code CLI. They build `okta-mcp-bridge`, a lightweight Bun/TypeScript program that Claude (Claude Code, Cursor, etc.) launches as a **local stdio MCP server**. The bridge authenticates **once** against Okta with DPoP, then proxies every MCP call to the Okta MCP Adapter over HTTPS, attaching a fresh DPoP proof per request ("login once, call many").

**This builds a standalone, independent repository.** The bridge has zero code coupling to the adapter — it imports no adapter code, reads none of the adapter's source at runtime, and communicates with it only over HTTP. Everything it needs to know about the adapter (the DPoP/proof contract) is captured as an authoritative spec in this document. Run these prompts from inside a fresh, empty Git repository; the project root **is** the repo root.

Execute P01 through P07 in order.

### What the bridge is

```
Claude Code  ──stdio (MCP JSON-RPC)──▶  okta-mcp-bridge  ──HTTPS + DPoP──▶  Okta Adapter (POST /)  ──▶  resources
                                              │
                                              └─ Auth Code + PKCE + DPoP (loopback) ──▶  Okta /token  (mints cnf.jkt-bound token)
```

The bridge is, in effect, a DPoP- and Okta-aware `mcp-remote`: it bridges a **stdio** transport (client side) to the adapter's **Streamable HTTP** transport (server side) while owning the OAuth + DPoP lifecycle.

### The adapter contract — this table is the source of truth

Because this is a standalone repo, the adapter's source is **not** present and must **not** be assumed available. The contract below was verified against the adapter (v0.15.x) and Okta's DPoP guide; treat it as the authoritative spec for every prompt. (If you happen to have the adapter checked out, P07 offers an optional cross-check hook — but nothing here requires it.)

| Fact | Bridge requirement |
|---|---|
| Unified MCP endpoint is `POST /` (Streamable HTTP); `initialize`/`ping`/`notifications/initialized` need no auth, everything else does | Forward JSON-RPC to `POST <ADAPTER_BASE_URL>/`; only attach auth to authed methods |
| Adapter accepts `Authorization: Bearer <t>` **and** `Authorization: DPoP <t>`; the `DPoP` scheme alone forces proof enforcement | Always send `Authorization: DPoP <access_token>` |
| Agent is resolved from the `X-MCP-Agent` header (fallback: token `cid`/`aud`) | Send `X-MCP-Agent: <AGENT_ID>` |
| Proof rules: `typ:"dpop+jwt"`, `alg ∈ {ES256, ES384, RS256}`, embedded **public** JWK only, required claims `htm/htu/iat/jti`, single-use `jti`, `iat` window 300s + 60s skew | Build proofs exactly this way; default **ES256** |
| `ath` (= `base64url(sha256(access_token))`) is **required** on any proof sent with an access token | Include `ath` on every adapter call |
| `htu` is canonicalized from the adapter's external base URL (scheme+host) + the **request path**; default ports stripped, query/fragment dropped | Set `htu = <ADAPTER_BASE_URL>/` (external base, path `/`) |
| The token's `cnf.jkt` (when present) **must equal** the proof's `jkt` | The token must be DPoP-bound **by Okta**; reuse the same key for proofs |
| Per-agent enforcement via a `require_dpop` boolean on the agent | Operator sets `require_dpop=true` on the bridge's agent |
| Adapter emits audit events `auth.dpop.required_missing`, `auth.dpop.verified`, `auth.dpop.rejected`, `auth.dpop.replay_detected` | Bridge log event names mirror these for cross-system correlation |
| MCP session via `Mcp-Session-Id`; responses may be SSE (`Accept: application/json, text/event-stream`) | Pass `Mcp-Session-Id` through; parse SSE and JSON |

Okta specifics (from Okta's DPoP guides):

- App setting: **Proof of possession → "Require Demonstrating Proof of Possession (DPoP) header in token requests" = true** (API: `dpop_bound_access_tokens: true`).
- `/token` requires the **nonce handshake**: first call → `400/401` with a `DPoP-Nonce` header + `error="use_dpop_nonce"`; retry with the `nonce` claim + a fresh `jti`. Okta rotates the nonce ~daily.
- **Refresh** requests also carry a DPoP proof (`htm=POST`, `htu=<token endpoint>`).
- Okta's `dpop_signing_alg_values_supported` includes ES256/ES384/ES512/RS256/…; **ES256** is the safe intersection with the adapter.

### Cross-cutting rules every prompt must honor

1. **stdout is sacred.** It carries the MCP JSON-RPC stream. **All** logging, diagnostics, and errors go to **stderr**. A single stray `console.log` to stdout corrupts the protocol.
2. **Structured logs.** Every meaningful action emits one JSON line to stderr with `ts`, `level`, `event`, `correlation_id`. Use event names that mirror the adapter (`dpop.proof.created`, `oauth.token.acquired`, `oauth.nonce.challenge`, `mcp.request.forwarded`, etc.) so logs correlate across the bridge and adapter.
3. **Tests must pass after every prompt** (`bun test`). Prompts are self-contained and idempotent; re-running is safe.
4. **Docs are markdown.** No docx.
5. **Secrets at rest:** the DPoP private key + tokens live under `~/.okta-mcp-bridge/`, files `chmod 600`, encrypted with a key derived from a per-machine/user secret. Never log token or key material — log thumbprints and lengths only.

## Prompt Map

All paths are relative to the repo root (the standalone project).

| # | Prompt | Creates / Modifies | Est. Time |
|---|--------|--------------------|-----------|
| P01 | Standalone repo scaffold, config, stderr logger, CI, CLI entry | `package.json`, `tsconfig.json`, `src/`, `.github/workflows/ci.yml` | 20 min |
| P02 | DPoP key manager + proof factory (ES256, RFC 9449) | `src/dpop.ts` | 25 min |
| P03 | OAuth discovery + PKCE auth-code via loopback (RFC 8252) | `src/oauth/discovery.ts`, `src/oauth/authcode.ts` | 25 min |
| P04 | DPoP token acquisition, nonce handshake, refresh, token store | `src/oauth/token.ts`, `src/store.ts`, `src/crypto.ts` | 30 min |
| P05 | stdio MCP server ↔ Streamable HTTP proxy core | `src/server.ts`, `src/upstream.ts` | 35 min |
| P06 | CLI commands (login/logout/doctor), resilience, shutdown | `src/cli.ts`, `src/index.ts`, `src/retry.ts` | 20 min |
| P07 | Integration tests, README, Okta+adapter setup, compiled binary | tests, `README.md`, `docs/` | 30 min |

## Prerequisites

- Bun ≥ 1.1 installed (`curl -fsSL https://bun.sh/install | bash`)
- A new, empty directory for the repo (you'll `git init` it in P01)
- A reachable Okta MCP Adapter (local `docker-compose up`, or a deployed URL) with its external base URL known — this becomes `ADAPTER_BASE_URL`
- An Okta OIDC app (Native or Web) with **DPoP required** enabled and a loopback redirect URI (added in P07's setup doc)
- An adapter **agent** whose `client_id` matches the Okta app and has `require_dpop=true`

## How to Execute

```bash
# Create and enter a fresh directory for the standalone repo:
mkdir okta-mcp-bridge && cd okta-mcp-bridge

# Launch Claude Code here, then paste each prompt one at a time.
# After each prompt: review `git diff`, run `bun test`, commit, then proceed.
```

---

## Prompt P01: Standalone Repo Scaffold, Config, stderr Logger, CI, CLI Entry

**Context:** Initializes this directory as its own Git repository and Bun/TypeScript project, with the config loader, the stderr-only structured logger, a minimal CLI entry point, and a CI workflow. No OAuth or MCP yet — this prompt locks in the conventions (stdout-is-sacred, structured stderr logs) and the standalone-repo hygiene everything else depends on. This project is fully self-contained and has no dependency on the Okta MCP Adapter's source code.

**Prompt:**

````
You are bootstrapping a brand-new, standalone repository in the current directory.
This is `okta-mcp-bridge`: a local stdio MCP bridge for the Okta MCP Adapter. It is
independent — it imports no adapter code and reads no adapter source. The current
directory is the repo root; do NOT nest the project in a subdirectory.

Execute the following:

1. Initialize the repo (idempotent): if there is no .git directory, run `git init`.
   Create a root `.gitignore` (node_modules, dist, *.log, .env, .okta-mcp-bridge/).

2. Scaffold at the repo root:
   - package.json
       name: "okta-mcp-bridge", type: "module", license: "Apache-2.0",
       bin: { "okta-mcp-bridge": "./dist/okta-mcp-bridge" }
       scripts: { "dev": "bun run src/index.ts", "test": "bun test",
                  "build": "bun build src/index.ts --compile --outfile dist/okta-mcp-bridge",
                  "typecheck": "tsc --noEmit" }
       dependencies: { "@modelcontextprotocol/sdk": "^1.0.0", "jose": "^5.9.0" }
       devDependencies: { "typescript": "^5.5.0", "@types/bun": "latest" }
   - tsconfig.json  (strict: true, module: "ESNext", moduleResolution: "bundler",
       target: "ES2022", lib: ["ES2023"], types: ["bun-types"],
       noUncheckedIndexedAccess: true)
   - src/ and tests/ directories.
   - LICENSE: Apache-2.0 full text.

3. src/version.ts — export const VERSION (read from package.json at build time;
   fall back to "0.1.0").

4. src/logger.ts — a structured logger that writes ONLY to process.stderr.
   - log(level, event, fields?) emits one JSON line:
     {"ts": ISO8601, "level", "event", "correlation_id"?, ...fields}
   - Helpers: logger.info/warn/error/debug(event, fields?).
   - LOG_LEVEL env gates output (default "info"); "debug" is verbose.
   - withCorrelation(id) returns a child logger that injects correlation_id.
   - NEVER write to stdout. Top-of-file comment: stdout is reserved for the MCP
     JSON-RPC stream; any stdout write corrupts the protocol.
   - Redaction helpers: redactToken(t) -> "len=NN sha256=<first12>";
     redactKey(jwk) -> "kty=.. crv=.. jkt=<thumb>". The logger must never receive
     raw token or private-key material.

5. src/config.ts — loadConfig() reads env (and optional --flags later) into a typed Config:
       ADAPTER_BASE_URL   (required; the adapter's external base URL, e.g. https://adapter.example.com)
       OKTA_CLIENT_ID     (required)
       AGENT_ID           (required; sent as X-MCP-Agent)
       OKTA_ISSUER        (optional; if set, used directly for the token endpoint — see P03)
       OKTA_REDIRECT_PORT (optional; 0 = ephemeral, default 0)
       OKTA_SCOPES        (optional; default "openid offline_access")
       DPOP_ALG           (optional; default "ES256"; one of ES256/ES384/RS256)
       DPOP_KEY_MODE      (optional; "persistent" | "ephemeral"; default "persistent")
       BRIDGE_HOME        (optional; default ~/.okta-mcp-bridge)
       HTTP_TIMEOUT_MS    (optional; default 30000)
       LOG_LEVEL          (optional; default "info")
   - Validate ADAPTER_BASE_URL is an absolute http(s) URL. Validate DPOP_ALG.
   - Throw a clear error (to stderr) listing any missing required vars.

6. src/index.ts — shebang `#!/usr/bin/env bun`. Minimal entry: if invoked with
   no/unknown args, print bridge name + VERSION to STDERR and exit 0. (Real stdio
   server + CLI land in P05/P06.)

7. README.md — a stub: one paragraph describing the bridge, a "Status: scaffold"
   line, and a note that this is a standalone repo. Full README is P07.

8. .github/workflows/ci.yml — a minimal CI: on push/PR, set up Bun (oven-sh/setup-bun),
   run `bun install`, `bun run typecheck`, and `bun test`.

9. tests/logger.test.ts — assert the logger writes valid JSON to stderr (spy on
   process.stderr.write) and NEVER to stdout; redactToken excludes the raw token;
   LOG_LEVEL gating works.
   tests/config.test.ts — loadConfig throws on missing ADAPTER_BASE_URL and on a
   bad DPOP_ALG; succeeds with a minimal valid env.

Run: bun install && bun test && bun run typecheck. All tests must pass.
Then make an initial commit: `git add -A && git commit -m "scaffold okta-mcp-bridge"`.
````

**Expected Output:** An initialized standalone Git repo with a compiling Bun project, a stderr-only structured logger (with redaction), a validated config loader, a placeholder entry point, a CI workflow, an Apache-2.0 license, and passing logger/config tests — committed.

---

## Prompt P02: DPoP Key Manager + Proof Factory (ES256, RFC 9449)

**Context:** The cryptographic core. Generates the DPoP key pair, persists it (encrypted, `chmod 600`) or holds it ephemerally, computes the RFC 7638 thumbprint (`jkt`), and produces DPoP proof JWTs that satisfy the adapter contract exactly (see the spec table above). This is reused for both the `/token` exchange (P04) and per-request proofs to the adapter (P05).

**Prompt:**

````
Create src/dpop.ts — the DPoP key manager and proof factory, using `jose`. It must
produce proofs that satisfy the adapter contract (typ/alg/jwk/htm/htu/iat/jti/ath,
canonical htu) and Okta's /token DPoP checks.

Execute the following:

1. Key generation & persistence:
   - DpopKeyManager class. On init, per Config.DPOP_KEY_MODE:
       "persistent": load an existing key from <BRIDGE_HOME>/dpop-key.json if present,
                     else generate and persist.
       "ephemeral":  generate in-memory only (no persistence; re-login each start).
   - Generate with jose.generateKeyPair(alg, { extractable: true }) for the chosen
     alg (default ES256 -> EC P-256). Comment: persistence requires extractable;
     ephemeral mode could use extractable:false for stronger hygiene.
   - Persistence: export the PRIVATE key via jose.exportJWK, encrypt the serialized
     JWK with AES-256-GCM. Derive the encryption key from a per-machine secret: read
     <BRIDGE_HOME>/.seed (32 random bytes, created chmod 600 on first run) and HKDF it.
     Write <BRIDGE_HOME>/dpop-key.json (chmod 600) as {alg, iv, ciphertext, tag} —
     never plaintext key material. Ensure <BRIDGE_HOME> exists with mode 0700.

2. Public key + thumbprint:
   - publicJwk(): the public JWK only (strip all private params d/p/q/dp/dq/qi/k).
   - jkt(): RFC 7638 thumbprint via jose.calculateJwkThumbprint(publicJwk, "sha256").

3. Proof factory:
   - async createProof({ htm, htu, accessToken?, nonce? }): string
       header:  { typ: "dpop+jwt", alg, jwk: <public JWK> }
       payload: { jti: crypto.randomUUID(), htm: htm.toUpperCase(),
                  htu: canonicalHtu(htu), iat: Math.floor(Date.now()/1000),
                  ...(accessToken ? { ath: base64url(sha256(accessToken)) } : {}),
                  ...(nonce ? { nonce } : {}) }
       Sign with the private key (jose.SignJWT or CompactSign with the protected
       header set so `jwk` and `typ` are present).
   - ath = base64url( SHA-256(utf8 bytes of accessToken) ), no padding.

4. canonicalHtu(raw): lower-case scheme+host, strip default ports (443/https,
   80/http), DROP query and fragment, keep path. This guarantees a byte-match
   against the adapter's recomputed htu.

5. Logging: dpop.key.loaded / dpop.key.generated (jkt only) and dpop.proof.created
   (htm, htu, jkt, has_ath, has_nonce — NEVER the proof string or key).

6. tests/dpop.test.ts (verify your own output with jose; >=14 tests):
   - header typ "dpop+jwt", alg ES256, embedded public jwk
   - embedded jwk has NO private params
   - payload has jti, htm (upper-cased), htu (canonical), iat
   - ath present+correct when accessToken provided; absent otherwise
   - ath equals base64url(sha256(token)) computed independently
   - nonce included only when provided
   - jti unique across two calls
   - canonicalHtu drops query+fragment, strips :443/:80, lowercases host
   - canonicalHtu("https://Host.EXAMPLE.com:443/?q=1#f") == "https://host.example.com/"
   - signature verifies against the embedded public key (jose.compactVerify)
   - persistent mode: a second manager loads the SAME jkt from disk
   - ephemeral mode: a second manager has a DIFFERENT jkt
   - dpop-key.json and .seed are chmod 600
   - file contents are not the plaintext exported JWK

Run: bun test && bun run typecheck. All tests must pass. Commit.
````

**Expected Output:** `src/dpop.ts` producing RFC 9449 proofs that verify against their own embedded key and satisfy the adapter's claim/canonicalization rules, with encrypted-at-rest key persistence (mode 600) and a comprehensive test suite.

---

## Prompt P03: OAuth Discovery + PKCE Auth-Code via Loopback (RFC 8252)

**Context:** Resolves the OAuth endpoints and runs the authorization-code flow with PKCE over a loopback redirect (RFC 8252). The adapter advertises itself as the AS (issuer = its external base URL) via RFC 9728 → RFC 8414 metadata; an `OKTA_ISSUER` override lets the bridge target Okta's `/token` directly when DPoP binding must occur at Okta (the reliable default, given the adapter enforces `cnf.jkt`). This prompt produces the auth code; the DPoP token exchange is P04.

**Prompt:**

````
Create src/oauth/discovery.ts and src/oauth/authcode.ts.

Execute the following:

1. discovery.ts — resolveEndpoints(config): Promise<Endpoints>
   - GET <ADAPTER_BASE_URL>/.well-known/oauth-protected-resource (RFC 9728);
     read authorization_servers[0] -> AS base.
   - GET <AS base>/.well-known/oauth-authorization-server (RFC 8414); read
     authorization_endpoint, token_endpoint, registration_endpoint (optional),
     dpop_signing_alg_values_supported (optional).
   - Endpoints = { issuer, authorizationEndpoint, tokenEndpoint, registrationEndpoint?,
                   dpopAlgs?: string[] }.
   - OVERRIDE: if config.OKTA_ISSUER is set, ALSO GET
     <OKTA_ISSUER>/.well-known/openid-configuration and use ITS token_endpoint and
     authorization_endpoint. Rationale comment: the adapter enforces cnf.jkt equality,
     so the DPoP-bound token must be minted by the actual issuer (Okta). With
     OKTA_ISSUER we bind DPoP directly at Okta; otherwise we rely on the adapter's
     token endpoint forwarding the DPoP proof + nonce to Okta.
   - If dpopAlgs is present and config.DPOP_ALG not in it, log a warning
     (oauth.dpop.alg_unsupported) and continue.
   - Cache resolved metadata in memory for the process lifetime.
   - Log oauth.discovery.resolved with endpoint HOSTS (not full URLs).

2. authcode.ts — PKCE auth-code with loopback redirect:
   - generatePkce(): { verifier, challenge } where challenge =
     base64url(sha256(verifier)); verifier is 43-128 char base64url random.
   - authorize(config, endpoints, opts?): Promise<{ code, redirectUri, verifier }>
       a. Start an ephemeral HTTP server on 127.0.0.1:<OKTA_REDIRECT_PORT|0>.
          redirectUri = `http://127.0.0.1:<port>/callback`.
       b. Build the authorization URL: response_type=code, client_id=OKTA_CLIENT_ID,
          redirect_uri, scope=OKTA_SCOPES, state=<random>, code_challenge,
          code_challenge_method=S256. (No DPoP at the authorize step.)
       c. Open the URL in the default browser via an INJECTABLE opener fn
          (default: OS opener open/xdg-open/start via Bun.spawn). If opening fails,
          print the URL to STDERR with manual instructions.
       d. Loopback handler validates state, captures `code`, returns a tiny
          "You may close this tab" HTML page, resolves, and shuts the server.
       e. Timeout after 300s -> reject. Handle ?error=... by rejecting with it.
   - Log oauth.authorize.started (redirect port) and oauth.authorize.code_received
     (NO code value) / oauth.authorize.failed.

3. Security: bind the loopback server to 127.0.0.1 ONLY; reject on state mismatch;
   never log code/verifier/state.

4. tests:
   - tests/discovery.test.ts: mocked fetch — PRM -> AS metadata resolution; OKTA_ISSUER
     override pulls token_endpoint from openid-configuration; alg-unsupported warns.
   - tests/pkce.test.ts: challenge == base64url(sha256(verifier)); verifier length in
     [43,128]; two verifiers differ.
   - tests/authcode.test.ts: pin OKTA_REDIRECT_PORT, inject a stub opener; simulate a
     GET to /callback with valid state+code -> resolves; wrong state -> rejects;
     ?error -> rejects.

Run: bun test && bun run typecheck. All tests must pass. Commit.
````

**Expected Output:** Endpoint discovery (RFC 9728 → RFC 8414, with an Okta-direct override) and a tested PKCE auth-code flow over a 127.0.0.1 loopback redirect that yields an authorization code without exposing secrets.

---

## Prompt P04: DPoP Token Acquisition, Nonce Handshake, Refresh, Token Store

**Context:** Exchanges the auth code for a **DPoP-bound** access token, implementing Okta's mandatory nonce handshake at `/token` (first call → `use_dpop_nonce` + `DPoP-Nonce` header → retry with the nonce in the proof). Persists tokens encrypted, refreshes transparently (with a DPoP proof on refresh too), and exposes a single `getAccessToken()` the proxy layer calls.

**Prompt:**

````
Create src/crypto.ts, src/store.ts, and src/oauth/token.ts.

Execute the following:

1. src/crypto.ts — factor the AES-256-GCM + .seed/HKDF helpers out of src/dpop.ts into
   a shared module: sealJson(obj) -> {iv, ciphertext, tag}, openJson({iv,ciphertext,tag})
   -> obj, and seed management (<BRIDGE_HOME>/.seed, chmod 600). Refactor src/dpop.ts to
   import from src/crypto.ts; keep all P02 dpop tests green.

2. src/store.ts — TokenStore (encrypted at rest via src/crypto.ts):
   - Shape: { accessToken, refreshToken?, tokenType, expiresAt (epoch s), scope, jkt }
     written to <BRIDGE_HOME>/tokens.json (chmod 600).
   - load(): TokenSet | null;  save(set): void;  clear(): void;  isExpired(set, skew=60).

3. src/oauth/token.ts — DpopTokenClient(config, endpoints, keyManager, store, logger):
   - private async tokenRequest(params, { nonce? }): ONE POST to endpoints.tokenEndpoint:
       headers: { "Content-Type": "application/x-www-form-urlencoded",
                  "DPoP": await keyManager.createProof({ htm: "POST",
                          htu: endpoints.tokenEndpoint, nonce }) }
       body: urlencoded params.
     Returns { status, json, dpopNonce: res.headers.get("DPoP-Nonce") }.
   - private async withNonceRetry(params): call tokenRequest (using any cached nonce);
     if the response error is "use_dpop_nonce" (check body and/or WWW-Authenticate),
     cache the response DPoP-Nonce and RETRY ONCE with it (fresh jti is automatic).
     If still failing, throw the server error. Keep the latest nonce in memory and
     reuse it; be ready to repeat the retry on a later use_dpop_nonce (Okta rotates ~daily).
   - async exchangeCode({ code, redirectUri, verifier }): TokenSet
       params: grant_type=authorization_code, code, redirect_uri, client_id, code_verifier.
       On success build a TokenSet with jkt=keyManager.jkt(); persist. Warn
       (oauth.token.not_dpop_bound) if token_type != "DPoP". Decode the access-token JWT
       WITHOUT verifying signature; read cnf.jkt; if present and != keyManager.jkt(),
       THROW (oauth.token.jkt_mismatch).
   - async refresh(set): TokenSet — grant_type=refresh_token, refresh_token, client_id,
       scope; same withNonceRetry; same DPoP proof; persist (carry forward refresh_token
       if not rotated).
   - async getAccessToken(authorizeFn): string — load stored set; if valid return it; if
       expired with a refresh_token, refresh; else call authorizeFn() (the injected P03
       authorize) then exchangeCode. This is the single "login once, call many" entry point.
   - Logging: oauth.nonce.challenge, oauth.token.acquired (jkt, expiresAt, scope — NEVER
     the token), oauth.token.refreshed, oauth.token.jkt_mismatch.

4. tests/token.test.ts (mock fetch; >=12 tests):
   - first /token returns 400 {"error":"use_dpop_nonce"} + DPoP-Nonce; retry succeeds ->
     exactly TWO fetches; the second proof's payload contains the nonce.
   - the token-request DPoP header has htm POST and htu == tokenEndpoint (canonical).
   - exchangeCode persists a TokenSet with jkt == keyManager.jkt().
   - token_type != "DPoP" warns but does not throw.
   - cnf.jkt mismatch THROWS; match (or absent) does not.
   - refresh() sends grant_type=refresh_token WITH a DPoP proof and persists.
   - getAccessToken: valid -> no network; expired+refresh -> refreshes; none -> authorizeFn+exchange.
   - tokens.json is chmod 600 and not plaintext.
   - a later use_dpop_nonce triggers another single retry.
   - src/dpop.ts P02 tests still pass after the crypto refactor.

Run: bun test && bun run typecheck. All tests must pass. Commit.
````

**Expected Output:** A token client that performs Okta's DPoP nonce handshake, validates `cnf.jkt` binding against the bridge's key, refreshes with a proof, and persists tokens encrypted — exposing one `getAccessToken()` for the proxy.

---

## Prompt P05: stdio MCP Server ↔ Streamable HTTP Proxy Core

**Context:** The heart of the bridge. It runs an MCP **server over stdio** (what Claude Code connects to) and forwards every request to the adapter's `POST /` with `Authorization: DPoP <token>`, a fresh per-request DPoP proof (with `ath`, `htu = <ADAPTER_BASE_URL>/`), `X-MCP-Agent`, and `Mcp-Session-Id` passthrough. Auth is lazy — `initialize`/`ping`/`notifications` pass through unauthenticated; the first authed method triggers `getAccessToken()`.

**Prompt:**

````
Create src/upstream.ts and src/server.ts.

Execute the following:

1. src/upstream.ts — UpstreamClient(config, keyManager, tokenClient, logger):
   - state: mcpSessionId?: string; upstreamNonce?: string (defensive — support a
     resource-side DPoP nonce challenge even though the adapter usually won't send one).
   - private async send(jsonRpc, { authed }): forwards ONE JSON-RPC message to
     `${ADAPTER_BASE_URL.replace(/\/+$/,"")}/`:
       method: POST
       headers:
         "Content-Type": "application/json",
         "Accept": "application/json, text/event-stream",
         ...(mcpSessionId ? { "Mcp-Session-Id": mcpSessionId } : {}),
         ...(authed ? await authHeaders(accessToken) : {})
       body: JSON.stringify(jsonRpc)
     authHeaders(token) = {
       "Authorization": `DPoP ${token}`,
       "X-MCP-Agent": config.AGENT_ID,
       "DPoP": await keyManager.createProof({
                 htm: "POST",
                 htu: `${config.ADAPTER_BASE_URL.replace(/\/+$/,"")}/`,
                 accessToken: token,
                 nonce: this.upstreamNonce,
               }),
     }
     - Capture Mcp-Session-Id from the response headers and reuse it.
     - Parse the body: text/event-stream -> take the LAST `data:` JSON line; else JSON.parse.
     - Return { httpStatus, headers, json }.
   - public async forward(jsonRpc): authed path with recovery:
       a. token = await tokenClient.getAccessToken(authorizeFn)  // authorizeFn injected (P03)
       b. resp = await send(jsonRpc, { authed: true })
       c. If HTTP 401:
            - DPoP nonce (use_dpop_nonce in WWW-Authenticate/body): cache response
              DPoP-Nonce into upstreamNonce, RETRY ONCE.
            - Else: clear the stored token, re-run getAccessToken (refresh or re-login),
              RETRY ONCE.
       d. If still failing, RETURN a JSON-RPC error (code -32001,
          "upstream authorization failed") and log mcp.request.upstream_unauthorized.
   - public async forwardUnauthed(jsonRpc): send(jsonRpc, { authed: false }).
   - Timeouts via config.HTTP_TIMEOUT_MS (AbortController). Map network errors to
     JSON-RPC errors; never throw out of forward()/forwardUnauthed().
   - Log mcp.request.forwarded (method, authed, has_session) and mcp.session.established.

2. src/server.ts — runStdioBridge({ config, keyManager, tokenClient, upstream, authorizeFn }):
   - Implement a TRANSPARENT passthrough so ANY adapter method works without the bridge
     knowing the schema:
       - Read newline-delimited JSON-RPC from process.stdin; parse each message.
       - Route: method in {"initialize","ping","notifications/initialized"} or starting
         with "notifications/" -> forwardUnauthed; everything else -> forward.
       - Write each JSON-RPC response as a single line to STDOUT (the ONLY allowed stdout
         writes in the whole program). Messages with no id (notifications) get no response.
       - Preserve the request `id` exactly on responses.
   - On stdin EOF / SIGINT / SIGTERM: flush, log bridge.shutdown, exit 0.
   - Never crash on one bad message: log mcp.request.parse_error and, if an id is
     recoverable, return JSON-RPC parse error (-32700).
   - Deps are injected so tests can mock them.

3. tests/upstream.test.ts (mock fetch; >=12 tests):
   - forward() attaches Authorization: DPoP <token>, X-MCP-Agent, and a DPoP header.
   - the adapter proof has htm POST, htu == "<ADAPTER_BASE_URL>/" (canonical), and ath
     matching the token (decode the header you sent).
   - Mcp-Session-Id from a response is captured and sent next time.
   - SSE response body (data: {...}) is parsed.
   - 401 use_dpop_nonce -> caches nonce, retries once, second proof has nonce.
   - 401 without nonce -> clears token, re-acquires, retries once.
   - persistent 401 -> JSON-RPC error -32001 (no throw).
   - timeout -> JSON-RPC error (no throw).
   - forwardUnauthed sends NO Authorization/DPoP/X-MCP-Agent headers.
   tests/server.test.ts:
   - feed fake stdin: initialize (unauthed) then tools/list (authed); assert routing,
     matching-id responses on stdout as single JSON lines, and NOTHING on stdout from
     logging (spy stderr vs stdout).
   - a notification (no id) yields no stdout response.
   - malformed JSON -> stderr parse_error, process stays alive.

Run: bun test && bun run typecheck. All tests must pass. Commit.
````

**Expected Output:** A transparent stdio↔HTTP MCP proxy that injects DPoP-bound auth on authed methods, passes `initialize`/`ping` through unauthenticated, manages MCP sessions and DPoP-nonce/401 recovery, and writes to stdout only the protocol stream.

---

## Prompt P06: CLI Commands, Resilience, Graceful Shutdown

**Context:** Wraps the core in a small CLI so the bridge behaves like Claude Code: a default `serve` (stdio) mode plus `login`, `logout`, and `doctor` subcommands. Adds bounded retries/backoff for transient upstream failures and clean shutdown.

**Prompt:**

````
Create src/cli.ts and src/retry.ts, and finalize src/index.ts. Wire P01-P05 together.

Execute the following:

1. src/retry.ts — withBackoff(fn, { retries=2, baseMs=200 }) for transient HTTP failures
   (network errors, 502/503/504, 408, 429). Used inside UpstreamClient.send. Do NOT retry
   on 401 (handled in P05) or other 4xx.

2. src/cli.ts — parseArgs(argv) + runCli() dispatcher:
   - (default / no subcommand): serve — build config, keyManager, store,
     endpoints (resolveEndpoints), tokenClient, upstream, then runStdioBridge.
     This is what Claude Code invokes.
   - "login": run the full flow eagerly (resolveEndpoints -> authorize -> exchangeCode),
     print a STDERR success line with the jkt and token expiry, exit 0.
   - "logout": store.clear() and delete the DPoP key file if DPOP_KEY_MODE=persistent;
     confirm to STDERR.
   - "doctor": print (STDERR) a diagnostics report — config (secrets redacted), resolved
     endpoints, stored-token presence + expiry, key jkt, and one unauthenticated
     `initialize` round-trip to the adapter to confirm reachability. Exit non-zero if
     the adapter is unreachable.
   - "--version"/"-v": VERSION to STDERR, exit 0.  "--help"/"-h": usage to STDERR, exit 0.
   - Support --flag overrides for the main config keys (--adapter-base-url, --client-id,
     --agent-id, ...) layered over env.

3. Graceful shutdown in src/index.ts: install SIGINT/SIGTERM handlers that stop the stdio
   loop, flush stderr, close any open loopback server, and exit 0. index.ts calls
   runCli(process.argv).catch -> log to stderr and exit 1.

4. tests/cli.test.ts:
   - parseArgs maps subcommands and flags; flags override env.
   - "doctor" with a mocked reachable adapter exits 0 and reports endpoints; unreachable -> non-zero.
   - "logout" clears the token store (and key file in persistent mode).
   tests/retry.test.ts:
   - withBackoff retries on 503 up to the limit then succeeds; does NOT retry on 400/401.

Run: bun test && bun run typecheck. All tests must pass. Commit.
````

**Expected Output:** A CLI with `serve` (default), `login`, `logout`, `doctor`, `--version`, and `--help`; bounded backoff for transient upstream errors; and clean signal-driven shutdown.

---

## Prompt P07: Integration Tests, README, Setup Docs, Compiled Binary

**Context:** Final hardening and operator-facing deliverables. An end-to-end integration test exercises the full stdio→DPoP→adapter path against a **mock adapter that re-implements the DPoP verifier contract** (so a green test is real evidence the bridge's proofs would pass the actual adapter — no adapter source required). The README and setup docs (markdown) cover the Okta app flag, the adapter agent's `require_dpop`, and registration in Claude Code; and `bun build --compile` produces a single distributable.

**Prompt:**

````
Add integration tests and operator documentation, and verify the compiled binary.
All docs are markdown. This repo is standalone and must not depend on the adapter's
source being present.

Execute the following:

1. tests/integration.test.ts — spin up a mock adapter (Bun.serve) that faithfully
   re-implements the adapter's DPoP contract:
   - serves /.well-known/oauth-protected-resource and /.well-known/oauth-authorization-server
     pointing token/authorize at itself;
   - /token: rejects the FIRST proof with 400 {"error":"use_dpop_nonce"} + DPoP-Nonce
     header; on retry, verifies the proof with jose (typ "dpop+jwt", alg ES256, htm POST,
     htu == token endpoint canonical, nonce present) and returns a DPoP-bound access token
     (a JWT whose cnf.jkt == the proof's jkt; token_type "DPoP");
   - POST /: requires Authorization: DPoP; verifies the per-request proof (htm POST,
     htu "<base>/", ath matches the token, jti not seen before -> maintain a Set);
     compares the token's cnf.jkt to the proof jkt; echoes a tools/list result; and 401s
     with use_dpop_nonce EXACTLY ONCE to exercise the resource-side nonce path.
   Drive the whole bridge programmatically (inject a stub authorize() returning a code) and
   assert: initialize passes unauthed; tools/call succeeds end-to-end; a replayed jti is
   rejected; the bridge recovers from the resource-side nonce challenge; a cnf.jkt mismatch
   is rejected. This mock IS the contract test — keep its checks aligned with the spec table
   at the top of this document.
   - OPTIONAL cross-check (skipped unless ADAPTER_REPO env points at a checked-out adapter):
     if present, read <ADAPTER_REPO>/okta_agent_proxy/auth/dpop_verifier.py and assert the
     mock's allowed algs and iat window still match (string-grep the constants). Skip cleanly
     when ADAPTER_REPO is unset so CI stays self-contained.

2. README.md (replace the P01 stub) — markdown:
   - what the bridge is + the ascii architecture diagram;
   - "Standalone repository" note (no adapter code dependency);
   - install (bun install / the compiled binary);
   - configuration table (every env var from src/config.ts);
   - quickstart: `okta-mcp-bridge login` then `okta-mcp-bridge doctor`;
   - the stdout-is-sacred / stderr-logging note;
   - troubleshooting (use_dpop_nonce loops, jkt_mismatch, 401 -> require_dpop/agent mismatch,
     htu mismatch behind a proxy).

3. docs/SETUP.md — operator guide. Document ONLY bridge/adapter-specific choices; link to
   Okta's DPoP guide rather than reproducing console click-paths:
   - Okta app: OIDC app (Native recommended for a PKCE public client; Web also works); enable
     "Require Demonstrating Proof of Possession (DPoP) header in token requests"
     (API: settings.oauthClient.dpop_bound_access_tokens=true). Link to
     https://developer.okta.com/docs/guides/dpop/ and its non-Okta-resource-server section.
   - Redirect URI: add http://127.0.0.1:<port>/callback (+ the ephemeral-port note).
   - Scopes: openid offline_access (offline_access enables refresh).
   - Algorithm: ES256 (intersection of Okta's dpop_signing_alg_values_supported and the
     adapter's allowed ES256/ES384/RS256).
   - Adapter agent: create an agent whose client_id == the Okta app client_id and set
     require_dpop=true. The X-MCP-Agent value the bridge sends must equal that agent's id.
   - Verification: `okta-mcp-bridge doctor`, then a real tools/list, then check the adapter's
     audit stream for auth.dpop.verified events.

4. docs/CLAUDE_CODE.md — registering the bridge as a stdio MCP server in Claude Code: the
   `claude mcp add` command and the equivalent JSON config (command/args/env with
   ADAPTER_BASE_URL, OKTA_CLIENT_ID, AGENT_ID, etc.). Note that env here holds only public
   values (client_id, URLs); the DPoP key and tokens live in BRIDGE_HOME, not in the MCP config.

5. Add a "DCO" note + sign-off guidance to README (Apache-2.0 + Developer Certificate of Origin).

6. Build verification: `bun run build`; confirm dist/okta-mcp-bridge runs;
   `./dist/okta-mcp-bridge --version` prints VERSION to stderr.

Run: bun test && bun run typecheck && bun run build. All tests must pass and the binary
must build. Commit, and tag v0.1.0.
````

**Expected Output:** A green end-to-end integration test against a DPoP-enforcing mock adapter (with an optional adapter-source cross-check), complete markdown docs (README, Okta+adapter setup, Claude Code registration), a DCO note, and a working compiled single-file binary — tagged v0.1.0.

---

## After All 7 Prompts — Manual Verification

Run these from the repo root against a live adapter whose bridge-agent has `require_dpop=true`.

```bash
# 1. Pre-authenticate (opens a browser; completes Okta's DPoP nonce handshake)
ADAPTER_BASE_URL=https://<adapter> OKTA_CLIENT_ID=<id> AGENT_ID=<agent> \
  ./dist/okta-mcp-bridge login
# Expect stderr "oauth.token.acquired" with a jkt and expiry; ~/.okta-mcp-bridge/{tokens,dpop-key}.json written 0600.

# 2. Diagnostics (unauthed initialize round-trip + token status)
./dist/okta-mcp-bridge doctor

# 3. Register in Claude Code (stdio) — point at the compiled binary's absolute path
claude mcp add okta-bridge -- \
  env ADAPTER_BASE_URL=https://<adapter> OKTA_CLIENT_ID=<id> AGENT_ID=<agent> \
  /absolute/path/to/dist/okta-mcp-bridge
# Then in Claude Code: list tools / call a tool. Each call carries a fresh DPoP proof.

# 4. Confirm enforcement on the adapter side (Grafana/Loki or Splunk):
#      auth.dpop.verified         on successful calls
#      auth.dpop.required_missing  if a non-DPoP client hits the same agent
#      auth.dpop.replay_detected   if a jti is ever reused
```

## Notes, Gotchas, and Boundaries

- **Standalone by design.** Nothing in the bridge imports or builds against the adapter. The spec table at the top is the contract; the P07 mock adapter is the contract test. Keep them in sync if the adapter's DPoP rules ever change.
- **The token must be DPoP-bound by Okta.** The adapter compares the access token's `cnf.jkt` to the proof thumbprint. The reliable path is binding DPoP at Okta's `/token` (set `OKTA_ISSUER`); only rely on the adapter's token endpoint if it forwards the DPoP proof + nonce to Okta unchanged. P03/P04 support both.
- **`htu` must use the adapter's external base.** Behind an ALB/ingress, set `ADAPTER_BASE_URL` to the public URL, not the dialed host. Mismatch → `auth.dpop.rejected`.
- **ES256 only** unless you have a reason otherwise — the safe intersection of Okta's supported DPoP algs and the adapter's allowed set.
- **stdout discipline** is the most common stdio-MCP failure. The only stdout writes in the entire program are the JSON-RPC response lines in `src/server.ts`.
- **Nonce is expected twice over a session's life:** once at the initial `/token` call and again whenever Okta rotates it (~daily) or the adapter challenges a resource call. Both are single-retry paths, never loops.
- **Out of scope (deliberately):** the bridge does no policy/authorization itself — that stays in the adapter. mTLS-bound tokens (RFC 8705) are a future alternative to DPoP and not covered here.
