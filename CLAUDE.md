# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Current state

This repo is **pre-implementation**. The only content is the build spec at
`prompts/DPOP_STDIO_BRIDGE_PROMPTS.md` — seven sequential Claude Code prompts (P01–P07)
that build `okta-mcp-bridge` from scratch. There is no source code and no git commit yet.

If asked to "build the bridge," execute the prompts P01→P07 **in order**; each is
self-contained, idempotent, and ends by running tests + committing. Do not skip ahead —
later prompts depend on modules from earlier ones (e.g. P04 refactors crypto out of P02's
`src/dpop.ts`). The spec's "adapter contract" table is the **source of truth**; keep it and
the P07 mock-adapter test in sync if DPoP rules change.

## What the bridge is

`okta-mcp-bridge` is a Bun/TypeScript program that Claude Code launches as a **local stdio
MCP server**. It authenticates once against Okta with DPoP, then proxies every MCP call to a
remote **Okta MCP Adapter** over HTTPS, attaching a fresh DPoP proof per request
("login once, call many"). It is effectively a DPoP- and Okta-aware `mcp-remote`: bridging a
stdio transport (client side) to the adapter's Streamable HTTP transport (server side) while
owning the OAuth + DPoP lifecycle.

```
Claude Code ──stdio (MCP JSON-RPC)──▶ okta-mcp-bridge ──HTTPS + DPoP──▶ Okta Adapter (POST /)
                                            │
                                            └─ Auth Code + PKCE + DPoP (loopback) ──▶ Okta /token
```

**Standalone by design:** the bridge imports no adapter code and reads no adapter source.
Everything it needs to know about the adapter is the contract table in the spec; the P07
mock adapter is the contract test.

## Architecture (once built)

Planned `src/` layout, in dependency order:

- `config.ts` — `loadConfig()`: typed env config. Required: `ADAPTER_BASE_URL`,
  `OKTA_CLIENT_ID`, `AGENT_ID`. Notable optional: `OKTA_ISSUER`, `DPOP_ALG` (default ES256),
  `DPOP_KEY_MODE` (persistent|ephemeral), `BRIDGE_HOME` (default `~/.okta-mcp-bridge`).
- `logger.ts` — structured logger that writes **only to stderr** (one JSON line per event,
  with `ts`/`level`/`event`/`correlation_id`); includes token/key redaction helpers.
- `crypto.ts` — AES-256-GCM `sealJson`/`openJson` + `.seed`/HKDF; backs encrypted-at-rest files.
- `dpop.ts` — `DpopKeyManager` (key gen/persistence, RFC 7638 `jkt` thumbprint) and the
  proof factory (`createProof`), using `jose`. Default ES256 (EC P-256).
- `oauth/discovery.ts` — `resolveEndpoints()`: RFC 9728 → RFC 8414 metadata; `OKTA_ISSUER`
  override targets Okta's `/token` directly.
- `oauth/authcode.ts` — PKCE auth-code flow over a `127.0.0.1` loopback redirect (RFC 8252).
- `oauth/token.ts` — `DpopTokenClient`: code exchange, Okta nonce handshake, refresh, and the
  single `getAccessToken()` entry point. `store.ts` persists tokens encrypted.
- `upstream.ts` — `UpstreamClient`: forwards JSON-RPC to `POST <ADAPTER_BASE_URL>/` with auth
  headers + per-request proof; handles SSE responses, `Mcp-Session-Id`, and 401/nonce recovery.
- `server.ts` — `runStdioBridge()`: transparent stdin→upstream→stdout passthrough.
- `cli.ts` / `index.ts` — `serve` (default), `login`, `logout`, `doctor`. `retry.ts` adds backoff.

Dependencies are injected throughout so tests can mock them (fetch, opener, authorize fn).

## Commands

The project targets **Bun ≥ 1.1**. From the repo root once P01 has run:

```bash
bun install
bun test                       # run all tests (must pass after every prompt)
bun test tests/dpop.test.ts    # run a single test file
bun run typecheck              # tsc --noEmit
bun run build                  # bun build --compile -> dist/okta-mcp-bridge
bun run dev                    # bun run src/index.ts
```

## Non-negotiable invariants

These are the rules every change must honor (from the spec's cross-cutting rules):

1. **stdout is sacred.** stdout carries the MCP JSON-RPC stream. The *only* stdout writes in
   the entire program are the JSON-RPC response lines in `src/server.ts`. All logging,
   diagnostics, and errors go to **stderr**. A single stray `console.log` corrupts the protocol.
2. **Never log secrets.** Log thumbprints (`jkt`) and lengths only — never raw tokens, proof
   strings, auth codes, PKCE verifiers, or private-key material. Use the logger's redaction helpers.
3. **Secrets at rest** live under `BRIDGE_HOME` (`~/.okta-mcp-bridge/`), files `chmod 600`,
   dir `0700`, encrypted via `crypto.ts`. Never write plaintext key/token material.
4. **DPoP proof contract** (what the adapter verifies — build proofs exactly this way):
   - header `typ:"dpop+jwt"`, `alg` ES256 (default), embedded **public** JWK only.
   - claims `htm`/`htu`/`iat`/`jti`; single-use `jti`; `iat` 300s window + 60s skew.
   - `ath` (= base64url(sha256(access_token))) **required** on any proof sent with a token.
   - `htu` is canonical: lowercase scheme+host, strip default ports, **drop query/fragment**,
     keep path. Adapter calls use `htu = <ADAPTER_BASE_URL>/`.
   - The token's `cnf.jkt` must equal the proof's `jkt` — reuse the same key for proofs;
     bind DPoP at Okta (`OKTA_ISSUER`) so the minted token is jkt-bound.
   - Always send `Authorization: DPoP <token>` (the `DPoP` scheme forces proof enforcement)
     and `X-MCP-Agent: <AGENT_ID>`.
5. **Auth is lazy.** `initialize`, `ping`, and `notifications/*` pass through unauthenticated;
   the first other method triggers `getAccessToken()`.
6. **Nonce handshakes are single-retry, never loops.** Okta's `/token` returns
   `use_dpop_nonce` + `DPoP-Nonce` on the first call → retry once with the nonce in a fresh
   proof. The same single-retry pattern applies to resource-side 401 nonce challenges.
7. **Log event names mirror the adapter** (`dpop.proof.created`, `oauth.token.acquired`,
   `oauth.nonce.challenge`, `mcp.request.forwarded`, `auth.dpop.*`, …) so logs correlate
   across the bridge and adapter.
8. After each prompt: review `git diff`, run `bun test`, then commit. Tests must stay green.
