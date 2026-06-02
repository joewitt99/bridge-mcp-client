# okta-mcp-bridge

A lightweight Bun/TypeScript program that Claude Code (or Cursor, etc.) launches as a
local **stdio MCP server**. It authenticates **once** against Okta with DPoP, then
proxies every MCP call to a remote **Okta MCP Adapter** over HTTPS, attaching a fresh
DPoP proof per request — "login once, call many". It is, in effect, a DPoP- and
Okta-aware `mcp-remote`: bridging a stdio transport (client side) to the adapter's
Streamable HTTP transport (server side) while owning the OAuth + DPoP lifecycle.

```
Claude Code ──stdio (MCP JSON-RPC)──▶ okta-mcp-bridge ──HTTPS + DPoP──▶ Okta Adapter (POST /)
                                            │
                                            └─ Auth Code + PKCE + DPoP (loopback) ──▶ Okta /token
                                                              (mints a cnf.jkt-bound token)
```

## Standalone repository

This repo has **zero code coupling** to the adapter: it imports no adapter code and reads
none of its source at runtime. Everything it needs to know about the adapter is the DPoP
proof contract, captured in the spec and enforced by the end-to-end test
(`tests/integration.test.ts`), which drives the bridge against a mock adapter that
re-implements that contract.

## Install

Requires **Bun ≥ 1.1**.

```bash
bun install
bun run build      # produces a single binary at dist/okta-mcp-bridge
```

You can run from source (`bun run src/index.ts ...`) or use the compiled
`dist/okta-mcp-bridge`.

## Configuration

All configuration is via environment variables (each has a matching `--flag` override).
The DPoP key and tokens are **not** configured here — they live encrypted under
`BRIDGE_HOME`.

| Env var | Required | Default | Flag | Description |
|---|---|---|---|---|
| `ADAPTER_BASE_URL` | ✅ | — | `--adapter-base-url` | Adapter's **external** base URL (e.g. `https://adapter.example.com`). |
| `OKTA_CLIENT_ID` | ✅ | — | `--client-id` | Okta OIDC app client ID. |
| `AGENT_ID` | ✅ | — | `--agent-id` | Adapter agent id; sent as `X-MCP-Agent`. |
| `OKTA_ISSUER` | | (adapter discovery) | `--issuer` | If set, mint the token at Okta directly (recommended; see below). |
| `OKTA_REDIRECT_PORT` | | `0` (ephemeral) | `--redirect-port` | Loopback redirect port for the auth-code flow. |
| `OKTA_SCOPES` | | `openid offline_access` | `--scopes` | `offline_access` enables refresh tokens. |
| `DPOP_ALG` | | `ES256` | `--alg` | One of `ES256` / `ES384` / `RS256`. |
| `DPOP_KEY_MODE` | | `persistent` | `--key-mode` | `persistent` (key on disk) or `ephemeral` (re-login each start). |
| `BRIDGE_HOME` | | `~/.okta-mcp-bridge` | `--bridge-home` | Where the encrypted key + tokens live (`0700`, files `0600`). |
| `HTTP_TIMEOUT_MS` | | `30000` | `--timeout` | Per-request upstream timeout. |
| `LOG_LEVEL` | | `info` | `--log-level` | `debug` / `info` / `warn` / `error`. |

> **Bind DPoP at Okta.** The adapter compares the access token's `cnf.jkt` to the proof
> thumbprint, so the token must be DPoP-bound **by Okta**. Set `OKTA_ISSUER` to mint the
> token at Okta's `/token` directly. See `docs/SETUP.md`.

## Quickstart

```bash
export ADAPTER_BASE_URL=https://adapter.example.com
export OKTA_CLIENT_ID=0oaXXXXXXXXXXXXXX
export AGENT_ID=my-agent

okta-mcp-bridge login     # opens a browser; completes Okta's DPoP nonce handshake
okta-mcp-bridge doctor    # config, resolved endpoints, token status, adapter reachability
```

Then register it in Claude Code as a stdio MCP server — see `docs/CLAUDE_CODE.md`.

## Commands

- **serve** (default) — run the stdio bridge. This is what Claude Code launches.
- **login** — authenticate eagerly and store a DPoP-bound token.
- **logout** — clear the stored token (and the DPoP key in persistent mode).
- **doctor** — diagnostics report + one unauthenticated `initialize` probe; non-zero exit
  if the adapter is unreachable.
- **--version** / **--help**.

## stdout is sacred

stdout carries the MCP JSON-RPC stream. The **only** stdout writes in the entire program
are the JSON-RPC response lines in `src/server.ts`. All logging, diagnostics, and errors
go to **stderr** as one JSON line per event (`ts`/`level`/`event`/`correlation_id`).
Secrets are never logged — only thumbprints (`jkt`) and lengths. A single stray
`console.log` to stdout would corrupt the protocol.

## Troubleshooting

- **`use_dpop_nonce` doesn't settle.** Okta's `/token` requires a nonce handshake (first
  call → `use_dpop_nonce` + `DPoP-Nonce`, retry once with the nonce). The bridge does this
  automatically as a *single* retry, and re-arms it when Okta rotates the nonce (~daily).
  Persistent failures usually mean the proof's `htu`/`htm` don't match the token endpoint.
- **`oauth.token.jkt_mismatch`.** The minted token's `cnf.jkt` ≠ the bridge key. Ensure
  DPoP is bound at Okta (`OKTA_ISSUER`) and that you didn't rotate the key after minting
  (`logout` clears both; `login` again).
- **401 on every authed call.** The adapter agent likely has `require_dpop=true` but the
  `X-MCP-Agent` value (`AGENT_ID`) doesn't match an agent whose `client_id` equals your
  Okta app — or the token isn't DPoP-bound. Check the adapter's `auth.dpop.*` audit events.
- **`htu` mismatch behind a proxy/ALB.** Set `ADAPTER_BASE_URL` to the adapter's **public**
  external URL, not the dialed host. The proof's `htu` must byte-match what the adapter
  recomputes, or you'll see `auth.dpop.rejected`.

## License & DCO

Licensed under **Apache-2.0** (see `LICENSE`).

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off each commit to certify you wrote the code (or have the right to submit it):

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer.
