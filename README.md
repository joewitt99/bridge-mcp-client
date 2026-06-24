# okta-mcp-bridge

A lightweight, single-binary **Go** program that Claude Code (or Cursor, etc.) launches as
a local **stdio MCP server**. It authenticates **once** against Okta with DPoP, then
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
(`internal/integration/integration_test.go`), which drives the bridge against a mock
adapter (`internal/mockadapter`) that re-implements that contract.

## Install

Requires **Go ≥ 1.24** (CI builds and tests on 1.26).

Build a single static binary:

```bash
go build -o okta-mcp-bridge ./cmd/okta-mcp-bridge
```

Or install it onto your `PATH` (lands in `$(go env GOPATH)/bin`):

```bash
go install github.com/joewitt99/bridge-mcp-client/cmd/okta-mcp-bridge@latest
```

During development you can also run straight from source:

```bash
go run ./cmd/okta-mcp-bridge doctor
```

### Build & test

```bash
go build ./...                 # compile everything
go test ./...                  # run all tests against the mock adapter
go test -race ./...            # what CI runs
go vet ./...                   # static checks

# build a stamped, stripped release binary for the current platform
go build -trimpath -ldflags "-s -w \
  -X github.com/joewitt99/bridge-mcp-client/internal/version.Version=$(git describe --tags --always)" \
  -o okta-mcp-bridge ./cmd/okta-mcp-bridge
```

Cross-compiling is just `GOOS`/`GOARCH` (CGO is not used):

```bash
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o okta-mcp-bridge        ./cmd/okta-mcp-bridge
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o okta-mcp-bridge.exe    ./cmd/okta-mcp-bridge
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -o okta-mcp-bridge        ./cmd/okta-mcp-bridge
```

Tagged releases (`v*`) build all targets and publish signed checksums + an SBOM via the
release workflow.

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
| `OKTA_TOKEN_DPOP_HTU` | | (= dialed token endpoint) | `--token-dpop-htu` | Override **only** the `htu` claim on the `/token` DPoP proof. For a BFF/proxy adapter that relays the proof to Okta: keep dialing the adapter, but set this to **Okta's real token endpoint** so the proof's `htu` matches what Okta recomputes. |
| `OKTA_REDIRECT_PORT` | (with Okta, yes) | `0` (ephemeral) | `--redirect-port` | Loopback redirect port. **Okta requires a fixed port** matching the registered redirect URI exactly — pin one (e.g. `8765`); the `0` default does not work with Okta. |
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
export OKTA_REDIRECT_PORT=8765   # must match the redirect URI registered in Okta exactly

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
are the JSON-RPC response lines in `internal/bridge/server.go`. All logging, diagnostics,
and errors go to **stderr** as one JSON line per event
(`ts`/`level`/`event`/`correlation_id`). Secrets are never logged — only thumbprints
(`jkt`) and lengths. A single stray `fmt.Println`/`os.Stdout` write would corrupt the
protocol, so CI fails the build if any stdout write appears outside that one file.

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
- **`use_dpop_nonce` never settles through a BFF adapter.** Okta returns the nonce in a
  **`DPoP-Nonce` response header**; the bridge must read it to build the retry proof. If you
  see `oauth.nonce.missing_header` (the bridge got `use_dpop_nonce` but no header), a
  proxy/BFF is stripping `DPoP-Nonce` — configure the adapter to relay that response header
  back to the bridge (on both the `400` challenge and the success response).
- **`redirect_uri` mismatch / login never returns.** Okta matches the loopback redirect URI
  **exactly, including the port**, and does not honor ephemeral/dynamic ports — even with a
  wildcard registered. Set `OKTA_REDIRECT_PORT` to a fixed port and register
  `http://127.0.0.1:<port>/callback` in the Okta app exactly. The `0` (ephemeral) default
  will not work with Okta.
- **`htu` mismatch behind a proxy/ALB.** Set `ADAPTER_BASE_URL` to the adapter's **public**
  external URL, not the dialed host. The proof's `htu` must byte-match what the adapter
  recomputes, or you'll see `auth.dpop.rejected`.
- **`/token` proof rejected through a BFF adapter.** If the adapter relays the bridge's
  `/token` DPoP proof to Okta, the proof's `htu` must match **Okta's** token endpoint (the
  verifier), not the adapter URL the bridge dials. Set `OKTA_TOKEN_DPOP_HTU` to Okta's real
  token endpoint (e.g. `https://your-org.okta.com/oauth2/v1/token`). The bridge keeps POSTing
  to the adapter; only the proof's `htu` changes. Run with `LOG_LEVEL=debug` to see
  `oauth.token.request` with `token_endpoint` (dialed) vs `proof_htu` (claimed).

## License & DCO

Licensed under **Apache-2.0** (see `LICENSE`).

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off each commit to certify you wrote the code (or have the right to submit it):

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer.
