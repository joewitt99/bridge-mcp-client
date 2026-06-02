# Setup

Operator guide for wiring `okta-mcp-bridge` to your Okta org and an Okta MCP Adapter.
This documents only the bridge/adapter-specific choices; for Okta console click-paths,
follow Okta's own DPoP guide rather than reproducing it here:
<https://developer.okta.com/docs/guides/dpop/> (see its **non-Okta resource server**
section in particular).

## 1. Okta OIDC application

Create an OIDC app for the bridge:

- **App type:** OIDC. **Native** is recommended (the bridge is a PKCE public client with a
  loopback redirect); a **Web** app also works.
- **Require DPoP:** enable *"Require Demonstrating Proof of Possession (DPoP) header in
  token requests"*. Via the Apps API this is
  `settings.oauthClient.dpop_bound_access_tokens = true`. This is what makes Okta mint a
  `cnf.jkt`-bound access token and enforce the `/token` nonce handshake.
- **Grant types:** Authorization Code (+ Refresh Token if you want silent refresh).

Copy the **Client ID** → `OKTA_CLIENT_ID`.

### Redirect URI

Add a loopback redirect URI:

```
http://127.0.0.1:<port>/callback
```

The bridge defaults to an **ephemeral port** (`OKTA_REDIRECT_PORT=0`). Okta matches
loopback redirect URIs by host+path and ignores the port (RFC 8252 §7.3), so registering
`http://127.0.0.1/callback` is sufficient. If your org requires an exact port, pin one with
`OKTA_REDIRECT_PORT` and register that.

### Scopes

```
openid offline_access
```

`offline_access` is what gives you a refresh token (silent refresh between sessions).

### Algorithm

Use **ES256**. It's the safe intersection of Okta's
`dpop_signing_alg_values_supported` (ES256/ES384/ES512/RS256/…) and the adapter's allowed
set (ES256/ES384/RS256). The bridge defaults to ES256; only change `DPOP_ALG` if you have a
specific reason.

### Bind DPoP at Okta

Set `OKTA_ISSUER` to your Okta authorization server issuer (e.g.
`https://your-org.okta.com/oauth2/<authServerId>`, or the org issuer for the org AS). The
bridge then mints the DPoP-bound token at Okta's `/token` directly. This is the reliable
path, because the adapter enforces `cnf.jkt` equality and the token must be bound by the
real issuer. Without `OKTA_ISSUER`, the bridge relies on the adapter's token endpoint
forwarding the DPoP proof + nonce to Okta unchanged.

## 2. Adapter agent

On the Okta MCP Adapter, create an **agent** for the bridge:

- The agent's **`client_id` must equal** the Okta app's Client ID.
- Set **`require_dpop=true`** on the agent.
- The **`X-MCP-Agent`** value the bridge sends (`AGENT_ID`) must equal that agent's id.

With `require_dpop=true`, the adapter rejects any non-DPoP call to this agent
(`auth.dpop.required_missing`) and verifies every proof
(`auth.dpop.verified` / `auth.dpop.rejected` / `auth.dpop.replay_detected`).

## 3. Verify

```bash
export ADAPTER_BASE_URL=https://adapter.example.com
export OKTA_CLIENT_ID=0oaXXXXXXXXXXXXXX
export AGENT_ID=my-agent
export OKTA_ISSUER=https://your-org.okta.com/oauth2/default   # recommended

okta-mcp-bridge login     # browser opens; Okta DPoP nonce handshake completes
okta-mcp-bridge doctor    # confirms endpoints + adapter reachability
```

After `login`, `~/.okta-mcp-bridge/{tokens,dpop-key}.json` exist with mode `0600`.
Then run a real `tools/list` (via Claude Code — see `CLAUDE_CODE.md`) and confirm
`auth.dpop.verified` events in the adapter's audit stream (Grafana/Loki, Splunk, etc.).

## `htu` behind a proxy

If the adapter sits behind an ALB/ingress, set `ADAPTER_BASE_URL` to the **public** URL,
not the internal dialed host. The proof's `htu` must byte-match what the adapter recomputes
from its external base URL; a mismatch yields `auth.dpop.rejected`.
