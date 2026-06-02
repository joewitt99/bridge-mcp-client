# Registering the bridge in Claude Code

`okta-mcp-bridge` is a **stdio MCP server**: Claude Code launches it as a subprocess and
speaks MCP JSON-RPC over stdin/stdout. Point Claude Code at the compiled binary's absolute
path (or `bun run /abs/path/src/index.ts`).

## `claude mcp add`

```bash
claude mcp add okta-bridge -- \
  env ADAPTER_BASE_URL=https://adapter.example.com \
      OKTA_CLIENT_ID=0oaXXXXXXXXXXXXXX \
      AGENT_ID=my-agent \
      OKTA_REDIRECT_PORT=8765 \
      OKTA_ISSUER=https://your-org.okta.com/oauth2/default \
  /absolute/path/to/dist/okta-mcp-bridge
```

The default (no subcommand) `serve` mode is what runs here.

## Equivalent JSON config

In the MCP servers config (e.g. `~/.claude.json` or your client's `mcp` config), the same
registration looks like:

```json
{
  "mcpServers": {
    "okta-bridge": {
      "command": "/absolute/path/to/dist/okta-mcp-bridge",
      "args": [],
      "env": {
        "ADAPTER_BASE_URL": "https://adapter.example.com",
        "OKTA_CLIENT_ID": "0oaXXXXXXXXXXXXXX",
        "AGENT_ID": "my-agent",
        "OKTA_REDIRECT_PORT": "8765",
        "OKTA_ISSUER": "https://your-org.okta.com/oauth2/default"
      }
    }
  }
}
```

## What goes in `env` (and what doesn't)

The `env` block holds only **public** values: the adapter URL, the Okta client id, the
issuer, and the agent id. There are **no secrets here.** The DPoP private key and the
OAuth tokens are generated and stored encrypted under `BRIDGE_HOME`
(`~/.okta-mcp-bridge/`, files `0600`) — never in the MCP config.

## First run

Pre-authenticate once so the first tool call doesn't block on a browser:

```bash
ADAPTER_BASE_URL=... OKTA_CLIENT_ID=... AGENT_ID=... OKTA_REDIRECT_PORT=8765 OKTA_ISSUER=... \
  /absolute/path/to/dist/okta-mcp-bridge login
```

After that, Claude Code can list and call tools; each call carries a fresh DPoP proof.
If the token is missing or expired when a call arrives, the bridge refreshes (or, as a last
resort, opens a browser to re-login).
