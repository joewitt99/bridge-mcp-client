# okta-mcp-bridge

A lightweight Bun/TypeScript program that Claude Code (or Cursor, etc.) launches as a
local **stdio MCP server**. It authenticates once against Okta with DPoP, then proxies
every MCP call to a remote Okta MCP Adapter over HTTPS, attaching a fresh DPoP proof per
request ("login once, call many").

**Status: scaffold.** This is a standalone repository — it imports no adapter code and
reads no adapter source. The full README, setup docs, and compiled binary arrive in P07.
