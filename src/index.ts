#!/usr/bin/env bun
// Entry point. For P01 this is a minimal placeholder: it prints the bridge name
// and version to STDERR (never stdout) and exits. The real CLI dispatcher and
// stdio MCP server are wired up in P05/P06.
import { VERSION } from "./version.ts";

function main(): void {
  process.stderr.write(`okta-mcp-bridge ${VERSION}\n`);
  process.exit(0);
}

main();
