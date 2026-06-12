// Command okta-mcp-bridge is the stdio MCP bridge entry point. Go port of
// src/index.ts: install signal handlers, dispatch to the CLI, exit with its code.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/joewitt99/bridge-mcp-client/internal/cli"
)

func main() {
	// main owns SIGINT/SIGTERM: cancellation propagates to serve's stdio loop,
	// which returns cleanly (exit 0). A second signal force-quits.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(cli.Run(ctx, os.Args[1:], cli.CliDeps{}))
}
