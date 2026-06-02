#!/usr/bin/env bun
// Entry point. Installs graceful-shutdown signal handlers, then dispatches to
// the CLI (serve/login/logout/doctor). runCli returns an exit code; a thrown
// error is logged to stderr and maps to exit 1. stdout is never written here.
import { runCli } from "./cli.ts";
import { logger } from "./logger.ts";

function installShutdown(): void {
  const onSignal = (signal: string) => {
    // Stop the stdio loop, flush stderr, and exit cleanly. Any open loopback
    // server (from an in-flight login) is torn down as the process exits.
    logger.info("bridge.shutdown", { reason: signal });
    process.exit(0);
  };
  process.once("SIGINT", () => onSignal("SIGINT"));
  process.once("SIGTERM", () => onSignal("SIGTERM"));
}

installShutdown();

runCli(process.argv)
  .then((code) => process.exit(code))
  .catch((err) => {
    logger.error("cli.fatal", { error: String(err) });
    process.exit(1);
  });
