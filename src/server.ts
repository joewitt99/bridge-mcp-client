// stdio MCP server: a transparent passthrough between Claude Code (stdin/stdout)
// and the adapter (via UpstreamClient). It reads newline-delimited JSON-RPC,
// routes each message (initialize/ping/notifications/* → unauthed; everything
// else → authed), and writes each response as ONE line to stdout.
//
// stdout is sacred: the writeResponse() call below is the ONLY place in the
// entire program that writes to stdout. All logging goes to stderr. A stray
// stdout write would corrupt the MCP protocol stream.
import type { Config } from "./config.ts";
import { logger as defaultLogger, type Logger } from "./logger.ts";
import type { AuthorizeFn } from "./oauth/token.ts";

/** The slice of UpstreamClient the server needs (eases testing). */
export interface UpstreamLike {
  forward(jsonRpc: unknown, authorizeFn: AuthorizeFn): Promise<unknown>;
  forwardUnauthed(jsonRpc: unknown): Promise<unknown>;
}

export interface StdioBridgeDeps {
  config: Config;
  upstream: UpstreamLike;
  authorizeFn: AuthorizeFn;
  /** Source of newline-delimited JSON-RPC; defaults to process.stdin. */
  input?: AsyncIterable<Uint8Array | string>;
  /** Sink for response lines; defaults to process.stdout. */
  output?: { write(chunk: string): unknown };
  logger?: Logger;
  /** Install SIGINT/SIGTERM handlers (default true; tests pass false). */
  installSignalHandlers?: boolean;
}

const ALWAYS_UNAUTHED = new Set(["initialize", "ping", "notifications/initialized"]);

function isUnauthed(method: string): boolean {
  return ALWAYS_UNAUTHED.has(method) || method.startsWith("notifications/");
}

/**
 * Run the stdio bridge until stdin EOF (or a termination signal). Resolves when
 * the input stream ends.
 */
export async function runStdioBridge(deps: StdioBridgeDeps): Promise<void> {
  const { config: _config, upstream, authorizeFn } = deps;
  const logger = deps.logger ?? defaultLogger;
  const input = deps.input ?? process.stdin;
  const output = deps.output ?? process.stdout;

  const writeResponse = (msg: unknown): void => {
    if (msg == null) return;
    // The one and only sanctioned stdout write in the program.
    output.write(JSON.stringify(msg) + "\n");
  };

  if (deps.installSignalHandlers !== false) {
    const onSignal = (signal: string) => {
      logger.info("bridge.shutdown", { reason: signal });
      process.exit(0);
    };
    process.once("SIGINT", () => onSignal("SIGINT"));
    process.once("SIGTERM", () => onSignal("SIGTERM"));
  }

  const handleLine = async (line: string): Promise<void> => {
    if (!line) return;
    let msg: { id?: unknown; method?: unknown } & Record<string, unknown>;
    try {
      msg = JSON.parse(line);
    } catch {
      // Don't crash on a bad message; the id isn't recoverable from invalid JSON.
      logger.warn("mcp.request.parse_error");
      return;
    }
    const method = typeof msg.method === "string" ? msg.method : "";
    const hasId = msg.id !== undefined && msg.id !== null;

    const response = isUnauthed(method)
      ? await upstream.forwardUnauthed(msg)
      : await upstream.forward(msg, authorizeFn);

    // Notifications (no id) get no response; requests get exactly one.
    if (!hasId) return;
    if (response && typeof response === "object") {
      (response as { id?: unknown }).id = msg.id; // preserve the request id exactly
    }
    writeResponse(response);
  };

  let buffer = "";
  for await (const chunk of input) {
    buffer +=
      typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    let nl: number;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      await handleLine(line);
    }
  }
  // Flush any trailing line without a terminating newline.
  if (buffer.trim()) await handleLine(buffer.trim());

  logger.info("bridge.shutdown", { reason: "eof" });
}
