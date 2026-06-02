// stdout is reserved for the MCP JSON-RPC stream; ANY stdout write corrupts the
// protocol. This logger writes ONLY to process.stderr. Never add a stdout write
// here, and never pass raw token or private-key material to it — use the
// redaction helpers below.
import { createHash } from "node:crypto";

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function currentThreshold(): number {
  const env = (process.env.LOG_LEVEL ?? "info").toLowerCase();
  return LEVEL_ORDER[env as LogLevel] ?? LEVEL_ORDER.info;
}

export interface Logger {
  log(level: LogLevel, event: string, fields?: Record<string, unknown>): void;
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
  /** Returns a child logger that injects `correlation_id` into every record. */
  withCorrelation(id: string): Logger;
}

function emit(
  level: LogLevel,
  event: string,
  correlationId: string | undefined,
  fields?: Record<string, unknown>,
): void {
  if (LEVEL_ORDER[level] < currentThreshold()) return;
  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    event,
  };
  if (correlationId !== undefined) record.correlation_id = correlationId;
  if (fields) {
    for (const [key, value] of Object.entries(fields)) record[key] = value;
  }
  process.stderr.write(JSON.stringify(record) + "\n");
}

function makeLogger(correlationId?: string): Logger {
  return {
    log: (level, event, fields) => emit(level, event, correlationId, fields),
    debug: (event, fields) => emit("debug", event, correlationId, fields),
    info: (event, fields) => emit("info", event, correlationId, fields),
    warn: (event, fields) => emit("warn", event, correlationId, fields),
    error: (event, fields) => emit("error", event, correlationId, fields),
    withCorrelation: (id) => makeLogger(id),
  };
}

export const logger: Logger = makeLogger();

/**
 * Render a token for logging without exposing it: its length and the first 12
 * hex chars of its SHA-256. Never returns the raw token.
 */
export function redactToken(token: string): string {
  const hash = createHash("sha256").update(token, "utf8").digest("hex");
  return `len=${token.length} sha256=${hash.slice(0, 12)}`;
}

/**
 * Render a JWK for logging with public metadata only (key type, curve, and the
 * RFC 7638 thumbprint). Private parameters are never read.
 */
export function redactKey(jwk: Record<string, unknown>): string {
  const kty = jwk.kty ?? "?";
  const crv = jwk.crv ?? "";
  let thumb = "?";
  try {
    thumb = jwkThumbprint(jwk);
  } catch {
    // best-effort: an unrecognized key shape just omits the thumbprint
  }
  return `kty=${kty} crv=${crv} jkt=${thumb}`;
}

// RFC 7638 thumbprint computed from the canonical public members only. The
// canonical (jose-based) implementation lives in src/dpop.ts; this sync copy
// exists so the logger has zero async dependencies.
function jwkThumbprint(jwk: Record<string, unknown>): string {
  let canonical: Record<string, unknown>;
  switch (jwk.kty) {
    case "EC":
      canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
      break;
    case "RSA":
      canonical = { e: jwk.e, kty: jwk.kty, n: jwk.n };
      break;
    case "OKP":
      canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
      break;
    default:
      canonical = { kty: jwk.kty };
  }
  return createHash("sha256")
    .update(JSON.stringify(canonical), "utf8")
    .digest("base64url");
}
