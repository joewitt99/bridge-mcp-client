// CLI dispatcher: serve (default), login, logout, doctor, --version, --help.
//
// Wires P01–P05 together. All human output goes to STDERR (stdout is reserved
// for the MCP JSON-RPC stream in serve mode). runCli returns an exit code; the
// process exit lives in index.ts.
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { loadConfig, type Config } from "./config.ts";
import { VERSION } from "./version.ts";
import { logger as defaultLogger, type Logger } from "./logger.ts";
import { DpopKeyManager } from "./dpop.ts";
import { TokenStore } from "./store.ts";
import { resolveEndpoints, type Endpoints } from "./oauth/discovery.ts";
import {
  authorize as defaultAuthorize,
  type AuthorizeOptions,
  type AuthorizeResult,
  type Opener,
} from "./oauth/authcode.ts";
import { DpopTokenClient } from "./oauth/token.ts";
import { UpstreamClient, type TokenProvider } from "./upstream.ts";
import { runStdioBridge } from "./server.ts";

export type Command = "serve" | "login" | "logout" | "doctor" | "version" | "help";

export interface ParsedArgs {
  command: Command;
  /** Flag overrides mapped to config/env keys. */
  overrides: Record<string, string>;
}

const FLAG_TO_ENV: Record<string, string> = {
  "--adapter-base-url": "ADAPTER_BASE_URL",
  "--client-id": "OKTA_CLIENT_ID",
  "--agent-id": "AGENT_ID",
  "--issuer": "OKTA_ISSUER",
  "--redirect-port": "OKTA_REDIRECT_PORT",
  "--scopes": "OKTA_SCOPES",
  "--alg": "DPOP_ALG",
  "--key-mode": "DPOP_KEY_MODE",
  "--bridge-home": "BRIDGE_HOME",
  "--timeout": "HTTP_TIMEOUT_MS",
  "--log-level": "LOG_LEVEL",
};

const SUBCOMMANDS = new Set<Command>(["serve", "login", "logout", "doctor"]);

const USAGE = `okta-mcp-bridge ${VERSION}

Usage: okta-mcp-bridge [command] [flags]

Commands:
  serve     (default) Run the stdio MCP bridge. This is what Claude Code launches.
  login     Authenticate against Okta (browser) and store a DPoP-bound token.
  logout    Clear the stored token (and the DPoP key in persistent mode).
  doctor    Print a diagnostics report and probe the adapter for reachability.

Flags (override the matching env var):
  --adapter-base-url <url>   --client-id <id>      --agent-id <id>
  --issuer <url>             --redirect-port <n>   --scopes <s>
  --alg <ES256|ES384|RS256>  --key-mode <persistent|ephemeral>
  --bridge-home <dir>        --timeout <ms>        --log-level <level>
  -v, --version              -h, --help
`;

/** Parse user args (already sliced past argv[0..1]) into a command + overrides. */
export function parseArgs(args: string[]): ParsedArgs {
  let command: Command = "serve";
  let commandSet = false;
  const overrides: Record<string, string> = {};

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i]!;
    if (arg === "--version" || arg === "-v") {
      command = "version";
      commandSet = true;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      command = "help";
      commandSet = true;
      continue;
    }
    if (arg.startsWith("--")) {
      let key = arg;
      let value: string | undefined;
      const eq = arg.indexOf("=");
      if (eq >= 0) {
        key = arg.slice(0, eq);
        value = arg.slice(eq + 1);
      }
      const envKey = FLAG_TO_ENV[key];
      if (envKey) {
        if (value === undefined) {
          value = args[i + 1];
          i += 1;
        }
        if (value !== undefined) overrides[envKey] = value;
      }
      continue;
    }
    if (!commandSet && SUBCOMMANDS.has(arg as Command)) {
      command = arg as Command;
      commandSet = true;
    }
  }

  return { command, overrides };
}

export interface CliDeps {
  env?: Record<string, string | undefined>;
  fetch?: typeof fetch;
  authorize?: (
    config: Config,
    endpoints: Endpoints,
    opts?: AuthorizeOptions,
  ) => Promise<AuthorizeResult>;
  opener?: Opener;
  logger?: Logger;
  runBridge?: typeof runStdioBridge;
}

/** Dispatch a CLI invocation. Returns the process exit code. */
export async function runCli(argv: string[], deps: CliDeps = {}): Promise<number> {
  const logger = deps.logger ?? defaultLogger;
  const parsed = parseArgs(argv.slice(2));

  if (parsed.command === "version") {
    process.stderr.write(`okta-mcp-bridge ${VERSION}\n`);
    return 0;
  }
  if (parsed.command === "help") {
    process.stderr.write(USAGE);
    return 0;
  }

  const env = { ...(deps.env ?? process.env), ...parsed.overrides };
  let config: Config;
  try {
    config = loadConfig(env);
  } catch (err) {
    process.stderr.write(`okta-mcp-bridge: ${(err as Error).message}\n`);
    return 2;
  }

  switch (parsed.command) {
    case "serve":
      return serve(config, deps, logger);
    case "login":
      return login(config, deps, logger);
    case "logout":
      return logout(config, logger);
    case "doctor":
      return doctor(config, deps, logger);
  }
}

async function serve(config: Config, deps: CliDeps, logger: Logger): Promise<number> {
  const doFetch = deps.fetch ?? fetch;
  const authorizeImpl = deps.authorize ?? defaultAuthorize;
  const runBridge = deps.runBridge ?? runStdioBridge;

  const keyManager = await DpopKeyManager.create(config, logger);
  const store = new TokenStore(config.BRIDGE_HOME);
  const endpoints = await resolveEndpoints(config, { fetch: doFetch, logger });
  const tokenClient = new DpopTokenClient(config, endpoints, keyManager, store, logger, {
    fetch: doFetch,
  });
  const upstream = new UpstreamClient(config, keyManager, tokenClient, logger, {
    fetch: doFetch,
  });
  const authorizeFn = () =>
    authorizeImpl(config, endpoints, { opener: deps.opener, logger });

  await runBridge({
    config,
    upstream,
    authorizeFn,
    logger,
    // index.ts owns SIGINT/SIGTERM so the loopback server is closed centrally.
    installSignalHandlers: false,
  });
  return 0;
}

async function login(config: Config, deps: CliDeps, logger: Logger): Promise<number> {
  const doFetch = deps.fetch ?? fetch;
  const authorizeImpl = deps.authorize ?? defaultAuthorize;

  const keyManager = await DpopKeyManager.create(config, logger);
  const store = new TokenStore(config.BRIDGE_HOME);
  const endpoints = await resolveEndpoints(config, { fetch: doFetch, logger });
  const tokenClient = new DpopTokenClient(config, endpoints, keyManager, store, logger, {
    fetch: doFetch,
  });

  const result = await authorizeImpl(config, endpoints, { opener: deps.opener, logger });
  const set = await tokenClient.exchangeCode(result);
  const expiry = new Date(set.expiresAt * 1000).toISOString();
  process.stderr.write(
    `okta-mcp-bridge: logged in (jkt=${set.jkt}, expires=${expiry})\n`,
  );
  return 0;
}

async function logout(config: Config, logger: Logger): Promise<number> {
  const store = new TokenStore(config.BRIDGE_HOME);
  store.clear();
  if (config.DPOP_KEY_MODE === "persistent") {
    const keyPath = join(config.BRIDGE_HOME, "dpop-key.json");
    if (existsSync(keyPath)) rmSync(keyPath, { force: true });
  }
  logger.info("auth.logout");
  process.stderr.write("okta-mcp-bridge: logged out (token and key cleared)\n");
  return 0;
}

/** A TokenProvider that refuses use — doctor only does an unauthed round-trip. */
const noAuthProvider: TokenProvider = {
  async getAccessToken() {
    throw new Error("doctor performs unauthenticated probes only");
  },
  clearStored() {},
};

async function doctor(config: Config, deps: CliDeps, logger: Logger): Promise<number> {
  const doFetch = deps.fetch ?? fetch;
  const out = (line: string) => process.stderr.write(line + "\n");

  const keyManager = await DpopKeyManager.create(config, logger);
  const store = new TokenStore(config.BRIDGE_HOME);

  out("okta-mcp-bridge doctor");
  out(`  adapter:    ${config.ADAPTER_BASE_URL}`);
  out(`  client_id:  ${config.OKTA_CLIENT_ID}`);
  out(`  agent_id:   ${config.AGENT_ID}`);
  out(`  issuer:     ${config.OKTA_ISSUER ?? "(adapter discovery)"}`);
  out(`  redirect:   http://127.0.0.1:${config.OKTA_REDIRECT_PORT}/callback`);
  if (config.OKTA_REDIRECT_PORT === 0) {
    out("  WARNING:    OKTA_REDIRECT_PORT=0 (ephemeral) — Okta needs a fixed, pre-registered port; set OKTA_REDIRECT_PORT");
  }
  out(`  alg:        ${config.DPOP_ALG}`);
  out(`  bridge_home:${config.BRIDGE_HOME}`);
  out(`  key jkt:    ${await keyManager.jkt()}`);

  const token = store.load();
  if (token) {
    const expiry = new Date(token.expiresAt * 1000).toISOString();
    const flag = store.isExpired(token) ? " (EXPIRED)" : "";
    out(`  token:      present, expires ${expiry}${flag}`);
  } else {
    out("  token:      none (run `login`)");
  }

  let endpoints: Endpoints;
  try {
    endpoints = await resolveEndpoints(config, { fetch: doFetch, logger });
  } catch (err) {
    out(`  endpoints:  UNRESOLVED — ${(err as Error).message}`);
    out("  adapter:    UNREACHABLE");
    return 1;
  }
  out(`  authorization_endpoint: ${endpoints.authorizationEndpoint}`);
  out(`  token_endpoint:         ${endpoints.tokenEndpoint}`);

  // One unauthenticated initialize round-trip to confirm reachability.
  const upstream = new UpstreamClient(config, keyManager, noAuthProvider, logger, {
    fetch: doFetch,
  });
  const resp = (await upstream.forwardUnauthed({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {},
  })) as { error?: unknown } | null;

  if (resp && typeof resp === "object" && "error" in resp && resp.error) {
    out("  adapter:    UNREACHABLE (initialize failed)");
    return 1;
  }
  out("  adapter:    reachable");
  return 0;
}
