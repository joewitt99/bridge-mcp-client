// Package cli is the command dispatcher: serve (default), login, logout, doctor,
// --version, --help. Go port of src/cli.ts. All human output goes to stderr
// (stdout is the MCP JSON-RPC stream in serve mode). Run returns an exit code.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/bridge"
	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
	"github.com/joewitt99/bridge-mcp-client/internal/store"
	"github.com/joewitt99/bridge-mcp-client/internal/upstream"
	"github.com/joewitt99/bridge-mcp-client/internal/version"
)

// Parsed is the result of ParseArgs.
type Parsed struct {
	Command   string // serve | login | logout | doctor | token | call | nonce-replay | version | help
	Overrides map[string]string
	Flags     map[string]string // non-env demo flags (--no-proof, --params, --method, …)
	Args      []string          // positional args after the command (e.g. the method for `call`)
}

// demoValueFlags are non-env flags that take a value; all other unknown flags
// are treated as booleans ("true" when present).
var demoValueFlags = map[string]bool{"--params": true, "--method": true}

var flagToEnv = map[string]string{
	"--adapter-base-url": "ADAPTER_BASE_URL",
	"--client-id":        "OKTA_CLIENT_ID",
	"--agent-id":         "AGENT_ID",
	"--issuer":           "OKTA_ISSUER",
	"--token-dpop-htu":   "OKTA_TOKEN_DPOP_HTU",
	"--redirect-port":    "OKTA_REDIRECT_PORT",
	"--scopes":           "OKTA_SCOPES",
	"--alg":              "DPOP_ALG",
	"--key-mode":         "DPOP_KEY_MODE",
	"--bridge-home":      "BRIDGE_HOME",
	"--timeout":          "HTTP_TIMEOUT_MS",
	"--log-level":        "LOG_LEVEL",
}

var subcommands = map[string]bool{
	"serve": true, "login": true, "logout": true, "doctor": true,
	"token": true, "call": true, "nonce-replay": true,
}

const usage = `okta-mcp-bridge

Usage: okta-mcp-bridge [command] [flags]

Commands:
  serve         (default) Run the stdio MCP bridge. This is what Claude Code launches.
  login         Authenticate against Okta (browser) and store a DPoP-bound token.
  logout        Clear the stored token (and the DPoP key in persistent mode).
  doctor        Print a diagnostics report and probe the adapter for reachability.
  token         Show the stored token's binding (token_type, jwt/opaque, cnf.jkt). [--raw]
  call          Send one MCP call to the adapter with controllable DPoP headers.
                <method> [--params <json>] [--no-proof] [--no-auth] [--no-init]
  nonce-replay  Demonstrate AS nonce-replay rejection (needs a prior login).

Flags (override the matching env var):
  --adapter-base-url <url>   --client-id <id>      --agent-id <id>
  --issuer <url>             --token-dpop-htu <url>
  --redirect-port <n>        --scopes <s>
  --alg <ES256>              --key-mode <persistent|ephemeral>
  --bridge-home <dir>        --timeout <ms>        --log-level <level>
  -v, --version              -h, --help
`

// ParseArgs parses user args (already sliced past the program name).
func ParseArgs(args []string) Parsed {
	command := "serve"
	commandSet := false
	overrides := map[string]string{}
	flags := map[string]string{}
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--version" || arg == "-v":
			command, commandSet = "version", true
		case arg == "--help" || arg == "-h":
			command, commandSet = "help", true
		case strings.HasPrefix(arg, "--"):
			key, value, hasValue := arg, "", false
			if eq := strings.IndexByte(arg, '='); eq >= 0 {
				key, value, hasValue = arg[:eq], arg[eq+1:], true
			}
			if envKey, ok := flagToEnv[key]; ok {
				if !hasValue && i+1 < len(args) {
					value, hasValue = args[i+1], true
					i++
				}
				if hasValue {
					overrides[envKey] = value
				}
				continue
			}
			// Non-env demo flag: value flags consume the next arg; the rest are booleans.
			if !hasValue && demoValueFlags[key] && i+1 < len(args) {
				value, hasValue = args[i+1], true
				i++
			}
			if hasValue {
				flags[key] = value
			} else {
				flags[key] = "true"
			}
		default:
			if !commandSet && subcommands[arg] {
				command, commandSet = arg, true
			} else if commandSet {
				positional = append(positional, arg)
			}
		}
	}
	return Parsed{Command: command, Overrides: overrides, Flags: flags, Args: positional}
}

// CliDeps are optional injectables (tests).
type CliDeps struct {
	Env       map[string]string
	Doer      oauth.Doer
	Authorize func(config.Config, oauth.Endpoints, oauth.AuthorizeOptions) (oauth.AuthCodeResult, error)
	Opener    oauth.Opener
	Logger    *logx.Logger
	Stderr    io.Writer // human output sink (default os.Stderr)
	Input     io.Reader // serve stdin (defaults to the process stdin)
	Output    io.Writer // serve response sink (defaults to the process stdout)
	RunBridge func(context.Context, bridge.Deps) error
}

// Run dispatches a CLI invocation and returns the process exit code.
func Run(ctx context.Context, args []string, deps CliDeps) int {
	stderr := deps.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	parsed := ParseArgs(args)

	switch parsed.Command {
	case "version":
		fmt.Fprintf(stderr, "okta-mcp-bridge %s\n", version.Version)
		return 0
	case "help":
		fmt.Fprint(stderr, usage)
		return 0
	}

	env := deps.Env
	if env == nil {
		env = config.EnvMap()
	}
	merged := map[string]string{}
	for k, v := range env {
		merged[k] = v
	}
	for k, v := range parsed.Overrides {
		merged[k] = v
	}

	cfg, err := config.Load(merged)
	if err != nil {
		fmt.Fprintf(stderr, "okta-mcp-bridge: %s\n", err.Error())
		return 2
	}

	logger := deps.Logger
	if logger == nil {
		logger = logx.New(cfg.LogLevel)
	}
	doer := deps.Doer
	if doer == nil {
		doer = &http.Client{Timeout: cfg.HTTPTimeout}
	}

	switch parsed.Command {
	case "serve":
		return serve(ctx, cfg, deps, logger, doer)
	case "login":
		return login(ctx, cfg, deps, logger, doer, stderr)
	case "logout":
		return logout(cfg, logger, stderr)
	case "doctor":
		return doctor(ctx, cfg, deps, logger, doer, stderr)
	case "token":
		return tokenCmd(cfg, logger, stderr, parsed)
	case "call":
		return callCmd(ctx, cfg, deps, logger, doer, stderr, parsed)
	case "nonce-replay":
		return nonceReplayCmd(ctx, cfg, deps, logger, doer, stderr)
	}
	return 0
}

func authorizeImpl(deps CliDeps) func(config.Config, oauth.Endpoints, oauth.AuthorizeOptions) (oauth.AuthCodeResult, error) {
	if deps.Authorize != nil {
		return deps.Authorize
	}
	return oauth.Authorize
}

func serve(ctx context.Context, cfg config.Config, deps CliDeps, logger *logx.Logger, doer oauth.Doer) int {
	km, err := dpop.NewKeyManager(cfg, logger)
	if err != nil {
		logger.Error("cli.serve.error", logx.Fields{"error": err.Error()})
		return 1
	}
	st := store.New(cfg.BridgeHome)
	endpoints, err := oauth.ResolveEndpoints(ctx, cfg, doer, logger)
	if err != nil {
		logger.Error("cli.serve.error", logx.Fields{"error": err.Error()})
		return 1
	}
	tokenClient := oauth.NewTokenClient(cfg, endpoints, km, st, logger, doer)
	up := upstream.New(cfg, km, tokenClient, logger, upstream.Deps{Doer: doer})
	authorize := authorizeImpl(deps)
	authFn := func() (oauth.AuthCodeResult, error) {
		return authorize(cfg, endpoints, oauth.AuthorizeOptions{Opener: deps.Opener, Logger: logger})
	}
	runBridge := deps.RunBridge
	if runBridge == nil {
		runBridge = bridge.Run
	}
	err = runBridge(ctx, bridge.Deps{Upstream: up, AuthFn: authFn, Input: deps.Input, Output: deps.Output, Logger: logger})
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("cli.serve.error", logx.Fields{"error": err.Error()})
		return 1
	}
	return 0
}

func login(ctx context.Context, cfg config.Config, deps CliDeps, logger *logx.Logger, doer oauth.Doer, stderr io.Writer) int {
	km, err := dpop.NewKeyManager(cfg, logger)
	if err != nil {
		fmt.Fprintf(stderr, "okta-mcp-bridge: %s\n", err.Error())
		return 1
	}
	st := store.New(cfg.BridgeHome)
	endpoints, err := oauth.ResolveEndpoints(ctx, cfg, doer, logger)
	if err != nil {
		fmt.Fprintf(stderr, "okta-mcp-bridge: %s\n", err.Error())
		return 1
	}
	tokenClient := oauth.NewTokenClient(cfg, endpoints, km, st, logger, doer)
	result, err := authorizeImpl(deps)(cfg, endpoints, oauth.AuthorizeOptions{Opener: deps.Opener, Logger: logger})
	if err != nil {
		fmt.Fprintf(stderr, "okta-mcp-bridge: %s\n", err.Error())
		return 1
	}
	set, err := tokenClient.ExchangeCode(ctx, result)
	if err != nil {
		fmt.Fprintf(stderr, "okta-mcp-bridge: %s\n", err.Error())
		return 1
	}
	expiry := time.Unix(set.ExpiresAt, 0).UTC().Format(time.RFC3339)
	fmt.Fprintf(stderr, "okta-mcp-bridge: logged in (jkt=%s, expires=%s)\n", set.JKT, expiry)
	return 0
}

func logout(cfg config.Config, logger *logx.Logger, stderr io.Writer) int {
	_ = store.New(cfg.BridgeHome).Clear()
	if cfg.DpopKeyMode == "persistent" {
		_ = os.Remove(filepath.Join(cfg.BridgeHome, "dpop-key.json"))
	}
	logger.Info("auth.logout", nil)
	fmt.Fprintln(stderr, "okta-mcp-bridge: logged out (token and key cleared)")
	return 0
}

type noAuthProvider struct{}

func (noAuthProvider) GetAccessToken(context.Context, oauth.AuthorizeFn) (string, error) {
	return "", fmt.Errorf("doctor performs unauthenticated probes only")
}
func (noAuthProvider) ClearStored() error { return nil }

func doctor(ctx context.Context, cfg config.Config, deps CliDeps, logger *logx.Logger, doer oauth.Doer, stderr io.Writer) int {
	out := func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) }

	km, err := dpop.NewKeyManager(cfg, logger)
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	st := store.New(cfg.BridgeHome)

	out("okta-mcp-bridge doctor")
	out("  adapter:    %s", cfg.AdapterBaseURL)
	out("  client_id:  %s", cfg.OktaClientID)
	out("  agent_id:   %s", cfg.AgentID)
	out("  issuer:     %s", orDefault(cfg.OktaIssuer, "(adapter discovery)"))
	if cfg.OktaTokenDpopHTU != "" {
		out("  token htu:  %s (proof override)", cfg.OktaTokenDpopHTU)
	}
	out("  redirect:   http://127.0.0.1:%d/callback", cfg.OktaRedirectPort)
	if cfg.OktaRedirectPort == 0 {
		out("  WARNING:    OKTA_REDIRECT_PORT=0 (ephemeral) — Okta needs a fixed, pre-registered port; set OKTA_REDIRECT_PORT")
	}
	out("  alg:        %s", cfg.DpopAlg)
	out("  bridge_home:%s", cfg.BridgeHome)
	out("  key jkt:    %s", km.JKT())

	if set, _ := st.Load(); set != nil {
		expiry := time.Unix(set.ExpiresAt, 0).UTC().Format(time.RFC3339)
		flag := ""
		if st.IsExpired(*set, store.DefaultSkew) {
			flag = " (EXPIRED)"
		}
		out("  token:      present, expires %s%s", expiry, flag)
	} else {
		out("  token:      none (run `login`)")
	}

	endpoints, err := oauth.ResolveEndpoints(ctx, cfg, doer, logger)
	if err != nil {
		out("  endpoints:  UNRESOLVED — %s", err.Error())
		out("  adapter:    UNREACHABLE")
		return 1
	}
	out("  authorization_endpoint: %s", endpoints.AuthorizationEndpoint)
	out("  token_endpoint:         %s", endpoints.TokenEndpoint)

	up := upstream.New(cfg, km, noAuthProvider{}, logger, upstream.Deps{Doer: doer})
	resp := up.ForwardUnauthed(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if resp == nil || resp["error"] != nil {
		out("  adapter:    UNREACHABLE (initialize failed)")
		return 1
	}
	out("  adapter:    reachable")
	return 0
}

// tokenCmd prints the stored access token's binding facts: token_type, format
// (jwt/opaque), and whether cnf.jkt matches the bridge key. With --raw it prints
// the raw access token (so it can be fed to an external tool). DEMO 3 artifact.
func tokenCmd(cfg config.Config, logger *logx.Logger, stderr io.Writer, parsed Parsed) int {
	out := func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) }
	km, err := dpop.NewKeyManager(cfg, logger)
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	set, err := store.New(cfg.BridgeHome).Load()
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	if set == nil {
		out("okta-mcp-bridge: no stored token — run `login` first")
		return 1
	}
	if parsed.Flags["--raw"] == "true" {
		out("%s", set.AccessToken)
		return 0
	}

	out("okta-mcp-bridge token")
	out("  token_type: %s", orDefault(set.TokenType, "(none)"))
	out("  scope:      %s", set.Scope)
	out("  expires:    %s", time.Unix(set.ExpiresAt, 0).UTC().Format(time.RFC3339))
	out("  key jkt:    %s", km.JKT())

	claims, isJWT := oauth.DecodeClaims(set.AccessToken)
	if !isJWT {
		out("  format:     opaque (cnf.jkt not inspectable; resource server enforces binding on introspection)")
		return 0
	}
	out("  format:     jwt")
	cnf, _ := oauth.CnfJKT(set.AccessToken)
	switch {
	case cnf == "":
		out("  cnf.jkt:    (absent) — NOT DPoP-bound")
	case cnf == km.JKT():
		out("  cnf.jkt:    %s", cnf)
		out("  bound:      YES — cnf.jkt matches the bridge key exactly")
	default:
		out("  cnf.jkt:    %s", cnf)
		out("  bound:      NO — cnf.jkt does not match the bridge key")
	}
	if exp, ok := claims["exp"].(float64); ok {
		out("  token exp:  %s", time.Unix(int64(exp), 0).UTC().Format(time.RFC3339))
	}
	return 0
}

// callCmd sends ONE MCP JSON-RPC call to the adapter with caller-controlled DPoP
// headers and prints the HTTP status + response. Flags: --method (default
// tools/list), --params <json>, --no-proof (omit the DPoP proof → expect 401),
// --no-auth (omit the token), --no-init (skip the initialize handshake). DEMO 2.
func callCmd(ctx context.Context, cfg config.Config, deps CliDeps, logger *logx.Logger, doer oauth.Doer, stderr io.Writer, parsed Parsed) int {
	out := func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) }

	method := parsed.Flags["--method"]
	if method == "" && len(parsed.Args) > 0 {
		method = parsed.Args[0]
	}
	if method == "" {
		method = "tools/list"
	}
	params := parsed.Flags["--params"]
	if params == "" {
		params = "{}"
	}
	if !json.Valid([]byte(params)) {
		out("okta-mcp-bridge: --params is not valid JSON: %s", params)
		return 2
	}
	includeProof := parsed.Flags["--no-proof"] != "true"
	includeAuth := parsed.Flags["--no-auth"] != "true"

	km, err := dpop.NewKeyManager(cfg, logger)
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	st := store.New(cfg.BridgeHome)
	endpoints, err := oauth.ResolveEndpoints(ctx, cfg, doer, logger)
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	tokenClient := oauth.NewTokenClient(cfg, endpoints, km, st, logger, doer)
	up := upstream.New(cfg, km, tokenClient, logger, upstream.Deps{Doer: doer})

	// Establish an MCP session first (initialize is an unauthenticated passthrough)
	// so the target method isn't rejected for protocol reasons rather than auth.
	if parsed.Flags["--no-init"] != "true" {
		up.ForwardUnauthed(ctx, []byte(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`))
	}

	var token string
	if includeAuth {
		authFn := func() (oauth.AuthCodeResult, error) {
			return authorizeImpl(deps)(cfg, endpoints, oauth.AuthorizeOptions{Opener: deps.Opener, Logger: logger})
		}
		token, err = tokenClient.GetAccessToken(ctx, authFn)
		if err != nil {
			out("okta-mcp-bridge: could not get access token: %s", err.Error())
			return 1
		}
	}

	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params)
	res, err := up.Probe(ctx, []byte(req), upstream.ProbeOptions{
		Token: token, IncludeProof: includeProof, IncludeAgent: true,
	})
	if err != nil {
		out("okta-mcp-bridge: request failed: %s", err.Error())
		return 1
	}

	out("okta-mcp-bridge call %s  (token=%v proof=%v)", method, includeAuth, includeProof)
	out("  HTTP status: %d", res.Status)
	if res.WWWAuth != "" {
		out("  WWW-Authenticate: %s", res.WWWAuth)
	}
	if res.DPoPNonce != "" {
		out("  DPoP-Nonce: %s", res.DPoPNonce)
	}
	if res.Body != nil {
		pretty, _ := json.MarshalIndent(res.Body, "  ", "  ")
		out("  body: %s", string(pretty))
	}
	if res.Status == 401 {
		return 1
	}
	return 0
}

// nonceReplayCmd demonstrates AS nonce-replay rejection using the refresh grant.
// It (1) gets a fresh nonce, (2) spends it on a successful token request, then
// (3) deliberately reuses the SAME nonce on a second request and shows the AS
// rejects it with use_dpop_nonce + a new nonce. Requires a prior `login`. DEMO 4.
func nonceReplayCmd(ctx context.Context, cfg config.Config, deps CliDeps, logger *logx.Logger, doer oauth.Doer, stderr io.Writer) int {
	out := func(format string, a ...any) { fmt.Fprintf(stderr, format+"\n", a...) }

	km, err := dpop.NewKeyManager(cfg, logger)
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	st := store.New(cfg.BridgeHome)
	set, err := st.Load()
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	if set == nil || set.RefreshToken == "" {
		out("okta-mcp-bridge: nonce-replay needs a stored refresh_token — run `login` with offline_access first")
		return 1
	}
	endpoints, err := oauth.ResolveEndpoints(ctx, cfg, doer, logger)
	if err != nil {
		out("okta-mcp-bridge: %s", err.Error())
		return 1
	}
	tc := oauth.NewTokenClient(cfg, endpoints, km, st, logger, doer)

	out("okta-mcp-bridge nonce-replay")

	// Step 1: prime — a no-nonce request elicits the AS nonce challenge.
	p1, err := tc.ProbeTokenRequest(ctx, tc.RefreshParams(*set), "")
	if err != nil {
		out("  step 1 (get nonce): request error: %s", err.Error())
		return 1
	}
	nonce := p1.DPoPNonce
	out("  step 1: no-nonce request → HTTP %d error=%q DPoP-Nonce=%q", p1.Status, p1.Error, nonce)
	if nonce == "" {
		out("  the AS did not return a DPoP-Nonce; cannot run the replay test")
		return 1
	}

	// Step 2: spend the nonce on a successful token request.
	p2, err := tc.ProbeTokenRequest(ctx, tc.RefreshParams(*set), nonce)
	if err != nil {
		out("  step 2 (use nonce): request error: %s", err.Error())
		return 1
	}
	out("  step 2: nonce used   → HTTP %d token_type=%q access_token=%s", p2.Status, p2.TokenType, present(p2.AccessToken))
	if p2.Status < 200 || p2.Status >= 300 {
		out("  expected a 2xx after supplying the nonce; got error=%q (%s)", p2.Error, p2.Description)
		return 1
	}

	// Step 3: replay the SAME nonce — expect rejection with a fresh nonce.
	p3, err := tc.ProbeTokenRequest(ctx, tc.RefreshParams(*set), nonce)
	if err != nil {
		out("  step 3 (replay): request error: %s", err.Error())
		return 1
	}
	out("  step 3: SAME nonce   → HTTP %d error=%q new DPoP-Nonce=%q", p3.Status, p3.Error, p3.DPoPNonce)

	if p3.Error == "use_dpop_nonce" || (p3.Status >= 400 && p3.DPoPNonce != "" && p3.DPoPNonce != nonce) {
		out("  RESULT: PASS — AS rejected the replayed nonce and issued a new one")
		return 0
	}
	out("  RESULT: replay was NOT rejected (HTTP %d) — the AS may accept this nonce within a time window", p3.Status)
	return 1
}

func present(s string) string {
	if s == "" {
		return "(none)"
	}
	return fmt.Sprintf("present (len=%d)", len(s))
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
