// Package cli is the command dispatcher: serve (default), login, logout, doctor,
// --version, --help. Go port of src/cli.ts. All human output goes to stderr
// (stdout is the MCP JSON-RPC stream in serve mode). Run returns an exit code.
package cli

import (
	"context"
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
	Command   string // serve | login | logout | doctor | version | help
	Overrides map[string]string
}

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

var subcommands = map[string]bool{"serve": true, "login": true, "logout": true, "doctor": true}

const usage = `okta-mcp-bridge

Usage: okta-mcp-bridge [command] [flags]

Commands:
  serve     (default) Run the stdio MCP bridge. This is what Claude Code launches.
  login     Authenticate against Okta (browser) and store a DPoP-bound token.
  logout    Clear the stored token (and the DPoP key in persistent mode).
  doctor    Print a diagnostics report and probe the adapter for reachability.

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
			}
		default:
			if !commandSet && subcommands[arg] {
				command, commandSet = arg, true
			}
		}
	}
	return Parsed{Command: command, Overrides: overrides}
}

// CliDeps are optional injectables (tests).
type CliDeps struct {
	Env       map[string]string
	Doer      oauth.Doer
	Authorize func(config.Config, oauth.Endpoints, oauth.AuthorizeOptions) (oauth.AuthCodeResult, error)
	Opener    oauth.Opener
	Logger    *logx.Logger
	Stderr    io.Writer // human output sink (default os.Stderr)
	Input     io.Reader // serve stdin (default os.Stdin)
	Output    io.Writer // serve stdout (default os.Stdout)
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

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
