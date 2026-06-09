// Package config loads and validates the bridge's typed configuration from a
// flat environment map (env values, with CLI --flags layered over them by the
// caller). Port of the TypeScript src/config.ts.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the validated, typed bridge configuration.
type Config struct {
	AdapterBaseURL string // required; adapter's external base URL
	OktaClientID   string // required
	AgentID        string // required; sent as X-MCP-Agent
	OktaIssuer     string // optional; if set, token/authorize taken from Okta directly
	// OktaTokenDpopHTU overrides ONLY the htu claim on the /token DPoP proof
	// (not the dialed URL) — for a BFF/proxy adapter that relays the proof to Okta.
	OktaTokenDpopHTU string
	OktaRedirectPort int           // loopback redirect port; 0 = ephemeral
	OktaScopes       string        // default "openid offline_access"
	DpopAlg          string        // ES256 (default) | ES384 | RS256
	DpopKeyMode      string        // persistent (default) | ephemeral
	BridgeHome       string        // default ~/.okta-mcp-bridge
	HTTPTimeout      time.Duration // default 30s
	LogLevel         string        // default "info"
}

var (
	validAlgs     = map[string]bool{"ES256": true, "ES384": true, "RS256": true}
	validKeyModes = map[string]bool{"persistent": true, "ephemeral": true}
)

// Load builds a Config from the given environment map, validating required vars
// and value formats. Returns a clear error listing any missing required vars.
func Load(env map[string]string) (Config, error) {
	adapter := clean(env["ADAPTER_BASE_URL"])
	clientID := clean(env["OKTA_CLIENT_ID"])
	agentID := clean(env["AGENT_ID"])

	var missing []string
	if adapter == "" {
		missing = append(missing, "ADAPTER_BASE_URL")
	}
	if clientID == "" {
		missing = append(missing, "OKTA_CLIENT_ID")
	}
	if agentID == "" {
		missing = append(missing, "AGENT_ID")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variable(s): %s", strings.Join(missing, ", "))
	}

	if err := validateHTTPURL("ADAPTER_BASE_URL", adapter); err != nil {
		return Config{}, err
	}

	tokenHTU := clean(env["OKTA_TOKEN_DPOP_HTU"])
	if tokenHTU != "" {
		if err := validateHTTPURL("OKTA_TOKEN_DPOP_HTU", tokenHTU); err != nil {
			return Config{}, err
		}
	}

	alg := orDefault(clean(env["DPOP_ALG"]), "ES256")
	if !validAlgs[alg] {
		return Config{}, fmt.Errorf("DPOP_ALG must be one of ES256/ES384/RS256; got %q", env["DPOP_ALG"])
	}

	keyMode := orDefault(clean(env["DPOP_KEY_MODE"]), "persistent")
	if !validKeyModes[keyMode] {
		return Config{}, fmt.Errorf("DPOP_KEY_MODE must be one of persistent/ephemeral; got %q", env["DPOP_KEY_MODE"])
	}

	port := 0
	if v := clean(env["OKTA_REDIRECT_PORT"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return Config{}, fmt.Errorf("OKTA_REDIRECT_PORT must be an integer in [0,65535]; got %q", v)
		}
		port = n
	}

	timeoutMs := 30000
	if v := clean(env["HTTP_TIMEOUT_MS"]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("HTTP_TIMEOUT_MS must be a positive integer; got %q", v)
		}
		timeoutMs = n
	}

	home := clean(env["BRIDGE_HOME"])
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return Config{}, fmt.Errorf("cannot resolve home directory: %w", err)
		}
		home = filepath.Join(h, ".okta-mcp-bridge")
	}

	return Config{
		AdapterBaseURL:   adapter,
		OktaClientID:     clientID,
		AgentID:          agentID,
		OktaIssuer:       clean(env["OKTA_ISSUER"]),
		OktaTokenDpopHTU: tokenHTU,
		OktaRedirectPort: port,
		OktaScopes:       orDefault(clean(env["OKTA_SCOPES"]), "openid offline_access"),
		DpopAlg:          alg,
		DpopKeyMode:      keyMode,
		BridgeHome:       home,
		HTTPTimeout:      time.Duration(timeoutMs) * time.Millisecond,
		LogLevel:         orDefault(clean(env["LOG_LEVEL"]), "info"),
	}, nil
}

// EnvMap snapshots the process environment as a flat map (for Load).
func EnvMap() map[string]string {
	m := make(map[string]string)
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func clean(v string) string { return strings.TrimSpace(v) }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func validateHTTPURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s must be an absolute http(s) URL: %q", name, raw)
	}
	return nil
}
