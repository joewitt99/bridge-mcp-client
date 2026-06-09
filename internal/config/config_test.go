package config

import (
	"strings"
	"testing"
	"time"
)

func base() map[string]string {
	return map[string]string{
		"ADAPTER_BASE_URL": "https://adapter.example.com",
		"OKTA_CLIENT_ID":   "client123",
		"AGENT_ID":         "agent123",
	}
}

func with(overrides map[string]string) map[string]string {
	m := base()
	for k, v := range overrides {
		m[k] = v
	}
	return m
}

func TestMissingAdapterBaseURL(t *testing.T) {
	_, err := Load(map[string]string{"OKTA_CLIENT_ID": "c", "AGENT_ID": "a"})
	if err == nil || !strings.Contains(err.Error(), "ADAPTER_BASE_URL") {
		t.Fatalf("expected ADAPTER_BASE_URL error, got %v", err)
	}
}

func TestMissingListsAll(t *testing.T) {
	_, err := Load(map[string]string{})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"ADAPTER_BASE_URL", "OKTA_CLIENT_ID", "AGENT_ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing-vars error should mention %s; got %q", want, err.Error())
		}
	}
}

func TestBadAdapterURL(t *testing.T) {
	if _, err := Load(with(map[string]string{"ADAPTER_BASE_URL": "ftp://nope"})); err == nil {
		t.Fatal("expected error for ftp scheme")
	}
	if _, err := Load(with(map[string]string{"ADAPTER_BASE_URL": "not a url"})); err == nil {
		t.Fatal("expected error for non-URL")
	}
}

func TestBadTokenDpopHTU(t *testing.T) {
	if _, err := Load(with(map[string]string{"OKTA_TOKEN_DPOP_HTU": "ftp://nope"})); err == nil {
		t.Fatal("expected error for bad OKTA_TOKEN_DPOP_HTU")
	} else if !strings.Contains(err.Error(), "OKTA_TOKEN_DPOP_HTU") {
		t.Errorf("error should mention OKTA_TOKEN_DPOP_HTU; got %q", err.Error())
	}
}

func TestAcceptsTokenDpopHTU(t *testing.T) {
	cfg, err := Load(with(map[string]string{"OKTA_TOKEN_DPOP_HTU": "https://org.okta.com/oauth2/v1/token"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OktaTokenDpopHTU != "https://org.okta.com/oauth2/v1/token" {
		t.Errorf("got %q", cfg.OktaTokenDpopHTU)
	}
}

func TestBadAlgAndKeyMode(t *testing.T) {
	if _, err := Load(with(map[string]string{"DPOP_ALG": "HS256"})); err == nil {
		t.Error("expected DPOP_ALG error")
	}
	if _, err := Load(with(map[string]string{"DPOP_KEY_MODE": "weird"})); err == nil {
		t.Error("expected DPOP_KEY_MODE error")
	}
}

func TestBadPortAndTimeout(t *testing.T) {
	if _, err := Load(with(map[string]string{"OKTA_REDIRECT_PORT": "70000"})); err == nil {
		t.Error("expected port range error")
	}
	if _, err := Load(with(map[string]string{"HTTP_TIMEOUT_MS": "0"})); err == nil {
		t.Error("expected timeout error")
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(base())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DpopAlg != "ES256" || cfg.DpopKeyMode != "persistent" {
		t.Errorf("alg/keymode defaults: %q %q", cfg.DpopAlg, cfg.DpopKeyMode)
	}
	if cfg.OktaScopes != "openid offline_access" {
		t.Errorf("scopes default: %q", cfg.OktaScopes)
	}
	if cfg.OktaRedirectPort != 0 {
		t.Errorf("port default: %d", cfg.OktaRedirectPort)
	}
	if cfg.HTTPTimeout != 30*time.Second {
		t.Errorf("timeout default: %v", cfg.HTTPTimeout)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log level default: %q", cfg.LogLevel)
	}
	if cfg.OktaIssuer != "" || cfg.OktaTokenDpopHTU != "" {
		t.Errorf("optional fields should be empty by default")
	}
	if !strings.Contains(cfg.BridgeHome, ".okta-mcp-bridge") {
		t.Errorf("bridge home default: %q", cfg.BridgeHome)
	}
}

func TestOverrides(t *testing.T) {
	cfg, err := Load(with(map[string]string{
		"OKTA_ISSUER":        "https://dev-1.okta.com",
		"DPOP_ALG":           "ES384",
		"DPOP_KEY_MODE":      "ephemeral",
		"OKTA_SCOPES":        "openid",
		"OKTA_REDIRECT_PORT": "8765",
		"HTTP_TIMEOUT_MS":    "5000",
		"BRIDGE_HOME":        "/tmp/custom-home",
		"LOG_LEVEL":          "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OktaIssuer != "https://dev-1.okta.com" || cfg.DpopAlg != "ES384" ||
		cfg.DpopKeyMode != "ephemeral" || cfg.OktaScopes != "openid" ||
		cfg.OktaRedirectPort != 8765 || cfg.HTTPTimeout != 5*time.Second ||
		cfg.BridgeHome != "/tmp/custom-home" || cfg.LogLevel != "debug" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}
