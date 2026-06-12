package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
	"github.com/joewitt99/bridge-mcp-client/internal/store"
)

func TestParseArgs(t *testing.T) {
	if ParseArgs(nil).Command != "serve" {
		t.Error("default should be serve")
	}
	for _, c := range []string{"login", "logout", "doctor"} {
		if ParseArgs([]string{c}).Command != c {
			t.Errorf("%s not recognized", c)
		}
	}
	for _, c := range []string{"--version", "-v"} {
		if ParseArgs([]string{c}).Command != "version" {
			t.Errorf("%s should map to version", c)
		}
	}
	for _, c := range []string{"--help", "-h"} {
		if ParseArgs([]string{c}).Command != "help" {
			t.Errorf("%s should map to help", c)
		}
	}
	p := ParseArgs([]string{"doctor", "--adapter-base-url", "https://x.example.com", "--agent-id=A2", "--alg", "ES384"})
	if p.Command != "doctor" {
		t.Errorf("command = %s", p.Command)
	}
	want := map[string]string{"ADAPTER_BASE_URL": "https://x.example.com", "AGENT_ID": "A2", "DPOP_ALG": "ES384"}
	for k, v := range want {
		if p.Overrides[k] != v {
			t.Errorf("override %s = %q, want %q", k, p.Overrides[k], v)
		}
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func reachableDoer() oauth.Doer {
	body := func(s string) *http.Response {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(s)), Header: http.Header{"Content-Type": []string{"application/json"}}}
	}
	return doerFunc(func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		switch {
		case strings.Contains(u, "oauth-protected-resource"):
			return body(`{"authorization_servers":["https://as.example.com"]}`), nil
		case strings.Contains(u, "oauth-authorization-server"):
			return body(`{"authorization_endpoint":"https://as.example.com/authorize","token_endpoint":"https://as.example.com/token"}`), nil
		default:
			return body(`{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}`), nil
		}
	})
}

var unreachableDoer = doerFunc(func(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
})

func baseEnv(home string, overrides map[string]string) map[string]string {
	env := map[string]string{
		"ADAPTER_BASE_URL": "https://adapter.example.com",
		"OKTA_CLIENT_ID":   "cid",
		"AGENT_ID":         "agent-1",
		"BRIDGE_HOME":      home,
		"LOG_LEVEL":        "error",
	}
	for k, v := range overrides {
		if v == "" {
			delete(env, k)
		} else {
			env[k] = v
		}
	}
	return env
}

func runCLI(t *testing.T, args []string, deps CliDeps) (int, string) {
	t.Helper()
	oauth.ClearDiscoveryCache()
	buf := &bytes.Buffer{}
	deps.Stderr = buf
	code := Run(context.Background(), args, deps)
	return code, buf.String()
}

func TestVersion(t *testing.T) {
	code, out := runCLI(t, []string{"--version"}, CliDeps{Env: baseEnv(t.TempDir(), nil)})
	if code != 0 || !strings.Contains(out, "okta-mcp-bridge") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

func TestDoctorReachable(t *testing.T) {
	code, out := runCLI(t, []string{"doctor"}, CliDeps{Env: baseEnv(t.TempDir(), nil), Doer: reachableDoer()})
	if code != 0 {
		t.Fatalf("expected 0, got %d (%s)", code, out)
	}
	for _, want := range []string{"token_endpoint", "as.example.com", "reachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor output missing %q: %s", want, out)
		}
	}
}

func TestDoctorUnreachable(t *testing.T) {
	code, out := runCLI(t, []string{"doctor"}, CliDeps{Env: baseEnv(t.TempDir(), nil), Doer: unreachableDoer})
	if code != 1 || !strings.Contains(out, "UNREACHABLE") {
		t.Fatalf("expected 1 + UNREACHABLE, got %d (%s)", code, out)
	}
}

func TestDoctorFlagOverride(t *testing.T) {
	env := baseEnv(t.TempDir(), map[string]string{"ADAPTER_BASE_URL": ""}) // remove from env
	code, out := runCLI(t, []string{"doctor", "--adapter-base-url", "https://adapter.example.com"},
		CliDeps{Env: env, Doer: reachableDoer()})
	if code != 0 {
		t.Fatalf("flag override should supply ADAPTER_BASE_URL: code=%d out=%s", code, out)
	}
}

func TestMissingConfig(t *testing.T) {
	code, _ := runCLI(t, []string{"doctor"}, CliDeps{Env: map[string]string{"BRIDGE_HOME": t.TempDir()}, Doer: reachableDoer()})
	if code != 2 {
		t.Fatalf("missing required config should exit 2, got %d", code)
	}
}

func TestLogoutClearsTokenAndKey(t *testing.T) {
	home := t.TempDir()
	cfg, err := config.Load(baseEnv(home, map[string]string{"DPOP_KEY_MODE": "persistent"}))
	if err != nil {
		t.Fatal(err)
	}
	km, err := dpop.NewKeyManager(cfg, nil) // writes dpop-key.json
	if err != nil {
		t.Fatal(err)
	}
	if err := store.New(home).Save(store.TokenSet{AccessToken: "tok", TokenType: "DPoP", ExpiresAt: 9_999_999_999, Scope: "openid", JKT: km.JKT()}); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "dpop-key.json")
	tokPath := filepath.Join(home, "tokens.json")
	if !exists(keyPath) || !exists(tokPath) {
		t.Fatal("setup: key/token files should exist")
	}

	code, _ := runCLI(t, []string{"logout"}, CliDeps{Env: baseEnv(home, map[string]string{"DPOP_KEY_MODE": "persistent"})})
	if code != 0 {
		t.Fatalf("logout exit = %d", code)
	}
	if exists(keyPath) || exists(tokPath) {
		t.Fatal("logout should remove tokens.json and dpop-key.json")
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
