package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestParseArgsDemoFlags(t *testing.T) {
	p := ParseArgs([]string{"call", "tools/list", "--no-proof", "--params", `{"a":1}`, "--method", "ping"})
	if p.Command != "call" {
		t.Fatalf("command = %s", p.Command)
	}
	if len(p.Args) != 1 || p.Args[0] != "tools/list" {
		t.Fatalf("args = %v", p.Args)
	}
	if p.Flags["--no-proof"] != "true" {
		t.Errorf("--no-proof = %q, want true", p.Flags["--no-proof"])
	}
	if p.Flags["--params"] != `{"a":1}` {
		t.Errorf("--params = %q", p.Flags["--params"])
	}
	if p.Flags["--method"] != "ping" {
		t.Errorf("--method = %q", p.Flags["--method"])
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// callDoer resolves discovery and enforces DPoP at the resource: a POST to the
// adapter without a DPoP proof header gets 401, with a proof gets 200.
func callDoer() oauth.Doer {
	json := func(code int, s string, h http.Header) *http.Response {
		if h == nil {
			h = http.Header{}
		}
		h.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(s)), Header: h}
	}
	return doerFunc(func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		switch {
		case strings.Contains(u, "oauth-protected-resource"):
			return json(200, `{"authorization_servers":["https://as.example.com"]}`, nil), nil
		case strings.Contains(u, "oauth-authorization-server"):
			return json(200, `{"authorization_endpoint":"https://as.example.com/authorize","token_endpoint":"https://as.example.com/token"}`, nil), nil
		default: // POST / to the adapter
			if r.Header.Get("DPoP") == "" {
				return json(401, `{"error":"missing_dpop_proof"}`, http.Header{"Www-Authenticate": []string{`DPoP error="use_dpop_proof"`}}), nil
			}
			return json(200, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`, nil), nil
		}
	})
}

func TestTokenNoStored(t *testing.T) {
	code, out := runCLI(t, []string{"token"}, CliDeps{Env: baseEnv(t.TempDir(), nil)})
	if code != 1 || !strings.Contains(out, "no stored token") {
		t.Fatalf("token without login: code=%d out=%s", code, out)
	}
}

func TestCallNoProofIs401(t *testing.T) {
	code, out := runCLI(t, []string{"call", "tools/list", "--no-auth", "--no-proof"},
		CliDeps{Env: baseEnv(t.TempDir(), nil), Doer: callDoer()})
	if code != 1 || !strings.Contains(out, "HTTP 401") {
		t.Fatalf("no-proof should be 401: code=%d out=%s", code, out)
	}
}

func TestCallWithProofIs200(t *testing.T) {
	code, out := runCLI(t, []string{"call", "tools/list", "--no-auth"},
		CliDeps{Env: baseEnv(t.TempDir(), nil), Doer: callDoer()})
	if code != 0 || !strings.Contains(out, "HTTP 200") {
		t.Fatalf("with-proof should be 200: code=%d out=%s", code, out)
	}
	// the wire dump should decode and show the DPoP proof
	if !strings.Contains(out, "DPoP proof (decoded)") || !strings.Contains(out, "htm=POST") {
		t.Errorf("expected decoded DPoP proof in wire output: %s", out)
	}
}

func proofNonce(proof string) string {
	parts := strings.Split(proof, ".")
	if len(parts) < 2 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	n, _ := m["nonce"].(string)
	return n
}

// replayDoer models an AS that requires a nonce and enforces single-use jti:
// a no-nonce proof gets use_dpop_nonce; a nonce'd proof succeeds once; the same
// proof replayed gets invalid_dpop_proof.
func replayDoer() oauth.Doer {
	seen := map[string]bool{}
	resp := func(code int, s string, h http.Header) *http.Response {
		if h == nil {
			h = http.Header{}
		}
		h.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(s)), Header: h}
	}
	return doerFunc(func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		switch {
		case strings.Contains(u, "oauth-protected-resource"):
			return resp(200, `{"authorization_servers":["https://as.example.com"]}`, nil), nil
		case strings.Contains(u, "oauth-authorization-server"):
			return resp(200, `{"authorization_endpoint":"https://as.example.com/authorize","token_endpoint":"https://as.example.com/token"}`, nil), nil
		default: // token endpoint
			proof := r.Header.Get("DPoP")
			if proofNonce(proof) == "" {
				return resp(400, `{"error":"use_dpop_nonce"}`, http.Header{"Dpop-Nonce": []string{"n1"}}), nil
			}
			if seen[proof] {
				return resp(400, `{"error":"invalid_dpop_proof","error_description":"jti replay"}`, nil), nil
			}
			seen[proof] = true
			return resp(200, `{"access_token":"AAAAAAAA_MIDDLE_SECRET_BBBB","refresh_token":"rt2","token_type":"DPoP","expires_in":3600,"scope":"openid offline_access"}`, nil), nil
		}
	})
}

func TestNonceReplayProofRejected(t *testing.T) {
	home := t.TempDir()
	if err := store.New(home).Save(store.TokenSet{
		AccessToken: "at", RefreshToken: "rt1", TokenType: "DPoP",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Scope: "openid offline_access",
	}); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, []string{"nonce-replay", "--replay-proof"},
		CliDeps{Env: baseEnv(home, nil), Doer: replayDoer()})
	if code != 0 || !strings.Contains(out, "PASS") {
		t.Fatalf("expected PASS, code=%d out=%s", code, out)
	}
	if !strings.Contains(out, "invalid_dpop_proof") {
		t.Errorf("expected invalid_dpop_proof in output: %s", out)
	}
	// the access_token in the /token response body must be redacted by default
	if strings.Contains(out, "MIDDLE_SECRET") {
		t.Errorf("access_token leaked in wire output: %s", out)
	}
}

func TestNonceReplayShowSecrets(t *testing.T) {
	home := t.TempDir()
	if err := store.New(home).Save(store.TokenSet{
		AccessToken: "at", RefreshToken: "rt1", TokenType: "DPoP",
		ExpiresAt: time.Now().Add(time.Hour).Unix(), Scope: "openid offline_access",
	}); err != nil {
		t.Fatal(err)
	}
	_, out := runCLI(t, []string{"nonce-replay", "--replay-proof", "--show-secrets"},
		CliDeps{Env: baseEnv(home, nil), Doer: replayDoer()})
	if !strings.Contains(out, "MIDDLE_SECRET") {
		t.Errorf("--show-secrets should print the raw access_token: %s", out)
	}
}

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
