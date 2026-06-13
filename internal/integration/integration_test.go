// Package integration drives the whole Go bridge end-to-end against the mock
// adapter (the contract parity gate), mirroring tests/integration.test.ts.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/joewitt99/bridge-mcp-client/internal/bridge"
	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/mockadapter"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
	"github.com/joewitt99/bridge-mcp-client/internal/store"
	"github.com/joewitt99/bridge-mcp-client/internal/upstream"
)

var bg = context.Background()

func stubAuthorize() (oauth.AuthCodeResult, error) {
	return oauth.AuthCodeResult{Code: "test-code", RedirectURI: "http://127.0.0.1:0/callback", Verifier: strings.Repeat("x", 64)}, nil
}

func build(t *testing.T, mock *mockadapter.Adapter) (config.Config, *dpop.KeyManager, *store.TokenStore, *oauth.TokenClient, *upstream.Client) {
	t.Helper()
	oauth.ClearDiscoveryCache()
	cfg, err := config.Load(map[string]string{
		"ADAPTER_BASE_URL":   mock.URL(),
		"OKTA_CLIENT_ID":     "test-client",
		"AGENT_ID":           "test-agent",
		"OKTA_REDIRECT_PORT": "0",
		"BRIDGE_HOME":        t.TempDir(),
		"LOG_LEVEL":          "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	km, err := dpop.NewKeyManager(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(cfg.BridgeHome)
	endpoints, err := oauth.ResolveEndpoints(bg, cfg, mock.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tc := oauth.NewTokenClient(cfg, endpoints, km, st, nil, mock.Client())
	up := upstream.New(cfg, km, tc, nil, upstream.Deps{Doer: mock.Client()})
	return cfg, km, st, tc, up
}

func TestInitializeAndToolsListEndToEnd(t *testing.T) {
	mock := mockadapter.New(mockadapter.Options{})
	defer mock.Close()
	_, _, st, _, up := build(t, mock)

	init := up.ForwardUnauthed(bg, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	result, _ := init["result"].(map[string]any)
	si, _ := result["serverInfo"].(map[string]any)
	if si["name"] != "mock-adapter" {
		t.Fatalf("initialize did not pass unauthed: %v", init)
	}
	if !mock.InitializeUnauthed() {
		t.Error("adapter saw auth on initialize")
	}

	list := up.Forward(bg, []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`), stubAuthorize)
	lr, _ := list["result"].(map[string]any)
	tools, _ := lr["tools"].([]any)
	if len(tools) == 0 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("tools/list end-to-end failed: %v", list)
	}
	if mock.TokenChallenges() != 1 {
		t.Errorf("expected exactly 1 /token nonce challenge, got %d", mock.TokenChallenges())
	}
	if !mock.ResourceNonceIssued() {
		t.Error("resource-side nonce recovery was not exercised")
	}
	if set, _ := st.Load(); set == nil || set.AccessToken == "" {
		t.Error("token was not persisted")
	}
}

func TestCnfJKTMismatchRejected(t *testing.T) {
	mock := mockadapter.New(mockadapter.Options{MintMismatch: true})
	defer mock.Close()
	_, _, _, tc, _ := build(t, mock)
	_, err := tc.ExchangeCode(bg, oauth.AuthCodeResult{Code: "c", RedirectURI: "http://127.0.0.1:0/cb", Verifier: strings.Repeat("x", 64)})
	if err == nil || !strings.Contains(err.Error(), "cnf.jkt") {
		t.Fatalf("expected cnf.jkt mismatch error, got %v", err)
	}
}

func TestReplayedJTIRejected(t *testing.T) {
	mock := mockadapter.New(mockadapter.Options{NoResourceNonce: true})
	defer mock.Close()
	cfg, km, _, tc, _ := build(t, mock)

	token, err := tc.GetAccessToken(bg, stubAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := km.CreateProof(dpop.ProofOptions{HTM: "POST", HTU: mock.URL() + "/", AccessToken: token}, nil)
	if err != nil {
		t.Fatal(err)
	}
	post := func() *http.Response {
		req, _ := http.NewRequest(http.MethodPost, mock.URL()+"/", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+token)
		req.Header.Set("X-MCP-Agent", cfg.AgentID)
		req.Header.Set("DPoP", proof)
		resp, err := mock.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := post()
	first.Body.Close()
	if first.StatusCode != 200 {
		t.Fatalf("first call should succeed, got %d", first.StatusCode)
	}
	second := post()
	defer second.Body.Close()
	if second.StatusCode != 401 {
		t.Fatalf("replayed jti should be rejected (401), got %d", second.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(second.Body).Decode(&body)
	if body["error"] != "replay_detected" {
		t.Fatalf("expected replay_detected, got %v", body)
	}
}

func TestStdioRoundTrip(t *testing.T) {
	mock := mockadapter.New(mockadapter.Options{})
	defer mock.Close()
	_, _, _, _, up := build(t, mock)

	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n")
	out := &bytes.Buffer{}
	if err := bridge.Run(bg, bridge.Deps{
		Upstream: up, AuthFn: stubAuthorize, Input: in, Output: out, Logger: logx.NewWith(io.Discard, "error"),
	}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 response lines, got %d: %v", len(lines), lines)
	}
	var r1, r2 map[string]any
	json.Unmarshal([]byte(lines[0]), &r1)
	json.Unmarshal([]byte(lines[1]), &r2)
	if r1["id"] != float64(1) || r1["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "mock-adapter" {
		t.Errorf("initialize response wrong: %v", r1)
	}
	if r2["id"] != float64(2) || len(r2["result"].(map[string]any)["tools"].([]any)) == 0 {
		t.Errorf("tools/list response wrong: %v", r2)
	}
}
