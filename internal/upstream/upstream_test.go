package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
)

const adapter = "https://adapter.example.com"

var reqBytes = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)

func authFn() (oauth.AuthCodeResult, error) { return oauth.AuthCodeResult{}, nil }

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

type recCall struct {
	headers http.Header
	body    []byte
}

func mockDoer(t *testing.T, resps ...*http.Response) (oauth.Doer, *[]recCall) {
	t.Helper()
	calls := &[]recCall{}
	i := 0
	d := doerFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		*calls = append(*calls, recCall{headers: r.Header.Clone(), body: b})
		if i >= len(resps) {
			t.Fatalf("unexpected upstream request #%d", i+1)
		}
		resp := resps[i]
		i++
		return resp, nil
	})
	return d, calls
}

func resp(status int, body any, headers map[string]string) *http.Response {
	var bb []byte
	if s, ok := body.(string); ok {
		bb = []byte(s)
	} else {
		bb, _ = json.Marshal(body)
	}
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(bb)), Header: h}
}

func tcfg(t *testing.T, overrides map[string]string) (config.Config, *dpop.KeyManager) {
	t.Helper()
	env := map[string]string{
		"ADAPTER_BASE_URL": adapter,
		"OKTA_CLIENT_ID":   "cid",
		"AGENT_ID":         "agent-1",
		"BRIDGE_HOME":      t.TempDir(),
		"LOG_LEVEL":        "error",
	}
	for k, v := range overrides {
		env[k] = v
	}
	cfg, err := config.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	km, err := dpop.NewKeyManager(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, km
}

type stubTokens struct {
	toks    []string
	i       int
	cleared int
}

func (s *stubTokens) GetAccessToken(_ context.Context, _ oauth.AuthorizeFn) (string, error) {
	tok := s.toks[min(s.i, len(s.toks)-1)]
	s.i++
	return tok, nil
}
func (s *stubTokens) ClearStored() error { s.cleared++; return nil }

func proofOf(t *testing.T, c recCall) map[string]any {
	t.Helper()
	parts := strings.Split(c.headers.Get("DPoP"), ".")
	if len(parts) != 3 {
		t.Fatalf("bad DPoP header")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func norm(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	json.Unmarshal(b, &out)
	return out
}

func TestForwardAuthHeaders(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t, resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, nil))
	c := New(cfg, km, &stubTokens{toks: []string{"tok-abc"}}, nil, Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn)
	h := (*calls)[0].headers
	if h.Get("Authorization") != "DPoP tok-abc" || h.Get("X-MCP-Agent") != "agent-1" || h.Get("DPoP") == "" {
		t.Fatalf("bad auth headers: %v", h)
	}
}

func TestForwardProofHtmHtuAth(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t, resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, nil))
	c := New(cfg, km, &stubTokens{toks: []string{"tok-xyz"}}, nil, Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn)
	pl := proofOf(t, (*calls)[0])
	wantHTU, _ := dpop.CanonicalHTU(adapter + "/")
	sum := sha256.Sum256([]byte("tok-xyz"))
	wantAth := base64.RawURLEncoding.EncodeToString(sum[:])
	if pl["htm"] != "POST" || pl["htu"] != wantHTU || pl["ath"] != wantAth {
		t.Fatalf("proof = %v; want htm POST htu %s ath %s", pl, wantHTU, wantAth)
	}
}

func TestForwardUnauthedNoAuthHeaders(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t, resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, nil))
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, nil, Deps{Doer: doer})
	c.ForwardUnauthed(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	h := (*calls)[0].headers
	if h.Get("Authorization") != "" || h.Get("DPoP") != "" || h.Get("X-MCP-Agent") != "" {
		t.Fatalf("unauthed request leaked auth headers: %v", h)
	}
}

func TestSessionCaptureAndReuse(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t,
		resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, map[string]string{"Mcp-Session-Id": "sess-9"}),
		resp(200, map[string]any{"jsonrpc": "2.0", "id": 2, "result": map[string]any{}}, nil),
	)
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, nil, Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn)
	c.Forward(context.Background(), reqBytes, authFn)
	if (*calls)[0].headers.Get("Mcp-Session-Id") != "" {
		t.Error("first request should not carry a session id")
	}
	if (*calls)[1].headers.Get("Mcp-Session-Id") != "sess-9" {
		t.Error("second request should reuse the captured session id")
	}
}

func TestSSEParsed(t *testing.T) {
	cfg, km := tcfg(t, nil)
	sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[\"a\"]}}\n\n"
	doer, _ := mockDoer(t, resp(200, sse, map[string]string{"Content-Type": "text/event-stream"}))
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, nil, Deps{Doer: doer})
	out := norm(c.Forward(context.Background(), reqBytes, authFn))
	result := out["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 || tools[0] != "a" {
		t.Fatalf("SSE body not parsed: %v", out)
	}
}

func TestNonceRetry(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t,
		resp(401, map[string]any{"error": "use_dpop_nonce"}, map[string]string{
			"WWW-Authenticate": `DPoP error="use_dpop_nonce"`, "DPoP-Nonce": "rs-nonce-1",
		}),
		resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, nil),
	)
	tokens := &stubTokens{toks: []string{"tok-1"}}
	c := New(cfg, km, tokens, nil, Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn)
	if len(*calls) != 2 || tokens.cleared != 0 {
		t.Fatalf("calls=%d cleared=%d", len(*calls), tokens.cleared)
	}
	if _, ok := proofOf(t, (*calls)[0])["nonce"]; ok {
		t.Error("first proof should have no nonce")
	}
	if proofOf(t, (*calls)[1])["nonce"] != "rs-nonce-1" {
		t.Error("retry proof should carry the resource nonce")
	}
}

func TestStaleTokenRetry(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t,
		resp(401, map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32000, "message": "unauthorized"}}, nil),
		resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, nil),
	)
	tokens := &stubTokens{toks: []string{"tok-old", "tok-new"}}
	c := New(cfg, km, tokens, nil, Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn)
	if len(*calls) != 2 || tokens.cleared != 1 {
		t.Fatalf("calls=%d cleared=%d", len(*calls), tokens.cleared)
	}
	if (*calls)[0].headers.Get("Authorization") != "DPoP tok-old" || (*calls)[1].headers.Get("Authorization") != "DPoP tok-new" {
		t.Fatal("token not re-acquired on retry")
	}
}

func TestPersistent401(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, _ := mockDoer(t,
		resp(401, map[string]any{"error": "denied"}, nil),
		resp(401, map[string]any{"error": "denied"}, nil),
	)
	c := New(cfg, km, &stubTokens{toks: []string{"t1", "t2"}}, nil, Deps{Doer: doer})
	out := norm(c.Forward(context.Background(), reqBytes, authFn))
	if out["error"].(map[string]any)["code"] != float64(-32001) || out["id"] != float64(1) {
		t.Fatalf("expected -32001 with id 1, got %v", out)
	}
}

func TestTimeout(t *testing.T) {
	cfg, km := tcfg(t, map[string]string{"HTTP_TIMEOUT_MS": "20"})
	hanging := doerFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, nil, Deps{Doer: hanging})
	out := norm(c.Forward(context.Background(), reqBytes, authFn))
	if out["error"].(map[string]any)["code"] != float64(-32000) {
		t.Fatalf("expected -32000 on timeout, got %v", out)
	}
}

func TestForwardUnauthedNetworkError(t *testing.T) {
	cfg, km := tcfg(t, nil)
	failing := doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, nil, Deps{Doer: failing})
	out := norm(c.ForwardUnauthed(context.Background(), []byte(`{"jsonrpc":"2.0","id":7,"method":"initialize"}`)))
	if out["error"].(map[string]any)["code"] != float64(-32000) || out["id"] != float64(7) {
		t.Fatalf("expected -32000 with id 7, got %v", out)
	}
}

func Test404SessionRecovery(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, calls := mockDoer(t,
		resp(200, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}}, map[string]string{"Mcp-Session-Id": "sess-1"}),
		resp(404, map[string]any{"error": "session not found"}, nil),
		resp(200, map[string]any{"jsonrpc": "2.0", "id": 2, "result": map[string]any{"ok": true}}, nil),
	)
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, nil, Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn) // establishes session
	out := norm(c.Forward(context.Background(), reqBytes, authFn))

	if len(*calls) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(*calls))
	}
	if (*calls)[1].headers.Get("Mcp-Session-Id") != "sess-1" {
		t.Error("404 request should have carried the stale session")
	}
	if (*calls)[2].headers.Get("Mcp-Session-Id") != "" {
		t.Error("retry after 404 should drop the cleared session")
	}
	if out["result"].(map[string]any)["ok"] != true {
		t.Fatalf("expected recovered result, got %v", out)
	}
}

func TestPageInfoUnit(t *testing.T) {
	if p := pageInfo("tools/list", map[string]any{"result": map[string]any{
		"tools": []any{1, 2, 3}, "nextCursor": "p2"}}); p == nil || !p.hasNextCursor || p.itemCount != 3 {
		t.Fatalf("tools/list with cursor: %+v", p)
	}
	if p := pageInfo("resources/list", map[string]any{"result": map[string]any{"resources": []any{1}}}); p == nil || p.hasNextCursor || p.itemCount != 1 {
		t.Fatalf("resources/list no cursor: %+v", p)
	}
	if p := pageInfo("tools/call", map[string]any{"result": map[string]any{}}); p != nil {
		t.Fatalf("non-list should be nil: %+v", p)
	}
}

func TestPaginationDiagnosticLog(t *testing.T) {
	cfg, km := tcfg(t, nil)
	doer, _ := mockDoer(t, resp(200, map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"tools": []any{map[string]any{"name": "a"}, map[string]any{"name": "b"}}, "nextCursor": "next-25"},
	}, nil))
	buf := &bytes.Buffer{}
	c := New(cfg, km, &stubTokens{toks: []string{"t"}}, logx.NewWith(buf, "debug"), Deps{Doer: doer})
	c.Forward(context.Background(), reqBytes, authFn)
	s := buf.String()
	if !strings.Contains(s, `"event":"mcp.response.page"`) || !strings.Contains(s, `"has_next_cursor":true`) || !strings.Contains(s, `"item_count":2`) {
		t.Fatalf("missing/incorrect pagination diagnostic: %q", s)
	}
}
