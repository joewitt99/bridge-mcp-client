package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
)

type stubUpstream struct {
	authed   []string
	unauthed []string
}

func methodOf(req []byte) string {
	var m struct {
		Method string `json:"method"`
	}
	json.Unmarshal(req, &m)
	return m.Method
}

func (s *stubUpstream) Forward(_ context.Context, req []byte, _ oauth.AuthorizeFn) map[string]any {
	s.authed = append(s.authed, methodOf(req))
	return map[string]any{"jsonrpc": "2.0", "result": map[string]any{"authed": true}}
}

func (s *stubUpstream) ForwardUnauthed(_ context.Context, req []byte) map[string]any {
	s.unauthed = append(s.unauthed, methodOf(req))
	return map[string]any{"jsonrpc": "2.0", "result": map[string]any{"unauthed": true}}
}

func authFn() (oauth.AuthCodeResult, error) { return oauth.AuthCodeResult{}, nil }

func run(t *testing.T, lines []string) (*stubUpstream, []string, string) {
	t.Helper()
	up := &stubUpstream{}
	out := &bytes.Buffer{}
	logBuf := &bytes.Buffer{}
	err := Run(context.Background(), Deps{
		Upstream: up,
		AuthFn:   authFn,
		Input:    strings.NewReader(strings.Join(lines, "\n") + "\n"),
		Output:   out,
		Logger:   logx.NewWith(logBuf, "info"),
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	var outLines []string
	for _, l := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if l != "" {
			outLines = append(outLines, l)
		}
	}
	return up, outLines, logBuf.String()
}

func TestRoutingAndIDs(t *testing.T) {
	up, outLines, _ := run(t, []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	})
	if len(up.unauthed) != 1 || up.unauthed[0] != "initialize" {
		t.Errorf("unauthed routing = %v", up.unauthed)
	}
	if len(up.authed) != 1 || up.authed[0] != "tools/list" {
		t.Errorf("authed routing = %v", up.authed)
	}
	if len(outLines) != 2 {
		t.Fatalf("expected 2 response lines, got %d: %v", len(outLines), outLines)
	}
	var r1, r2 map[string]any
	json.Unmarshal([]byte(outLines[0]), &r1)
	json.Unmarshal([]byte(outLines[1]), &r2)
	if r1["id"] != float64(1) || r1["result"].(map[string]any)["unauthed"] != true {
		t.Errorf("response 1 = %v", r1)
	}
	if r2["id"] != float64(2) || r2["result"].(map[string]any)["authed"] != true {
		t.Errorf("response 2 = %v", r2)
	}
}

func TestNotificationNoResponse(t *testing.T) {
	up, outLines, _ := run(t, []string{`{"jsonrpc":"2.0","method":"notifications/initialized"}`})
	if len(up.unauthed) != 1 {
		t.Errorf("notification should still be forwarded: %v", up.unauthed)
	}
	if len(outLines) != 0 {
		t.Fatalf("notification (no id) must yield no response, got %v", outLines)
	}
}

func TestMalformedStaysAlive(t *testing.T) {
	up, outLines, logs := run(t, []string{
		`this is not json`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/list"}`,
	})
	if !strings.Contains(logs, "mcp.request.parse_error") {
		t.Error("expected parse_error log")
	}
	if len(up.authed) != 1 || up.authed[0] != "tools/list" {
		t.Errorf("valid request after bad line should be served: %v", up.authed)
	}
	if len(outLines) != 1 {
		t.Fatalf("expected 1 response, got %v", outLines)
	}
	var r map[string]any
	json.Unmarshal([]byte(outLines[0]), &r)
	if r["id"] != float64(5) {
		t.Errorf("id not preserved: %v", r)
	}
}

func TestStringIDFidelity(t *testing.T) {
	_, outLines, _ := run(t, []string{`{"jsonrpc":"2.0","id":"abc-123","method":"tools/list"}`})
	if len(outLines) != 1 {
		t.Fatalf("expected 1 response, got %v", outLines)
	}
	if !strings.Contains(outLines[0], `"id":"abc-123"`) {
		t.Errorf("string id not preserved: %q", outLines[0])
	}
}

func TestNoLeakToOutputAndShutdownLogged(t *testing.T) {
	_, outLines, logs := run(t, []string{`{"jsonrpc":"2.0","id":1,"method":"initialize"}`})
	for _, l := range outLines {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) != nil || m["jsonrpc"] != "2.0" {
			t.Fatalf("non-JSON-RPC content leaked to output: %q", l)
		}
	}
	if !strings.Contains(logs, "bridge.shutdown") {
		t.Error("expected bridge.shutdown on EOF")
	}
}
