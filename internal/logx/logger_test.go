package logx

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func parseLine(t *testing.T, b *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimRight(b.String(), "\n")
	if strings.Contains(line, "\n") {
		t.Fatalf("expected a single line, got: %q", b.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not valid JSON: %q (%v)", line, err)
	}
	return m
}

func TestEmitsSingleJSONLine(t *testing.T) {
	buf := &bytes.Buffer{}
	NewWith(buf, "info").Info("test.event", Fields{"foo": "bar"})
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatal("line must end with newline")
	}
	m := parseLine(t, buf)
	if m["level"] != "info" || m["event"] != "test.event" || m["foo"] != "bar" {
		t.Fatalf("unexpected record: %v", m)
	}
	if _, ok := m["ts"].(string); !ok {
		t.Fatal("ts must be a string")
	}
}

func TestWithCorrelation(t *testing.T) {
	buf := &bytes.Buffer{}
	NewWith(buf, "info").WithCorrelation("corr-123").Info("with.corr", nil)
	if parseLine(t, buf)["correlation_id"] != "corr-123" {
		t.Fatal("correlation_id not injected")
	}
}

func TestBaseOmitsCorrelation(t *testing.T) {
	buf := &bytes.Buffer{}
	NewWith(buf, "info").Info("no.corr", nil)
	if _, ok := parseLine(t, buf)["correlation_id"]; ok {
		t.Fatal("correlation_id should be absent")
	}
}

func TestLevelGating(t *testing.T) {
	buf := &bytes.Buffer{}
	l := NewWith(buf, "warn")
	l.Info("dropped", nil)
	l.Debug("also.dropped", nil)
	if buf.Len() != 0 {
		t.Fatalf("info/debug should be gated at warn, got: %q", buf.String())
	}
	l.Warn("kept", nil)
	l.Error("kept.too", nil)
	lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	if lines != 2 {
		t.Fatalf("expected 2 kept lines, got %d: %q", lines, buf.String())
	}
}

func TestDebugVerbose(t *testing.T) {
	buf := &bytes.Buffer{}
	NewWith(buf, "debug").Debug("verbose", nil)
	if buf.Len() == 0 {
		t.Fatal("debug should emit at debug level")
	}
}

func TestRedactToken(t *testing.T) {
	tok := "super-secret-token-value"
	red := RedactToken(tok)
	if strings.Contains(red, tok) {
		t.Fatal("redaction leaked the raw token")
	}
	if !strings.Contains(red, "len=24") {
		t.Errorf("missing length: %q", red)
	}
	if !strings.Contains(red, "sha256=") {
		t.Errorf("missing sha256 prefix: %q", red)
	}
}
