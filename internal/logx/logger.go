// Package logx is the bridge's structured logger. It writes one JSON object per
// event to a sink that defaults to os.Stderr.
//
// stdout is reserved for the MCP JSON-RPC stream; this logger must never write
// there. Never pass raw token or private-key material — use the redaction
// helpers. Port of the TypeScript src/logger.ts.
package logx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"
)

type level int

const (
	levelDebug level = 10
	levelInfo  level = 20
	levelWarn  level = 30
	levelError level = 40
)

func parseLevel(s string) level {
	switch s {
	case "debug":
		return levelDebug
	case "warn":
		return levelWarn
	case "error":
		return levelError
	default:
		return levelInfo
	}
}

// Logger emits structured JSON lines to its sink, gated by a level threshold.
type Logger struct {
	mu            *sync.Mutex
	w             io.Writer
	threshold     level
	correlationID string
}

// New returns a logger writing to os.Stderr, gated at the given level name
// ("debug"/"info"/"warn"/"error"; unknown → "info").
func New(levelName string) *Logger { return NewWith(os.Stderr, levelName) }

// NewWith returns a logger writing to w (used by tests to capture output).
func NewWith(w io.Writer, levelName string) *Logger {
	return &Logger{mu: &sync.Mutex{}, w: w, threshold: parseLevel(levelName)}
}

// Default gates on the LOG_LEVEL env var; used before config is loaded.
var Default = New(os.Getenv("LOG_LEVEL"))

// WithCorrelation returns a child logger that injects correlation_id.
func (l *Logger) WithCorrelation(id string) *Logger {
	c := *l
	c.correlationID = id
	return &c
}

// Fields is a convenience alias for a log record's extra fields.
type Fields = map[string]any

func (l *Logger) Debug(event string, fields Fields) { l.emit(levelDebug, "debug", event, fields) }
func (l *Logger) Info(event string, fields Fields)  { l.emit(levelInfo, "info", event, fields) }
func (l *Logger) Warn(event string, fields Fields)  { l.emit(levelWarn, "warn", event, fields) }
func (l *Logger) Error(event string, fields Fields) { l.emit(levelError, "error", event, fields) }

func (l *Logger) emit(lvl level, levelName, event string, fields Fields) {
	if lvl < l.threshold {
		return
	}
	buf := &bytes.Buffer{}
	buf.WriteByte('{')
	writeField(buf, "ts", time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), true)
	writeField(buf, "level", levelName, false)
	writeField(buf, "event", event, false)
	if l.correlationID != "" {
		writeField(buf, "correlation_id", l.correlationID, false)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		writeField(buf, k, fields[k], false)
	}
	buf.WriteString("}\n")
	l.mu.Lock()
	_, _ = l.w.Write(buf.Bytes())
	l.mu.Unlock()
}

func writeField(buf *bytes.Buffer, key string, val any, first bool) {
	if !first {
		buf.WriteByte(',')
	}
	kb, _ := json.Marshal(key)
	buf.Write(kb)
	buf.WriteByte(':')
	vb, err := json.Marshal(val)
	if err != nil {
		vb, _ = json.Marshal(fmt.Sprintf("%v", val))
	}
	buf.Write(vb)
}

// RedactToken renders a token for logging without exposing it: its length and
// the first 12 hex chars of its SHA-256. Never returns the raw token.
func RedactToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("len=%d sha256=%s", len(token), hex.EncodeToString(sum[:])[:12])
}
