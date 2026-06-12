// Package bridge is the stdio MCP server: a transparent passthrough between the
// MCP client (stdin/stdout) and the adapter (via the upstream client). Go port
// of src/server.ts.
//
// stdout is sacred: writeResponse is the ONLY place in the program that writes
// to the output sink (os.Stdout in production). All logging goes to stderr.
package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
)

// Upstream is the slice of the upstream client the server needs (eases testing).
type Upstream interface {
	Forward(ctx context.Context, req []byte, authFn oauth.AuthorizeFn) map[string]any
	ForwardUnauthed(ctx context.Context, req []byte) map[string]any
}

// Deps configure Run.
type Deps struct {
	Upstream Upstream
	AuthFn   oauth.AuthorizeFn
	Input    io.Reader // newline-delimited JSON-RPC; default os.Stdin
	Output   io.Writer // response sink; default os.Stdout
	Logger   *logx.Logger
}

var alwaysUnauthed = map[string]bool{
	"initialize":                true,
	"ping":                      true,
	"notifications/initialized": true,
}

func isUnauthed(method string) bool {
	return alwaysUnauthed[method] || strings.HasPrefix(method, "notifications/")
}

// Run reads newline-delimited JSON-RPC from input, routes each message
// (initialize/ping/notifications/* unauthed, else authed), and writes each
// response as one line to output. Returns when input reaches EOF or ctx is done.
func Run(ctx context.Context, deps Deps) error {
	logger := deps.Logger
	if logger == nil {
		logger = logx.Default
	}
	var input io.Reader = os.Stdin
	if deps.Input != nil {
		input = deps.Input
	}
	var output io.Writer = os.Stdout
	if deps.Output != nil {
		output = deps.Output
	}

	writeResponse := func(msg map[string]any) {
		if msg == nil {
			return
		}
		data, err := json.Marshal(msg)
		if err != nil {
			logger.Error("mcp.response.marshal_error", logx.Fields{"error": err.Error()})
			return
		}
		// The one and only sanctioned write to the output sink.
		_, _ = output.Write(append(data, '\n'))
	}

	handleLine := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			// Don't crash on a bad message; the id isn't recoverable here.
			logger.Warn("mcp.request.parse_error", nil)
			return
		}
		hasID := len(msg.ID) > 0 && string(msg.ID) != "null"

		var response map[string]any
		if isUnauthed(msg.Method) {
			response = deps.Upstream.ForwardUnauthed(ctx, []byte(line))
		} else {
			response = deps.Upstream.Forward(ctx, []byte(line), deps.AuthFn)
		}

		// Notifications (no id) get no response; requests get exactly one.
		if !hasID {
			return
		}
		if response != nil {
			response["id"] = msg.ID // preserve the request id exactly
		}
		writeResponse(response)
	}

	// Read lines in a goroutine so ctx cancellation can stop a blocking stdin
	// read (signals are owned by main; this also unblocks a graceful ctx done).
	lines := make(chan string)
	readErr := make(chan error, 1)
	go func() {
		reader := bufio.NewReaderSize(input, 1<<20)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				readErr <- err
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Info("bridge.shutdown", logx.Fields{"reason": "context"})
			return ctx.Err()
		case line := <-lines:
			handleLine(line)
		case err := <-readErr:
			if err == io.EOF {
				logger.Info("bridge.shutdown", logx.Fields{"reason": "eof"})
				return nil
			}
			logger.Error("bridge.read_error", logx.Fields{"error": err.Error()})
			return err
		}
	}
}
