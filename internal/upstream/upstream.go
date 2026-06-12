package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/oauth"
)

// TokenProvider is the slice of the token client the upstream needs (eases tests).
type TokenProvider interface {
	GetAccessToken(ctx context.Context, authFn oauth.AuthorizeFn) (string, error)
	ClearStored() error
}

// Deps are optional injectables.
type Deps struct {
	Doer    oauth.Doer
	Retries int                 // transient retries inside send (default 2)
	BaseMs  int                 // backoff base (default 200)
	Sleep   func(time.Duration) // injectable backoff sleep
}

// Client forwards JSON-RPC to the adapter's POST / with DPoP-bound auth.
type Client struct {
	cfg           config.Config
	km            *dpop.KeyManager
	tokens        TokenProvider
	logger        *logx.Logger
	doer          oauth.Doer
	base          string
	retries       int
	baseMs        int
	sleep         func(time.Duration)
	mcpSessionID  string
	upstreamNonce string
}

// New builds an upstream client.
func New(cfg config.Config, km *dpop.KeyManager, tokens TokenProvider, logger *logx.Logger, deps Deps) *Client {
	if logger == nil {
		logger = logx.Default
	}
	doer := deps.Doer
	if doer == nil {
		doer = &http.Client{Timeout: cfg.HTTPTimeout}
	}
	retries := deps.Retries
	if retries <= 0 {
		retries = 2
	}
	baseMs := deps.BaseMs
	if baseMs <= 0 {
		baseMs = 200
	}
	return &Client{
		cfg: cfg, km: km, tokens: tokens, logger: logger, doer: doer,
		base:    strings.TrimRight(cfg.AdapterBaseURL, "/"),
		retries: retries, baseMs: baseMs, sleep: deps.Sleep,
	}
}

type sendResult struct {
	status  int
	headers http.Header
	body    map[string]any
}

// Forward proxies an authed JSON-RPC message with single-retry recovery. It
// never returns an error: failures become JSON-RPC error objects.
func (c *Client) Forward(ctx context.Context, req []byte, authFn oauth.AuthorizeFn) map[string]any {
	token, err := c.tokens.GetAccessToken(ctx, authFn)
	if err != nil {
		return c.fail(req, err)
	}
	resp, err := c.send(ctx, req, true, token)
	if err != nil {
		return c.fail(req, err)
	}

	// 404 → a stale Mcp-Session-Id; clear it and retry once.
	if resp.status == http.StatusNotFound && c.mcpSessionID != "" {
		c.logger.Warn("mcp.session.not_found", logx.Fields{"clearing": true})
		c.mcpSessionID = ""
		if resp, err = c.send(ctx, req, true, token); err != nil {
			return c.fail(req, err)
		}
	}

	if resp.status == http.StatusUnauthorized {
		if isUseDpopNonce(resp) {
			if n := resp.headers.Get("DPoP-Nonce"); n != "" {
				c.upstreamNonce = n
			}
			c.logger.Info("oauth.nonce.challenge", logx.Fields{"side": "resource"})
			resp, err = c.send(ctx, req, true, token)
		} else {
			_ = c.tokens.ClearStored()
			fresh, ferr := c.tokens.GetAccessToken(ctx, authFn)
			if ferr != nil {
				return c.fail(req, ferr)
			}
			resp, err = c.send(ctx, req, true, fresh)
		}
		if err != nil {
			return c.fail(req, err)
		}
	}

	if resp.status == http.StatusUnauthorized {
		c.logger.Warn("mcp.request.upstream_unauthorized", logx.Fields{"method": methodOf(req)})
		return rpcError(req, -32001, "upstream authorization failed")
	}
	return resp.body
}

// ForwardUnauthed proxies initialize/ping/notifications without auth.
func (c *Client) ForwardUnauthed(ctx context.Context, req []byte) map[string]any {
	resp, err := c.send(ctx, req, false, "")
	if err != nil {
		return c.fail(req, err)
	}
	if resp.status == http.StatusNotFound && c.mcpSessionID != "" {
		c.logger.Warn("mcp.session.not_found", logx.Fields{"clearing": true})
		c.mcpSessionID = ""
		if resp, err = c.send(ctx, req, false, ""); err != nil {
			return c.fail(req, err)
		}
	}
	return resp.body
}

func (c *Client) fail(req []byte, err error) map[string]any {
	c.logger.Error("mcp.request.upstream_error", logx.Fields{"error": err.Error()})
	return rpcError(req, -32000, "upstream request failed")
}

func (c *Client) authHeaders(token string) (map[string]string, error) {
	proof, err := c.km.CreateProof(dpop.ProofOptions{
		HTM: "POST", HTU: c.base + "/", AccessToken: token, Nonce: c.upstreamNonce,
	}, c.logger)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"Authorization": "DPoP " + token,
		"X-MCP-Agent":   c.cfg.AgentID,
		"DPoP":          proof,
	}, nil
}

func (c *Client) send(ctx context.Context, req []byte, authed bool, token string) (sendResult, error) {
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}
	if c.mcpSessionID != "" {
		headers["Mcp-Session-Id"] = c.mcpSessionID
	}
	if authed && token != "" {
		ah, err := c.authHeaders(token)
		if err != nil {
			return sendResult{}, err
		}
		for k, v := range ah {
			headers[k] = v
		}
	}

	c.logger.Info("mcp.request.forwarded", logx.Fields{
		"method": methodOf(req), "authed": authed, "has_session": c.mcpSessionID != "",
	})

	ctx2, cancel := context.WithTimeout(ctx, c.cfg.HTTPTimeout)
	defer cancel()
	res, err := WithBackoff(func() (*http.Response, error) {
		r, err := http.NewRequestWithContext(ctx2, http.MethodPost, c.base+"/", bytes.NewReader(req))
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return c.doer.Do(r)
	}, c.retries, c.baseMs, c.sleep)
	if err != nil {
		return sendResult{}, err
	}
	defer res.Body.Close()

	if sid := res.Header.Get("Mcp-Session-Id"); sid != "" && sid != c.mcpSessionID {
		c.mcpSessionID = sid
		c.logger.Info("mcp.session.established", logx.Fields{"has_session": true})
	}

	body := parseBody(res)
	if page := pageInfo(methodOf(req), body); page != nil {
		c.logger.Debug("mcp.response.page", logx.Fields{
			"method":          methodOf(req),
			"http_status":     res.StatusCode,
			"content_type":    res.Header.Get("Content-Type"),
			"has_next_cursor": page.hasNextCursor,
			"item_count":      page.itemCount,
		})
	}
	return sendResult{status: res.StatusCode, headers: res.Header, body: body}, nil
}

func isUseDpopNonce(r sendResult) bool {
	if strings.Contains(r.headers.Get("WWW-Authenticate"), "use_dpop_nonce") {
		return true
	}
	e, _ := r.body["error"].(string)
	return e == "use_dpop_nonce"
}

// parseBody decodes the response: the LAST `data:` line for SSE, else JSON.
func parseBody(res *http.Response) map[string]any {
	raw, _ := io.ReadAll(res.Body)
	if len(raw) == 0 {
		return nil
	}
	if strings.Contains(res.Header.Get("Content-Type"), "text/event-stream") {
		var last string
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimRight(line, "\r")
			if strings.HasPrefix(line, "data:") {
				last = strings.TrimSpace(line[len("data:"):])
			}
		}
		return unmarshalObject([]byte(last))
	}
	return unmarshalObject(raw)
}

func unmarshalObject(b []byte) map[string]any {
	if len(b) == 0 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	return m
}

type pageSummary struct {
	hasNextCursor bool
	itemCount     int
}

// pageInfo summarizes the pagination shape of a list response (debug only).
func pageInfo(method string, body map[string]any) *pageSummary {
	if !strings.HasSuffix(method, "/list") {
		return nil
	}
	result, _ := body["result"].(map[string]any)
	if result == nil {
		return &pageSummary{}
	}
	hasNext := false
	if nc, ok := result["nextCursor"].(string); ok && nc != "" {
		hasNext = true
	}
	count := 0
	for _, key := range []string{"tools", "resources", "prompts", "resourceTemplates"} {
		if arr, ok := result[key].([]any); ok {
			count = len(arr)
			break
		}
	}
	return &pageSummary{hasNextCursor: hasNext, itemCount: count}
}

func methodOf(req []byte) string {
	var m struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(req, &m)
	return m.Method
}

// idOf returns the request's id as raw JSON (preserving number/string fidelity),
// or nil for notifications.
func idOf(req []byte) any {
	var m struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(req, &m) == nil && len(m.ID) > 0 && string(m.ID) != "null" {
		return m.ID
	}
	return nil
}

func rpcError(req []byte, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      idOf(req),
		"error":   map[string]any{"code": code, "message": message},
	}
}
