package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/store"
)

// AuthorizeFn yields an authorization code (the injected P03 authorize step).
type AuthorizeFn func() (AuthCodeResult, error)

// TokenClient performs Okta's DPoP token flow (nonce handshake, exchange,
// refresh) and exposes GetAccessToken — the "login once, call many" entry point.
type TokenClient struct {
	cfg      config.Config
	ep       Endpoints
	km       *dpop.KeyManager
	store    *store.TokenStore
	doer     Doer
	logger   *logx.Logger
	tokenHTU string // htu claim for the /token proof (may differ from the dialed URL)
	nonce    string
	now      func() time.Time
}

// NewTokenClient builds a token client. The /token proof's htu defaults to the
// dialed token endpoint, overridden by OKTA_TOKEN_DPOP_HTU (BFF/proxy case).
func NewTokenClient(cfg config.Config, ep Endpoints, km *dpop.KeyManager, st *store.TokenStore, logger *logx.Logger, doer Doer) *TokenClient {
	if logger == nil {
		logger = logx.Default
	}
	htu := cfg.OktaTokenDpopHTU
	if htu == "" {
		htu = ep.TokenEndpoint
	}
	return &TokenClient{cfg: cfg, ep: ep, km: km, store: st, doer: doer, logger: logger, tokenHTU: htu, now: time.Now}
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type tokenHTTPResult struct {
	status    int
	body      tokenResponse
	raw       string
	dpopNonce string
	wwwAuth   string
	wire      Wire
}

// Wire is a captured request/response pair for the demo commands' --wire output.
type Wire struct {
	Method      string
	URL         string
	ReqHeaders  http.Header
	ReqBody     string
	Status      int
	RespHeaders http.Header
	RespBody    string
}

// ClearStored drops the persisted token, forcing the next GetAccessToken to
// re-acquire. Used by the upstream's 401 recovery.
func (c *TokenClient) ClearStored() error { return c.store.Clear() }

func (c *TokenClient) tokenRequest(ctx context.Context, params url.Values, nonce string) (tokenHTTPResult, error) {
	proof, err := c.NewTokenProof(nonce)
	if err != nil {
		return tokenHTTPResult{}, err
	}
	return c.sendTokenProof(ctx, params, proof)
}

// NewTokenProof builds a single /token DPoP proof (HTM POST, the configured htu,
// optional nonce). Exposed so the proof-replay demo can send the SAME proof twice.
func (c *TokenClient) NewTokenProof(nonce string) (string, error) {
	return c.km.CreateProof(dpop.ProofOptions{HTM: "POST", HTU: c.tokenHTU, Nonce: nonce}, c.logger)
}

// sendTokenProof POSTs the form params to the token endpoint with the EXACT proof
// supplied, and returns the raw result.
func (c *TokenClient) sendTokenProof(ctx context.Context, params url.Values, proof string) (tokenHTTPResult, error) {
	// Safe to log: grant_type and client_id are public; code/verifier are not.
	c.logger.Debug("oauth.token.request", logx.Fields{
		"token_endpoint":    c.ep.TokenEndpoint,
		"proof_htu":         c.tokenHTU,
		"grant_type":        params.Get("grant_type"),
		"client_id":         params.Get("client_id"),
		"has_code":          params.Get("code") != "",
		"has_code_verifier": params.Get("code_verifier") != "",
		"has_refresh_token": params.Get("refresh_token") != "",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return tokenHTTPResult{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	res, err := c.doer.Do(req)
	if err != nil {
		return tokenHTTPResult{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var body tokenResponse
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &body) // keep raw even if it isn't JSON
	}
	return tokenHTTPResult{
		status:    res.StatusCode,
		body:      body,
		raw:       string(raw),
		dpopNonce: res.Header.Get("DPoP-Nonce"),
		wwwAuth:   res.Header.Get("WWW-Authenticate"),
		wire: Wire{
			Method: http.MethodPost, URL: c.ep.TokenEndpoint,
			ReqHeaders: req.Header.Clone(), ReqBody: params.Encode(),
			Status: res.StatusCode, RespHeaders: res.Header, RespBody: string(raw),
		},
	}, nil
}

func isUseDpopNonce(r tokenHTTPResult) bool {
	return r.body.Error == "use_dpop_nonce" || strings.Contains(r.wwwAuth, "use_dpop_nonce")
}

// withNonceRetry calls /token with the cached nonce; on a use_dpop_nonce
// challenge it caches the fresh DPoP-Nonce and retries exactly once.
func (c *TokenClient) withNonceRetry(ctx context.Context, params url.Values) (tokenHTTPResult, error) {
	res, err := c.tokenRequest(ctx, params, c.nonce)
	if err != nil {
		return tokenHTTPResult{}, err
	}
	if isUseDpopNonce(res) {
		if res.dpopNonce != "" {
			c.nonce = res.dpopNonce
			c.logger.Info("oauth.nonce.challenge", nil)
		} else {
			c.logger.Warn("oauth.nonce.missing_header", logx.Fields{
				"note": "server returned use_dpop_nonce but no DPoP-Nonce response header — a proxy/BFF is likely stripping it; relay the DPoP-Nonce header back to the bridge",
			})
		}
		res, err = c.tokenRequest(ctx, params, c.nonce)
		if err != nil {
			return tokenHTTPResult{}, err
		}
	}
	return res, nil
}

// ExchangeCode swaps an authorization code for a DPoP-bound token set.
func (c *TokenClient) ExchangeCode(ctx context.Context, r AuthCodeResult) (*store.TokenSet, error) {
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", r.Code)
	params.Set("redirect_uri", r.RedirectURI)
	params.Set("client_id", c.cfg.OktaClientID)
	params.Set("code_verifier", r.Verifier)
	res, err := c.withNonceRetry(ctx, params)
	if err != nil {
		return nil, err
	}
	return c.buildAndPersist(res, "acquired", nil)
}

// Refresh refreshes a token set (carrying a DPoP proof on the refresh too).
func (c *TokenClient) Refresh(ctx context.Context, set store.TokenSet) (*store.TokenSet, error) {
	if set.RefreshToken == "" {
		return nil, fmt.Errorf("cannot refresh: no refresh_token")
	}
	res, err := c.withNonceRetry(ctx, c.RefreshParams(set))
	if err != nil {
		return nil, err
	}
	return c.buildAndPersist(res, "refreshed", &set)
}

// RefreshParams builds the refresh_token grant params for a token set. Exposed
// for the nonce-replay demo, which drives individual /token requests by hand.
func (c *TokenClient) RefreshParams(set store.TokenSet) url.Values {
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", set.RefreshToken)
	params.Set("client_id", c.cfg.OktaClientID)
	params.Set("scope", set.Scope)
	return params
}

// TokenProbe is the raw result of a single low-level /token request.
type TokenProbe struct {
	Status       int
	Error        string
	Description  string
	DPoPNonce    string
	TokenType    string
	AccessToken  string
	RefreshToken string
	Wire         Wire
}

func toProbe(res tokenHTTPResult) TokenProbe {
	return TokenProbe{
		Status:       res.status,
		Error:        res.body.Error,
		Description:  res.body.ErrorDescription,
		DPoPNonce:    res.dpopNonce,
		TokenType:    res.body.TokenType,
		AccessToken:  res.body.AccessToken,
		RefreshToken: res.body.RefreshToken,
		Wire:         res.wire,
	}
}

// ProbeTokenRequest performs exactly ONE /token call with the given (possibly
// empty) nonce — no auto-retry, no nonce recovery — and returns the raw result.
// Used by the nonce-replay demo to deliberately reuse a stale nonce.
func (c *TokenClient) ProbeTokenRequest(ctx context.Context, params url.Values, nonce string) (TokenProbe, error) {
	res, err := c.tokenRequest(ctx, params, nonce)
	if err != nil {
		return TokenProbe{}, err
	}
	return toProbe(res), nil
}

// ProbeTokenRequestWithProof performs exactly ONE /token call using the EXACT
// proof supplied (no fresh proof generated). Used by the proof-replay demo to
// send a byte-identical proof twice and show the AS reject the duplicate jti.
func (c *TokenClient) ProbeTokenRequestWithProof(ctx context.Context, params url.Values, proof string) (TokenProbe, error) {
	res, err := c.sendTokenProof(ctx, params, proof)
	if err != nil {
		return TokenProbe{}, err
	}
	return toProbe(res), nil
}

// DecodeClaims decodes (WITHOUT verifying) a JWT access token's claims. Returns
// (nil, false) for an opaque (non-JWT) token.
func DecodeClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, false
	}
	return m, true
}

// CnfJKT returns the cnf.jkt thumbprint embedded in a JWT access token.
func CnfJKT(token string) (string, bool) { return decodeCnfJKT(token) }

// GetAccessToken returns a valid token: stored-if-valid, else refresh, else the
// full login (authFn + ExchangeCode).
func (c *TokenClient) GetAccessToken(ctx context.Context, authFn AuthorizeFn) (string, error) {
	existing, err := c.store.Load()
	if err != nil {
		return "", err
	}
	if existing != nil && !c.store.IsExpired(*existing, store.DefaultSkew) {
		return existing.AccessToken, nil
	}
	if existing != nil && existing.RefreshToken != "" {
		next, err := c.Refresh(ctx, *existing)
		if err != nil {
			return "", err
		}
		return next.AccessToken, nil
	}
	codeRes, err := authFn()
	if err != nil {
		return "", err
	}
	set, err := c.ExchangeCode(ctx, codeRes)
	if err != nil {
		return "", err
	}
	return set.AccessToken, nil
}

func (c *TokenClient) buildAndPersist(res tokenHTTPResult, kind string, prev *store.TokenSet) (*store.TokenSet, error) {
	if res.status < 200 || res.status >= 300 || res.body.AccessToken == "" {
		fields := logx.Fields{
			"status":         res.status,
			"token_endpoint": c.ep.TokenEndpoint,
			"has_dpop_nonce": res.dpopNonce != "",
		}
		if res.body.Error != "" {
			fields["error"] = res.body.Error
		}
		if res.body.ErrorDescription != "" {
			fields["error_description"] = res.body.ErrorDescription
		}
		if res.wwwAuth != "" {
			fields["www_authenticate"] = res.wwwAuth
		}
		if res.status < 200 || res.status >= 300 {
			fields["body"] = truncate(res.raw, 500)
		}
		c.logger.Error("oauth.token.request_failed", fields)

		detail := fmt.Sprintf("HTTP %d", res.status)
		if res.body.Error != "" {
			detail = res.body.Error
			if res.body.ErrorDescription != "" {
				detail = res.body.Error + ": " + res.body.ErrorDescription
			}
		}
		return nil, fmt.Errorf("token request failed: %s", detail)
	}

	jkt := c.km.JKT()

	// Decode (do NOT verify) the access token to determine actual DPoP binding.
	// The token_type label is unreliable: some issuers/BFFs return "Bearer" even
	// when the JWT carries a matching cnf.jkt. The only proof of binding is cnf.jkt.
	cnf, isJWT := decodeCnfJKT(res.body.AccessToken)
	confirmedBound := isJWT && cnf != "" && cnf == jkt

	// Diagnostic: report whether the issued token is actually sender-constrained,
	// independent of the token_type label. Opaque (non-JWT) tokens can't be
	// inspected here — binding is enforced by the resource server on introspection.
	// Logs thumbprints only, never the token.
	binding := logx.Fields{
		"token_type": orDefault(res.body.TokenType, "(none)"),
		"format":     "opaque",
		"key_jkt":    jkt,
	}
	switch {
	case !isJWT:
		binding["bound"] = "unknown"
		binding["note"] = "opaque token — cnf.jkt not inspectable here; resource server enforces binding on introspection"
	case cnf == "":
		binding["format"] = "jwt"
		binding["bound"] = false
		binding["note"] = "JWT access token has no cnf.jkt — NOT DPoP-bound (issuer/BFF did not bind the proof to the token)"
	case cnf == jkt:
		binding["format"] = "jwt"
		binding["bound"] = true
		binding["token_jkt"] = cnf
	default:
		binding["format"] = "jwt"
		binding["bound"] = false
		binding["token_jkt"] = cnf
	}
	c.logger.Info("oauth.token.binding", binding)

	if isJWT && cnf != "" && cnf != jkt {
		c.logger.Error("oauth.token.jkt_mismatch", logx.Fields{"expected": jkt, "got": cnf})
		return nil, fmt.Errorf("access token cnf.jkt does not match the bridge key")
	}

	// Warn only when the token is not the DPoP type AND we couldn't confirm it's
	// actually bound to our key. A confirmed cnf.jkt match means the token IS
	// sender-constrained even if the issuer mislabeled token_type as "Bearer".
	if res.body.TokenType != "DPoP" && !confirmedBound {
		c.logger.Warn("oauth.token.not_dpop_bound", logx.Fields{"token_type": orDefault(res.body.TokenType, "(none)")})
	}

	set := store.TokenSet{
		AccessToken:  res.body.AccessToken,
		RefreshToken: refreshOf(res.body.RefreshToken, prev),
		TokenType:    orDefault(res.body.TokenType, "DPoP"),
		ExpiresAt:    c.now().Unix() + res.body.ExpiresIn,
		Scope:        scopeOf(res.body.Scope, prev, c.cfg.OktaScopes),
		JKT:          jkt,
	}
	if err := c.store.Save(set); err != nil {
		return nil, err
	}
	event := "oauth.token.acquired"
	if kind == "refreshed" {
		event = "oauth.token.refreshed"
	}
	c.logger.Info(event, logx.Fields{"jkt": jkt, "expiresAt": set.ExpiresAt, "scope": set.Scope})
	return &set, nil
}

// decodeCnfJKT extracts cnf.jkt from a JWT access token WITHOUT verifying its
// signature. Returns ("", false) for an opaque (non-JWT) token.
func decodeCnfJKT(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		Cnf struct {
			Jkt string `json:"jkt"`
		} `json:"cnf"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	return claims.Cnf.Jkt, true
}

func refreshOf(newRT string, prev *store.TokenSet) string {
	if newRT != "" {
		return newRT
	}
	if prev != nil {
		return prev.RefreshToken
	}
	return ""
}

func scopeOf(s string, prev *store.TokenSet, def string) string {
	if s != "" {
		return s
	}
	if prev != nil && prev.Scope != "" {
		return prev.Scope
	}
	return def
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
