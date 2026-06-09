package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/store"
)

var codeResult = AuthCodeResult{Code: "the-code", RedirectURI: "http://127.0.0.1:0/cb", Verifier: strings.Repeat("v", 43)}

type recReq struct {
	url  string
	dpop string
	body url.Values
}

func seqDoer(t *testing.T, resps ...*http.Response) (Doer, *[]recReq) {
	t.Helper()
	calls := &[]recReq{}
	i := 0
	d := doerFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		*calls = append(*calls, recReq{url: r.URL.String(), dpop: r.Header.Get("DPoP"), body: v})
		if i >= len(resps) {
			t.Fatalf("unexpected token request #%d", i+1)
		}
		resp := resps[i]
		i++
		return resp, nil
	})
	return d, calls
}

func oauthResp(status int, body map[string]any, headers map[string]string) *http.Response {
	bb, _ := json.Marshal(body)
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(bb)), Header: h}
}

func mintToken(claims map[string]any) string {
	pb, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(pb) + ".sig"
}

func successResp(km *dpop.KeyManager, extra map[string]any) *http.Response {
	body := map[string]any{
		"access_token": mintToken(map[string]any{"cnf": map[string]any{"jkt": km.JKT()}}),
		"token_type":   "DPoP",
		"expires_in":   3600,
		"scope":        "openid offline_access",
	}
	for k, v := range extra {
		body[k] = v
	}
	return oauthResp(200, body, nil)
}

func setup(t *testing.T, override string) (config.Config, *dpop.KeyManager, *store.TokenStore) {
	t.Helper()
	home := t.TempDir()
	env := map[string]string{
		"ADAPTER_BASE_URL": "https://adapter.example.com",
		"OKTA_CLIENT_ID":   "cid",
		"AGENT_ID":         "agent-1",
		"BRIDGE_HOME":      home,
		"LOG_LEVEL":        "error",
	}
	if override != "" {
		env["OKTA_TOKEN_DPOP_HTU"] = override
	}
	cfg, err := config.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	km, err := dpop.NewKeyManager(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, km, store.New(home)
}

func proofPayload(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT proof, got %q", proof)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNonceHandshake(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t,
		oauthResp(400, map[string]any{"error": "use_dpop_nonce"}, map[string]string{"DPoP-Nonce": "nonce-1"}),
		successResp(km, nil),
	)
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("expected exactly 2 token requests, got %d", len(*calls))
	}
	if _, ok := proofPayload(t, (*calls)[0].dpop)["nonce"]; ok {
		t.Error("first proof should have no nonce")
	}
	if proofPayload(t, (*calls)[1].dpop)["nonce"] != "nonce-1" {
		t.Error("retry proof should carry the nonce")
	}
}

func TestProofHtmHtu(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t, successResp(km, nil))
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err != nil {
		t.Fatal(err)
	}
	pl := proofPayload(t, (*calls)[0].dpop)
	wantHTU, _ := dpop.CanonicalHTU(ep.TokenEndpoint)
	if pl["htm"] != "POST" || pl["htu"] != wantHTU {
		t.Fatalf("proof htm/htu = %v / %v, want POST / %s", pl["htm"], pl["htu"], wantHTU)
	}
}

func TestExchangePersistsJKT(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, _ := seqDoer(t, successResp(km, nil))
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	set, err := c.ExchangeCode(context.Background(), codeResult)
	if err != nil {
		t.Fatal(err)
	}
	if set.JKT != km.JKT() {
		t.Fatalf("set.JKT = %s, want %s", set.JKT, km.JKT())
	}
	loaded, _ := st.Load()
	if loaded == nil || loaded.AccessToken != set.AccessToken {
		t.Fatal("token not persisted")
	}
}

func TestTokenTypeNotDPoPWarns(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, _ := seqDoer(t, successResp(km, map[string]any{"token_type": "Bearer"}))
	buf := &bytes.Buffer{}
	c := NewTokenClient(cfg, ep, km, st, logx.NewWith(buf, "warn"), doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "oauth.token.not_dpop_bound") {
		t.Fatalf("expected not_dpop_bound warning; got %q", buf.String())
	}
}

func TestCnfMismatchThrows(t *testing.T) {
	cfg, km, st := setup(t, "")
	bad := oauthResp(200, map[string]any{
		"access_token": mintToken(map[string]any{"cnf": map[string]any{"jkt": "WRONG"}}),
		"token_type":   "DPoP",
		"expires_in":   3600,
	}, nil)
	doer, _ := seqDoer(t, bad)
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err == nil || !strings.Contains(err.Error(), "cnf.jkt") {
		t.Fatalf("expected cnf.jkt error, got %v", err)
	}
}

func TestCnfAbsentOK(t *testing.T) {
	cfg, km, st := setup(t, "")
	opaque := oauthResp(200, map[string]any{
		"access_token": mintToken(map[string]any{"sub": "user"}),
		"token_type":   "DPoP",
		"expires_in":   3600,
	}, nil)
	doer, _ := seqDoer(t, opaque)
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err != nil {
		t.Fatalf("absent cnf should not error: %v", err)
	}
}

func TestRefresh(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t, successResp(km, nil))
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	prior := store.TokenSet{AccessToken: "old", RefreshToken: "rt-1", TokenType: "DPoP", ExpiresAt: 0, Scope: "openid offline_access", JKT: km.JKT()}
	next, err := c.Refresh(context.Background(), prior)
	if err != nil {
		t.Fatal(err)
	}
	b := (*calls)[0].body
	if b.Get("grant_type") != "refresh_token" || b.Get("refresh_token") != "rt-1" {
		t.Fatalf("bad refresh params: %v", b)
	}
	if (*calls)[0].dpop == "" {
		t.Fatal("refresh must carry a DPoP proof")
	}
	if next.RefreshToken != "rt-1" {
		t.Fatalf("refresh token not carried forward: %q", next.RefreshToken)
	}
}

func TestGetAccessTokenValidNoNetwork(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, _ := seqDoer(t) // any request → t.Fatal
	st.Save(store.TokenSet{AccessToken: "still-good", TokenType: "DPoP", ExpiresAt: 9_999_999_999, Scope: "openid", JKT: km.JKT()})
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	tok, err := c.GetAccessToken(context.Background(), func() (AuthCodeResult, error) {
		t.Fatal("authFn must not run")
		return AuthCodeResult{}, nil
	})
	if err != nil || tok != "still-good" {
		t.Fatalf("got %q, %v", tok, err)
	}
}

func TestGetAccessTokenRefreshes(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t, successResp(km, nil))
	st.Save(store.TokenSet{AccessToken: "expired", RefreshToken: "rt-9", TokenType: "DPoP", ExpiresAt: 1, Scope: "openid", JKT: km.JKT()})
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	tok, err := c.GetAccessToken(context.Background(), func() (AuthCodeResult, error) {
		t.Fatal("authFn must not run on refresh")
		return AuthCodeResult{}, nil
	})
	if err != nil || tok == "expired" {
		t.Fatalf("expected refreshed token, got %q (%v)", tok, err)
	}
	if (*calls)[0].body.Get("grant_type") != "refresh_token" {
		t.Fatalf("expected refresh, got %v", (*calls)[0].body)
	}
}

func TestGetAccessTokenLogin(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t, successResp(km, nil))
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	authorized := false
	tok, err := c.GetAccessToken(context.Background(), func() (AuthCodeResult, error) {
		authorized = true
		return codeResult, nil
	})
	if err != nil || tok == "" || !authorized {
		t.Fatalf("login path failed: tok=%q authorized=%v err=%v", tok, authorized, err)
	}
	if (*calls)[0].body.Get("grant_type") != "authorization_code" {
		t.Fatalf("expected authorization_code, got %v", (*calls)[0].body)
	}
}

func TestLaterNonceRetries(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t,
		oauthResp(400, map[string]any{"error": "use_dpop_nonce"}, map[string]string{"DPoP-Nonce": "nonce-1"}),
		successResp(km, map[string]any{"refresh_token": "rt-1"}),
		oauthResp(400, map[string]any{"error": "use_dpop_nonce"}, map[string]string{"DPoP-Nonce": "nonce-2"}),
		successResp(km, nil),
	)
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	set, err := c.ExchangeCode(context.Background(), codeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(context.Background(), *set); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 4 {
		t.Fatalf("expected 4 token requests, got %d", len(*calls))
	}
	if proofPayload(t, (*calls)[3].dpop)["nonce"] != "nonce-2" {
		t.Error("second handshake retry should carry nonce-2")
	}
}

func TestTokenDpopHTUOverride(t *testing.T) {
	override := "https://org.okta.com/oauth2/v1/token"
	cfg, km, st := setup(t, override)
	doer, calls := seqDoer(t, successResp(km, nil))
	c := NewTokenClient(cfg, ep, km, st, nil, doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err != nil {
		t.Fatal(err)
	}
	// Still dials the discovered token endpoint...
	if (*calls)[0].url != ep.TokenEndpoint {
		t.Fatalf("dialed %q, want %q", (*calls)[0].url, ep.TokenEndpoint)
	}
	// ...but the proof htu is the override.
	wantHTU, _ := dpop.CanonicalHTU(override)
	if proofPayload(t, (*calls)[0].dpop)["htu"] != wantHTU {
		t.Fatalf("proof htu = %v, want %s", proofPayload(t, (*calls)[0].dpop)["htu"], wantHTU)
	}
}

func TestMissingNonceHeaderWarns(t *testing.T) {
	cfg, km, st := setup(t, "")
	doer, calls := seqDoer(t,
		oauthResp(400, map[string]any{"error": "use_dpop_nonce"}, nil), // no DPoP-Nonce header
		oauthResp(400, map[string]any{"error": "use_dpop_nonce"}, nil),
	)
	buf := &bytes.Buffer{}
	c := NewTokenClient(cfg, ep, km, st, logx.NewWith(buf, "warn"), doer)
	if _, err := c.ExchangeCode(context.Background(), codeResult); err == nil || !strings.Contains(err.Error(), "use_dpop_nonce") {
		t.Fatalf("expected use_dpop_nonce failure, got %v", err)
	}
	if !strings.Contains(buf.String(), "oauth.nonce.missing_header") {
		t.Fatalf("expected missing_header warning; got %q", buf.String())
	}
	if len(*calls) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(*calls))
	}
	if _, ok := proofPayload(t, (*calls)[1].dpop)["nonce"]; ok {
		t.Error("retry proof should have no nonce when the header was stripped")
	}
}
