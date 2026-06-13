// Package mockadapter is an httptest server that faithfully re-implements the
// Okta MCP Adapter's DPoP verifier contract (RFC 9728/8414 discovery, the
// /token nonce handshake + cnf.jkt-bound minting, and POST / proof verification
// with htm/htu/ath/jti-replay/cnf.jkt checks). Driving the real bridge against
// it is real evidence the bridge's proofs would pass the actual adapter — this
// mock IS the contract test. It verifies ES256 signatures independently (no
// reuse of the bridge's signing code), reusing only dpop.CanonicalHTU for htu.
package mockadapter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/joewitt99/bridge-mcp-client/internal/dpop"
)

var mockSecret = []byte("mock-adapter-secret-mock-adapter-secret!")

const (
	tokenNonce    = "tok-nonce-1"
	resourceNonce = "res-nonce-1"
)

// Options configure the mock's behavior.
type Options struct {
	MintMismatch    bool // mint a token whose cnf.jkt != the proof jkt
	NoResourceNonce bool // skip the one-time resource-side use_dpop_nonce challenge
}

// Adapter is a running mock adapter.
type Adapter struct {
	server *httptest.Server
	opts   Options

	mu                  sync.Mutex
	tokenChallenges     int
	resourceNonceIssued bool
	seenJTI             map[string]bool
	initializeUnauthed  bool
}

// New starts a mock adapter. Call Close when done.
func New(opts Options) *Adapter {
	a := &Adapter{opts: opts, seenJTI: map[string]bool{}}
	a.server = httptest.NewServer(http.HandlerFunc(a.handle))
	return a
}

func (a *Adapter) URL() string          { return a.server.URL }
func (a *Adapter) Client() *http.Client { return a.server.Client() }
func (a *Adapter) Close()               { a.server.Close() }

func (a *Adapter) TokenChallenges() int { a.mu.Lock(); defer a.mu.Unlock(); return a.tokenChallenges }
func (a *Adapter) ResourceNonceIssued() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.resourceNonceIssued
}
func (a *Adapter) InitializeUnauthed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.initializeUnauthed
}

func (a *Adapter) handle(w http.ResponseWriter, r *http.Request) {
	base := "http://" + r.Host
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-protected-resource":
		writeJSON(w, 200, map[string]any{"authorization_servers": []string{base}})
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/oauth-authorization-server":
		writeJSON(w, 200, map[string]any{
			"issuer":                            base,
			"authorization_endpoint":            base + "/authorize",
			"token_endpoint":                    base + "/token",
			"dpop_signing_alg_values_supported": []string{"ES256", "ES384", "RS256"},
		})
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		a.handleToken(w, r, base)
	case r.Method == http.MethodPost && r.URL.Path == "/":
		a.handleMCP(w, r, base)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (a *Adapter) handleToken(w http.ResponseWriter, r *http.Request, base string) {
	claims, jkt, err := verifyProof(r.Header.Get("DPoP"))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "invalid_dpop_proof", "error_description": err.Error()})
		return
	}
	wantHTU, _ := dpop.CanonicalHTU(base + "/token")
	if claims["htm"] != "POST" || claims["htu"] != wantHTU {
		writeJSON(w, 400, map[string]any{"error": "invalid_dpop_proof", "error_description": "htm/htu"})
		return
	}
	// Okta nonce handshake: the first proof (no nonce) is rejected.
	if claims["nonce"] != tokenNonce {
		a.mu.Lock()
		a.tokenChallenges++
		a.mu.Unlock()
		w.Header().Set("DPoP-Nonce", tokenNonce)
		writeJSON(w, 400, map[string]any{"error": "use_dpop_nonce"})
		return
	}
	cnf := jkt
	if a.opts.MintMismatch {
		cnf = "WRONG-JKT-THUMBPRINT"
	}
	writeJSON(w, 200, map[string]any{
		"access_token":  mintToken(map[string]any{"cnf": map[string]any{"jkt": cnf}, "scope": "openid offline_access", "sub": "user"}),
		"token_type":    "DPoP",
		"expires_in":    3600,
		"scope":         "openid offline_access",
		"refresh_token": "rt-1",
	})
}

func (a *Adapter) handleMCP(w http.ResponseWriter, r *http.Request, base string) {
	body, _ := io.ReadAll(r.Body)
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	json.Unmarshal(body, &msg)

	if msg.Method == "initialize" || msg.Method == "ping" || strings.HasPrefix(msg.Method, "notifications/") {
		if msg.Method == "initialize" {
			a.mu.Lock()
			a.initializeUnauthed = r.Header.Get("Authorization") == ""
			a.mu.Unlock()
			writeJSON(w, 200, rpcResult(msg.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mock-adapter", "version": "0.0.0"},
			}))
			return
		}
		writeJSON(w, 200, rpcResult(msg.ID, map[string]any{}))
		return
	}

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "DPoP ") {
		writeJSON(w, 401, map[string]any{"error": "required_missing"})
		return
	}
	token := strings.TrimPrefix(auth, "DPoP ")

	if !a.opts.NoResourceNonce {
		a.mu.Lock()
		issued := a.resourceNonceIssued
		a.resourceNonceIssued = true
		a.mu.Unlock()
		if !issued {
			w.Header().Set("DPoP-Nonce", resourceNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			writeJSON(w, 401, map[string]any{"error": "use_dpop_nonce"})
			return
		}
	}

	claims, jkt, err := verifyProof(r.Header.Get("DPoP"))
	if err != nil {
		writeJSON(w, 401, map[string]any{"error": "rejected", "error_description": err.Error()})
		return
	}
	wantHTU, _ := dpop.CanonicalHTU(base + "/")
	if claims["htm"] != "POST" || claims["htu"] != wantHTU {
		writeJSON(w, 401, map[string]any{"error": "rejected", "error_description": "htm/htu"})
		return
	}
	sum := sha256.Sum256([]byte(token))
	if claims["ath"] != b64(sum[:]) {
		writeJSON(w, 401, map[string]any{"error": "rejected", "error_description": "ath"})
		return
	}
	if cnf := tokenCnfJKT(token); cnf != "" && cnf != jkt {
		writeJSON(w, 401, map[string]any{"error": "rejected_jkt"})
		return
	}
	jti, _ := claims["jti"].(string)
	a.mu.Lock()
	replay := a.seenJTI[jti]
	a.seenJTI[jti] = true
	a.mu.Unlock()
	if replay {
		writeJSON(w, 401, map[string]any{"error": "replay_detected"})
		return
	}

	writeJSON(w, 200, rpcResult(msg.ID, map[string]any{"tools": []any{map[string]any{"name": "echo", "description": "echoes input"}}}))
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func rpcResult(id json.RawMessage, result map[string]any) map[string]any {
	var idVal any
	if len(id) > 0 {
		idVal = id
	}
	return map[string]any{"jsonrpc": "2.0", "id": idVal, "result": result}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mintToken(claims map[string]any) string {
	hb, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	pb, _ := json.Marshal(claims)
	si := b64(hb) + "." + b64(pb)
	mac := hmac.New(sha256.New, mockSecret)
	mac.Write([]byte(si))
	return si + "." + b64(mac.Sum(nil))
}

func tokenCnfJKT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Cnf struct {
			Jkt string `json:"jkt"`
		} `json:"cnf"`
	}
	json.Unmarshal(pb, &c)
	return c.Cnf.Jkt
}

// verifyProof independently verifies a DPoP proof's ES256 signature against its
// embedded public JWK and returns the claims + RFC 7638 thumbprint.
func verifyProof(proof string) (map[string]any, string, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("malformed proof")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", err
	}
	var hdr struct {
		Typ string         `json:"typ"`
		Alg string         `json:"alg"`
		JWK map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, "", err
	}
	if hdr.Typ != "dpop+jwt" {
		return nil, "", fmt.Errorf("bad typ %q", hdr.Typ)
	}
	if hdr.Alg != "ES256" {
		return nil, "", fmt.Errorf("bad alg %q", hdr.Alg)
	}
	if hdr.JWK == nil {
		return nil, "", fmt.Errorf("missing jwk")
	}
	xb, err := base64.RawURLEncoding.DecodeString(str(hdr.JWK["x"]))
	if err != nil {
		return nil, "", err
	}
	yb, err := base64.RawURLEncoding.DecodeString(str(hdr.JWK["y"]))
	if err != nil {
		return nil, "", err
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, "", fmt.Errorf("bad signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, "", fmt.Errorf("signature verification failed")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(pb, &claims); err != nil {
		return nil, "", err
	}
	return claims, thumbprint(hdr.JWK), nil
}

// thumbprint computes the RFC 7638 SHA-256 thumbprint of an EC JWK.
func thumbprint(jwk map[string]any) string {
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`,
		str(jwk["crv"]), str(jwk["kty"]), str(jwk["x"]), str(jwk["y"]))
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

func str(v any) string { s, _ := v.(string); return s }
