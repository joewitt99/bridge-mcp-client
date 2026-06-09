package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
)

func testCfg(home, mode string) config.Config {
	return config.Config{
		AdapterBaseURL: "https://adapter.example.com",
		OktaClientID:   "cid",
		AgentID:        "agent-1",
		OktaScopes:     "openid offline_access",
		DpopAlg:        "ES256",
		DpopKeyMode:    mode,
		BridgeHome:     home,
		HTTPTimeout:    30 * time.Second,
		LogLevel:       "error",
	}
}

func newKM(t *testing.T, mode string) *KeyManager {
	t.Helper()
	km, err := NewKeyManager(testCfg(t.TempDir(), mode), nil)
	if err != nil {
		t.Fatal(err)
	}
	return km
}

func mustProof(t *testing.T, km *KeyManager, o ProofOptions) string {
	t.Helper()
	p, err := km.CreateProof(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeSeg(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url decode: %v", err)
	}
	return b
}

func parseProof(t *testing.T, proof string) (hdr, pl map[string]any, parts []string) {
	t.Helper()
	parts = strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}
	if err := json.Unmarshal(decodeSeg(t, parts[0]), &hdr); err != nil {
		t.Fatalf("header: %v", err)
	}
	if err := json.Unmarshal(decodeSeg(t, parts[1]), &pl); err != nil {
		t.Fatalf("payload: %v", err)
	}
	return hdr, pl, parts
}

func TestProofHeaderAndClaims(t *testing.T) {
	km := newKM(t, "persistent")
	before := time.Now().Unix()
	hdr, pl, _ := parseProof(t, mustProof(t, km, ProofOptions{
		HTM: "post",
		HTU: "https://Adapter.Example.com:443/?q=1#frag",
	}))

	if hdr["typ"] != "dpop+jwt" || hdr["alg"] != "ES256" {
		t.Fatalf("bad header: %v", hdr)
	}
	jwk, ok := hdr["jwk"].(map[string]any)
	if !ok {
		t.Fatal("header missing jwk")
	}
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		t.Fatalf("bad jwk: %v", jwk)
	}
	if _, leaked := jwk["d"]; leaked {
		t.Fatal("embedded jwk leaked the private parameter d")
	}
	if s, _ := pl["jti"].(string); s == "" {
		t.Fatal("missing jti")
	}
	if pl["htm"] != "POST" {
		t.Fatalf("htm not upper-cased: %v", pl["htm"])
	}
	if pl["htu"] != "https://adapter.example.com/" {
		t.Fatalf("htu not canonical: %v", pl["htu"])
	}
	iat, ok := pl["iat"].(float64)
	if !ok || int64(iat) < before {
		t.Fatalf("bad iat: %v", pl["iat"])
	}
}

func TestAth(t *testing.T) {
	km := newKM(t, "persistent")
	token := "access-token-xyz"
	_, pl, _ := parseProof(t, mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/", AccessToken: token}))
	sum := sha256.Sum256([]byte(token))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if pl["ath"] != want {
		t.Fatalf("ath = %v, want %s", pl["ath"], want)
	}

	_, pl2, _ := parseProof(t, mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/"}))
	if _, ok := pl2["ath"]; ok {
		t.Fatal("ath should be absent without an access token")
	}
}

func TestNonceOnlyWhenProvided(t *testing.T) {
	km := newKM(t, "persistent")
	_, plNo, _ := parseProof(t, mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/"}))
	if _, ok := plNo["nonce"]; ok {
		t.Fatal("nonce should be absent")
	}
	_, plYes, _ := parseProof(t, mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/", Nonce: "abc123"}))
	if plYes["nonce"] != "abc123" {
		t.Fatalf("nonce = %v", plYes["nonce"])
	}
}

func TestJtiUnique(t *testing.T) {
	km := newKM(t, "persistent")
	_, a, _ := parseProof(t, mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/"}))
	_, b, _ := parseProof(t, mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/"}))
	if a["jti"] == b["jti"] {
		t.Fatal("jti should be unique across proofs")
	}
}

func TestSignatureVerifies(t *testing.T) {
	km := newKM(t, "persistent")
	proof := mustProof(t, km, ProofOptions{HTM: "POST", HTU: "https://adapter.example.com/"})
	hdr, _, parts := parseProof(t, proof)
	jwk := hdr["jwk"].(map[string]any)
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(decodeSeg(t, jwk["x"].(string))),
		Y:     new(big.Int).SetBytes(decodeSeg(t, jwk["y"].(string))),
	}
	sig := decodeSeg(t, parts[2])
	if len(sig) != 64 {
		t.Fatalf("ES256 signature must be 64 bytes (R||S), got %d", len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature did not verify against the embedded public key")
	}
}

func TestCanonicalHTU(t *testing.T) {
	cases := map[string]string{
		"https://Host.EXAMPLE.com:443/?q=1#f":     "https://host.example.com/",
		"http://Host.example.com:80/token":        "http://host.example.com/token",
		"https://host.example.com:8443/cb?x=1":    "https://host.example.com:8443/cb",
		"https://JOE.oktapreview.com/oauth2/v1/x": "https://joe.oktapreview.com/oauth2/v1/x",
	}
	for in, want := range cases {
		got, err := CanonicalHTU(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("CanonicalHTU(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := CanonicalHTU("not a url"); err == nil {
		t.Error("expected error for non-absolute URL")
	}
}

func TestPersistentSameJKT(t *testing.T) {
	home := t.TempDir()
	a, err := NewKeyManager(testCfg(home, "persistent"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeyManager(testCfg(home, "persistent"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.JKT() != b.JKT() {
		t.Fatalf("persistent reload changed jkt: %s != %s", a.JKT(), b.JKT())
	}
}

func TestEphemeralDifferentJKT(t *testing.T) {
	a := newKM(t, "ephemeral")
	b := newKM(t, "ephemeral")
	if a.JKT() == b.JKT() {
		t.Fatal("ephemeral managers should have different jkts")
	}
}

func TestKeyFileSealedAndMode(t *testing.T) {
	home := t.TempDir()
	if _, err := NewKeyManager(testCfg(home, "persistent"), nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "dpop-key.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"d"`) || strings.Contains(string(raw), `"x"`) {
		t.Fatal("key file should not contain plaintext private/public JWK params")
	}
	if !strings.Contains(string(raw), `"ct"`) {
		t.Fatal("key file should contain the sealed ciphertext")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("dpop-key.json mode = %o, want 600", fi.Mode().Perm())
		}
	}
}
