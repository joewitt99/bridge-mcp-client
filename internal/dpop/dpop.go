// Package dpop is the DPoP key manager and proof factory (RFC 9449 / 7638),
// the Go port of src/dpop.ts. It produces proof JWTs that satisfy the Okta MCP
// Adapter contract (typ/alg/jwk/htm/htu/iat/jti/ath, canonical htu) using only
// the standard library — no JOSE dependency.
//
// Secrets at rest: the EC P-256 private key is sealed (AES-256-GCM via the seal
// package) and written 0600. Never log key/proof material — only thumbprints.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
	"github.com/joewitt99/bridge-mcp-client/internal/seal"
)

// KeyManager holds the bridge's DPoP key and mints proofs.
type KeyManager struct {
	alg  string
	priv *ecdsa.PrivateKey
	pub  publicJWK
	jkt  string
	now  func() time.Time // injectable for deterministic iat in tests
}

// keyFile is the on-disk dpop-key.json: the alg alongside the sealed private JWK.
type keyFile struct {
	Alg string `json:"alg"`
	seal.Sealed
}

// NewKeyManager builds a key manager per cfg.DpopKeyMode: persistent loads
// <BRIDGE_HOME>/dpop-key.json (or generates + seals it), ephemeral generates
// in memory. Only ES256 (EC P-256) is supported in this build.
func NewKeyManager(cfg config.Config, logger *logx.Logger) (*KeyManager, error) {
	if logger == nil {
		logger = logx.Default
	}
	if cfg.DpopAlg != "ES256" {
		return nil, fmt.Errorf("dpop: only ES256 is supported in this build, got %q", cfg.DpopAlg)
	}

	if cfg.DpopKeyMode == "persistent" {
		if err := seal.EnsureBridgeHome(cfg.BridgeHome); err != nil {
			return nil, err
		}
		path := filepath.Join(cfg.BridgeHome, "dpop-key.json")
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			var kf keyFile
			if err := json.Unmarshal(b, &kf); err != nil {
				return nil, fmt.Errorf("dpop-key.json: %w", err)
			}
			var pjwk privateJWK
			if err := seal.OpenJSON(cfg.BridgeHome, kf.Sealed, &pjwk); err != nil {
				return nil, err
			}
			priv, err := pjwk.toKey()
			if err != nil {
				return nil, err
			}
			km, err := newFromKey(cfg.DpopAlg, priv)
			if err != nil {
				return nil, err
			}
			logger.Info("dpop.key.loaded", logx.Fields{"jkt": km.jkt})
			return km, nil
		case os.IsNotExist(err):
			// fall through to generate + persist
		default:
			return nil, err
		}

		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		sealed, err := seal.SealJSON(cfg.BridgeHome, privateJWKFromKey(priv))
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(keyFile{Alg: cfg.DpopAlg, Sealed: sealed})
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		km, err := newFromKey(cfg.DpopAlg, priv)
		if err != nil {
			return nil, err
		}
		logger.Info("dpop.key.generated", logx.Fields{"jkt": km.jkt})
		return km, nil
	}

	// ephemeral
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	km, err := newFromKey(cfg.DpopAlg, priv)
	if err != nil {
		return nil, err
	}
	logger.Info("dpop.key.generated", logx.Fields{"jkt": km.jkt, "ephemeral": true})
	return km, nil
}

func newFromKey(alg string, priv *ecdsa.PrivateKey) (*KeyManager, error) {
	pub := publicJWKFromKey(&priv.PublicKey)
	jkt, err := pub.thumbprint()
	if err != nil {
		return nil, err
	}
	return &KeyManager{alg: alg, priv: priv, pub: pub, jkt: jkt, now: time.Now}, nil
}

// JKT returns the RFC 7638 thumbprint of the public key.
func (k *KeyManager) JKT() string { return k.jkt }

// ProofOptions are the inputs to a DPoP proof.
type ProofOptions struct {
	HTM         string // HTTP method
	HTU         string // target URI (canonicalized internally)
	AccessToken string // if set, adds the ath claim
	Nonce       string // if set, adds the nonce claim
}

// CreateProof builds and signs a DPoP proof JWT.
func (k *KeyManager) CreateProof(opts ProofOptions, logger *logx.Logger) (string, error) {
	if logger == nil {
		logger = logx.Default
	}
	htu, err := CanonicalHTU(opts.HTU)
	if err != nil {
		return "", err
	}
	jti, err := uuidV4()
	if err != nil {
		return "", err
	}

	header := map[string]any{"typ": "dpop+jwt", "alg": k.alg, "jwk": k.pub}
	htm := strings.ToUpper(opts.HTM)
	payload := map[string]any{
		"jti": jti,
		"htm": htm,
		"htu": htu,
		"iat": k.now().Unix(),
	}
	if opts.AccessToken != "" {
		sum := sha256.Sum256([]byte(opts.AccessToken))
		payload["ath"] = b64url(sum[:])
	}
	if opts.Nonce != "" {
		payload["nonce"] = opts.Nonce
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	proof, err := signES256(k.priv, hb, pb)
	if err != nil {
		return "", err
	}
	logger.Debug("dpop.proof.created", logx.Fields{
		"htm":       htm,
		"htu":       htu,
		"jkt":       k.jkt,
		"has_ath":   opts.AccessToken != "",
		"has_nonce": opts.Nonce != "",
	})
	return proof, nil
}

// CanonicalHTU lower-cases scheme+host, strips default ports (443/https,
// 80/http), drops query+fragment, and keeps the path (defaulting to "/"), so
// the value byte-matches what the verifier (adapter/Okta) recomputes.
func CanonicalHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "" || host == "" {
		return "", fmt.Errorf("htu is not an absolute URL: %q", raw)
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	authority := host
	if port != "" {
		authority = host + ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + authority + path, nil
}
