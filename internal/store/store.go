// Package store persists the OAuth token set, encrypted at rest, the Go port of
// src/store.ts. The token set is sealed (AES-256-GCM via the seal package) and
// written to <BRIDGE_HOME>/tokens.json with mode 0600. Never log token material.
package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/seal"
)

// DefaultSkew is the expiry safety margin (seconds) used by getAccessToken.
const DefaultSkew int64 = 60

// TokenSet is the persisted OAuth token bundle.
type TokenSet struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	TokenType    string `json:"tokenType"`
	ExpiresAt    int64  `json:"expiresAt"` // absolute expiry, epoch seconds
	Scope        string `json:"scope"`
	JKT          string `json:"jkt"` // thumbprint of the bound DPoP key
}

// TokenStore reads/writes the encrypted token file under BRIDGE_HOME.
type TokenStore struct {
	home string
	path string
	now  func() time.Time // injectable for deterministic expiry tests
}

// New returns a store rooted at home.
func New(home string) *TokenStore {
	return &TokenStore{home: home, path: filepath.Join(home, "tokens.json"), now: time.Now}
}

// Load returns the persisted token set, or (nil, nil) if none exists.
func (s *TokenStore) Load() (*TokenSet, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sealed seal.Sealed
	if err := json.Unmarshal(b, &sealed); err != nil {
		return nil, err
	}
	var ts TokenSet
	if err := seal.OpenJSON(s.home, sealed, &ts); err != nil {
		return nil, err
	}
	return &ts, nil
}

// Save persists the token set, encrypted, mode 0600.
func (s *TokenStore) Save(ts TokenSet) error {
	if err := seal.EnsureBridgeHome(s.home); err != nil {
		return err
	}
	sealed, err := seal.SealJSON(s.home, ts)
	if err != nil {
		return err
	}
	data, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}

// Clear removes the persisted token set (idempotent).
func (s *TokenStore) Clear() error {
	err := os.Remove(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// IsExpired reports whether the set is expired or within skew seconds of expiry.
func (s *TokenStore) IsExpired(ts TokenSet, skew int64) bool {
	return s.now().Unix() >= ts.ExpiresAt-skew
}
