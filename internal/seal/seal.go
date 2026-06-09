// Package seal provides encryption-at-rest for the bridge's secrets (DPoP key
// and OAuth tokens), the Go port of src/crypto.ts.
//
// Values are sealed with AES-256-GCM under a key derived (HKDF-SHA256) from a
// per-machine seed (<BRIDGE_HOME>/.seed, 32 random bytes, 0600). Plaintext key
// or token material never touches disk. The on-disk format is Go-native
// ({v, nonce, ct}, where ct is GCM ciphertext||tag) and intentionally NOT
// interoperable with the TypeScript build's {iv,ciphertext,tag} format — these
// are fresh installs. Never log what passes through here.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const seedInfo = "okta-mcp-bridge seal v1"

// Sealed is an AES-256-GCM blob: a nonce and ciphertext||tag, both base64.
type Sealed struct {
	V     int    `json:"v"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// EnsureBridgeHome creates BRIDGE_HOME with mode 0700 (idempotent).
func EnsureBridgeHome(home string) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	return os.Chmod(home, 0o700)
}

// readSeed reads (or creates, 0600) the 32-byte per-machine seed.
func readSeed(home string) ([]byte, error) {
	path := filepath.Join(home, ".seed")
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	return seed, nil
}

func deriveKey(home string) ([]byte, error) {
	if err := EnsureBridgeHome(home); err != nil {
		return nil, err
	}
	seed, err := readSeed(home)
	if err != nil {
		return nil, err
	}
	// Stdlib HKDF-SHA256 (Go 1.24+); nil salt = HashLen zero bytes per RFC 5869.
	return hkdf.Key(sha256.New, seed, nil, seedInfo, 32)
}

func gcmFor(home string) (cipher.AEAD, error) {
	key, err := deriveKey(home)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealJSON marshals v and seals it. Creates the seed on first use.
func SealJSON(home string, v any) (Sealed, error) {
	plaintext, err := json.Marshal(v)
	if err != nil {
		return Sealed{}, err
	}
	gcm, err := gcmFor(home)
	if err != nil {
		return Sealed{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return Sealed{
		V:     1,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// OpenJSON opens a sealed blob and unmarshals it into dst.
func OpenJSON(home string, s Sealed, dst any) error {
	nonce, err := base64.StdEncoding.DecodeString(s.Nonce)
	if err != nil {
		return fmt.Errorf("bad nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(s.CT)
	if err != nil {
		return fmt.Errorf("bad ciphertext: %w", err)
	}
	gcm, err := gcmFor(home)
	if err != nil {
		return err
	}
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return fmt.Errorf("decrypt failed: %w", err)
	}
	return json.Unmarshal(plaintext, dst)
}
