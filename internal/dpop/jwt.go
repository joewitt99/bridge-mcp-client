package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

const p256Bytes = 32 // coordinate width for P-256

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// leftPad fixes b to exactly size bytes (left-pad with zeros, or left-truncate).
// Critical for ES256 R||S signatures and fixed-width JWK coordinates: a naive
// big.Int.Bytes() drops leading zeros and would produce malformed values.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// publicJWK is the public EC JWK with members in RFC 7638 canonical
// (lexicographic) order, so its marshaled form IS the thumbprint input.
type publicJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func publicJWKFromKey(pub *ecdsa.PublicKey) publicJWK {
	return publicJWK{
		Crv: "P-256",
		Kty: "EC",
		X:   b64url(leftPad(pub.X.Bytes(), p256Bytes)),
		Y:   b64url(leftPad(pub.Y.Bytes(), p256Bytes)),
	}
}

// thumbprint is the RFC 7638 SHA-256 JWK thumbprint (base64url, no padding).
func (j publicJWK) thumbprint() (string, error) {
	canonical, err := json.Marshal(j) // fields are already lexicographically ordered
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return b64url(sum[:]), nil
}

// signES256 produces a compact JWS over (header, payload) signed with priv.
// The signature is the fixed-width 64-byte R||S form DPoP/JWS requires — NOT
// the ASN.1/DER form ecdsa.SignASN1 returns.
func signES256(priv *ecdsa.PrivateKey, header, payload []byte) (string, error) {
	signingInput := b64url(header) + "." + b64url(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	sig := append(leftPad(r.Bytes(), p256Bytes), leftPad(s.Bytes(), p256Bytes)...)
	return signingInput + "." + b64url(sig), nil
}

// uuidV4 returns a random RFC 4122 v4 UUID (for the DPoP jti).
func uuidV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// privateJWK is the sealed-at-rest key representation (public params + d).
type privateJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

func privateJWKFromKey(priv *ecdsa.PrivateKey) privateJWK {
	return privateJWK{
		Crv: "P-256",
		Kty: "EC",
		X:   b64url(leftPad(priv.X.Bytes(), p256Bytes)),
		Y:   b64url(leftPad(priv.Y.Bytes(), p256Bytes)),
		D:   b64url(leftPad(priv.D.Bytes(), p256Bytes)),
	}
}

func (j privateJWK) toKey() (*ecdsa.PrivateKey, error) {
	x, err := bigFromB64(j.X)
	if err != nil {
		return nil, err
	}
	y, err := bigFromB64(j.Y)
	if err != nil {
		return nil, err
	}
	d, err := bigFromB64(j.D)
	if err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = elliptic.P256()
	priv.PublicKey.X = x
	priv.PublicKey.Y = y
	return priv, nil
}

func bigFromB64(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("bad jwk field: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}
