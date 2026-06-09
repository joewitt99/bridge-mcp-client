package seal

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// RFC 5869 Appendix A, Test Case 1 (SHA-256).
func TestHKDFVector(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a" +
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865"
	got := hex.EncodeToString(hkdf(sha256.New, ikm, salt, info, 42))
	if got != want {
		t.Fatalf("HKDF mismatch:\n got %s\nwant %s", got, want)
	}
}

type secret struct {
	Token string `json:"token"`
	N     int    `json:"n"`
}

func TestSealOpenRoundTrip(t *testing.T) {
	home := t.TempDir()
	in := secret{Token: "super-secret-access-token", N: 42}
	sealed, err := SealJSON(home, in)
	if err != nil {
		t.Fatal(err)
	}
	var out secret
	if err := OpenJSON(home, sealed, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch: %+v != %+v", out, in)
	}
}

func TestSealedIsNotPlaintext(t *testing.T) {
	home := t.TempDir()
	sealed, err := SealJSON(home, secret{Token: "PLAINTEXT-MARKER", N: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed.CT, "PLAINTEXT-MARKER") || strings.Contains(sealed.Nonce, "PLAINTEXT-MARKER") {
		t.Fatal("plaintext leaked into sealed blob")
	}
	if sealed.V != 1 || sealed.Nonce == "" || sealed.CT == "" {
		t.Fatalf("unexpected sealed shape: %+v", sealed)
	}
}

func TestTamperFailsAuth(t *testing.T) {
	home := t.TempDir()
	sealed, err := SealJSON(home, secret{Token: "x", N: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte of the ciphertext → GCM auth must fail.
	b := []byte(sealed.CT)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	sealed.CT = string(b)
	var out secret
	if err := OpenJSON(home, sealed, &out); err == nil {
		t.Fatal("tampered ciphertext should fail to open")
	}
}

func TestSeedPersistsAcrossCalls(t *testing.T) {
	home := t.TempDir()
	sealed, err := SealJSON(home, secret{Token: "persist", N: 7})
	if err != nil {
		t.Fatal(err)
	}
	// A separate Open call re-derives the key from the same on-disk seed.
	var out secret
	if err := OpenJSON(home, sealed, &out); err != nil {
		t.Fatalf("second derive should reproduce the key: %v", err)
	}
	if out.Token != "persist" {
		t.Fatalf("got %q", out.Token)
	}
}

func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are a no-op on Windows")
	}
	home := t.TempDir()
	if _, err := SealJSON(home, secret{Token: "x"}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, home); m != 0o700 {
		t.Errorf("BRIDGE_HOME mode = %o, want 700", m)
	}
	if m := mode(t, filepath.Join(home, ".seed")); m != 0o600 {
		t.Errorf(".seed mode = %o, want 600", m)
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}
