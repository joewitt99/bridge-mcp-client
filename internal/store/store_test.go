package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sample() TokenSet {
	return TokenSet{
		AccessToken:  "secret-access-token",
		RefreshToken: "rt-1",
		TokenType:    "DPoP",
		ExpiresAt:    9_999_999_999,
		Scope:        "openid offline_access",
		JKT:          "thumb",
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	in := sample()
	if err := s.Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if out == nil || *out != in {
		t.Fatalf("round-trip mismatch: %+v != %+v", out, in)
	}
}

func TestLoadMissingReturnsNil(t *testing.T) {
	out, err := New(t.TempDir()).Load()
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("expected nil for missing token file, got %+v", out)
	}
}

func TestClear(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Save(sample()); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	out, err := s.Load()
	if err != nil || out != nil {
		t.Fatalf("expected nil after clear, got %+v (err %v)", out, err)
	}
	// Clearing again is a no-op, not an error.
	if err := s.Clear(); err != nil {
		t.Fatalf("second clear should be a no-op: %v", err)
	}
}

func TestIsExpired(t *testing.T) {
	s := New(t.TempDir())
	fixed := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return fixed }

	future := TokenSet{ExpiresAt: 1_000_000 + 3600}
	if s.IsExpired(future, DefaultSkew) {
		t.Error("token 1h in the future should not be expired")
	}
	past := TokenSet{ExpiresAt: 1_000_000 - 10}
	if !s.IsExpired(past, DefaultSkew) {
		t.Error("past token should be expired")
	}
	// Within the skew window counts as expired.
	withinSkew := TokenSet{ExpiresAt: 1_000_000 + 30}
	if !s.IsExpired(withinSkew, DefaultSkew) {
		t.Error("token within the 60s skew window should be treated as expired")
	}
}

func TestTokensFileSealedAndMode(t *testing.T) {
	home := t.TempDir()
	s := New(home)
	if err := s.Save(sample()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "tokens.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-access-token") {
		t.Fatal("token leaked in plaintext")
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("tokens.json mode = %o, want 600", fi.Mode().Perm())
		}
	}
}
