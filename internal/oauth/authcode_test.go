package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
)

func TestGeneratePKCE(t *testing.T) {
	v, c, err := GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(v))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); c != want {
		t.Fatalf("challenge != S256(verifier): %s != %s", c, want)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Fatalf("verifier length %d out of [43,128]", len(v))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(v) {
		t.Fatalf("verifier not base64url: %q", v)
	}
	v2, _, _ := GeneratePKCE()
	if v == v2 {
		t.Fatal("two verifiers should differ")
	}
}

func acfg() config.Config {
	return dcfg(map[string]string{"OKTA_REDIRECT_PORT": "0"})
}

var ep = Endpoints{
	Issuer:                "https://okta.example.com",
	AuthorizationEndpoint: "https://okta.example.com/oauth2/v1/authorize",
	TokenEndpoint:         "https://okta.example.com/oauth2/v1/token",
}

// callbackOpener drives the loopback by hitting /callback with the given query.
func callbackOpener(build func(state string) url.Values) Opener {
	return func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		cb, _ := url.Parse(u.Query().Get("redirect_uri"))
		cb.RawQuery = build(u.Query().Get("state")).Encode()
		resp, err := http.Get(cb.String())
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
}

var loopbackRE = regexp.MustCompile(`^http://127\.0\.0\.1:\d+/callback$`)

func TestAuthorizeSuccess(t *testing.T) {
	opener := callbackOpener(func(state string) url.Values {
		return url.Values{"state": {state}, "code": {"the-code"}}
	})
	res, err := Authorize(acfg(), ep, AuthorizeOptions{Opener: opener})
	if err != nil {
		t.Fatal(err)
	}
	if res.Code != "the-code" {
		t.Fatalf("code = %q", res.Code)
	}
	if !loopbackRE.MatchString(res.RedirectURI) {
		t.Fatalf("redirectURI = %q", res.RedirectURI)
	}
	if len(res.Verifier) < 43 {
		t.Fatalf("verifier too short: %q", res.Verifier)
	}
}

func TestAuthorizeURLParams(t *testing.T) {
	var seen *url.URL
	opener := func(authURL string) error {
		seen, _ = url.Parse(authURL)
		cb, _ := url.Parse(seen.Query().Get("redirect_uri"))
		cb.RawQuery = url.Values{"state": {seen.Query().Get("state")}, "code": {"x"}}.Encode()
		resp, err := http.Get(cb.String())
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	if _, err := Authorize(acfg(), ep, AuthorizeOptions{Opener: opener}); err != nil {
		t.Fatal(err)
	}
	q := seen.Query()
	if seen.Scheme+"://"+seen.Host+seen.Path != "https://okta.example.com/oauth2/v1/authorize" {
		t.Errorf("authorize endpoint = %q", seen.String())
	}
	if q.Get("response_type") != "code" || q.Get("client_id") != "cid" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("state") == "" || !loopbackRE.MatchString(q.Get("redirect_uri")) {
		t.Errorf("bad authorize params: %v", q)
	}
}

func TestAuthorizeStateMismatch(t *testing.T) {
	opener := callbackOpener(func(string) url.Values {
		return url.Values{"state": {"WRONG"}, "code": {"x"}}
	})
	_, err := Authorize(acfg(), ep, AuthorizeOptions{Opener: opener})
	if err == nil || !regexpContains(err.Error(), "state mismatch") {
		t.Fatalf("expected state mismatch error, got %v", err)
	}
}

func TestAuthorizeErrorParam(t *testing.T) {
	opener := callbackOpener(func(state string) url.Values {
		return url.Values{"state": {state}, "error": {"access_denied"}, "error_description": {"user said no"}}
	})
	_, err := Authorize(acfg(), ep, AuthorizeOptions{Opener: opener})
	if err == nil || !regexpContains(err.Error(), "access_denied") {
		t.Fatalf("expected access_denied error, got %v", err)
	}
}

func TestAuthorizeTimeout(t *testing.T) {
	opener := func(string) error { return nil } // never hits the callback
	_, err := Authorize(acfg(), ep, AuthorizeOptions{Opener: opener, Timeout: 50 * time.Millisecond})
	if err == nil || !regexpContains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func regexpContains(s, sub string) bool {
	return regexp.MustCompile(regexp.QuoteMeta(sub)).MatchString(s)
}
