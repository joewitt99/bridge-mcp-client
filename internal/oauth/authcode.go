package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
)

// AuthCodeResult is the output of the authorize step (consumed by ExchangeCode).
type AuthCodeResult struct {
	Code        string
	RedirectURI string
	Verifier    string
}

// Opener opens a URL in the user's browser (injectable for tests).
type Opener func(url string) error

// GeneratePKCE returns a PKCE verifier (43-char base64url) and its S256
// challenge = base64url(sha256(verifier)).
func GeneratePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// AuthorizeOptions configure Authorize (all optional).
type AuthorizeOptions struct {
	Opener  Opener
	Timeout time.Duration
	Logger  *logx.Logger
}

const closePage = `<!doctype html><html><head><meta charset="utf-8"><title>okta-mcp-bridge</title></head>` +
	`<body style="font-family:system-ui;padding:2rem"><p>%s</p>` +
	`<p>You may close this tab and return to your terminal.</p></body></html>`

// Authorize runs the PKCE authorization-code flow over a 127.0.0.1 loopback
// redirect and returns the captured code. There is NO DPoP at this step.
func Authorize(cfg config.Config, ep Endpoints, opts AuthorizeOptions) (AuthCodeResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = logx.Default
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 300 * time.Second
	}
	opener := opts.Opener
	if opener == nil {
		opener = defaultOpener
	}

	verifier, challenge, err := GeneratePKCE()
	if err != nil {
		return AuthCodeResult{}, err
	}
	state, err := randomState()
	if err != nil {
		return AuthCodeResult{}, err
	}

	if cfg.OktaRedirectPort == 0 {
		// Okta matches the redirect URI exactly, including the port, and does
		// not honor ephemeral ports — even with a wildcard registered.
		logger.Warn("oauth.authorize.ephemeral_port", logx.Fields{
			"note": "Okta requires a fixed, pre-registered redirect port; set OKTA_REDIRECT_PORT to match the redirect URI registered in Okta",
		})
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.OktaRedirectPort))
	if err != nil {
		return AuthCodeResult{}, fmt.Errorf("loopback listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	type outcome struct {
		code string
		err  error
	}
	resultCh := make(chan outcome, 1)
	var once sync.Once
	settle := func(o outcome) { once.Do(func() { resultCh <- o }) }

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		page := func(status int, msg string) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(status)
			fmt.Fprintf(w, closePage, msg)
		}
		if e := q.Get("error"); e != "" {
			msg := e
			if d := q.Get("error_description"); d != "" {
				msg = e + " — " + d
			}
			page(http.StatusBadRequest, "Authorization failed.")
			settle(outcome{err: fmt.Errorf("authorization failed: %s", msg)})
			return
		}
		if q.Get("state") != state {
			page(http.StatusBadRequest, "Authorization failed (state mismatch).")
			settle(outcome{err: fmt.Errorf("authorization failed: state mismatch")})
			return
		}
		code := q.Get("code")
		if code == "" {
			page(http.StatusBadRequest, "Authorization failed (no code).")
			settle(outcome{err: fmt.Errorf("authorization failed: no code in callback")})
			return
		}
		logger.Info("oauth.authorize.code_received", nil)
		page(http.StatusOK, "Authorization complete.")
		settle(outcome{code: code})
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	authURL := buildAuthorizeURL(cfg, ep, redirectURI, state, challenge)
	logger.Info("oauth.authorize.started", logx.Fields{"redirect_port": port})
	go func() {
		if err := opener(authURL); err != nil {
			logger.Warn("oauth.authorize.opener_failed", logx.Fields{"error": err.Error()})
			fmt.Fprintf(os.Stderr, "\nOpen this URL in your browser to authorize:\n\n%s\n\n", authURL)
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var res outcome
	select {
	case res = <-resultCh:
	case <-timer.C:
		logger.Warn("oauth.authorize.failed", logx.Fields{"reason": "timeout"})
		res = outcome{err: fmt.Errorf("authorization timed out")}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	if res.err != nil {
		return AuthCodeResult{}, res.err
	}
	return AuthCodeResult{Code: res.code, RedirectURI: redirectURI, Verifier: verifier}, nil
}

func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func buildAuthorizeURL(cfg config.Config, ep Endpoints, redirectURI, state, challenge string) string {
	u, err := url.Parse(ep.AuthorizationEndpoint)
	if err != nil {
		// Fall back to a best-effort string; discovery already validated this.
		return ep.AuthorizationEndpoint
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.OktaClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", cfg.OktaScopes)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

func defaultOpener(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		// rundll32 avoids cmd.exe's `&`-in-URL pitfalls with OAuth query strings.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
}
