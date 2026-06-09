package oauth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
)

// doerFunc adapts a function to the Doer interface.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResp(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// routeDoer returns canned JSON for URLs containing the given needles.
func routeDoer(routes map[string]string, counts map[string]int) Doer {
	return doerFunc(func(r *http.Request) (*http.Response, error) {
		u := r.URL.String()
		for needle, body := range routes {
			if strings.Contains(u, needle) {
				if counts != nil {
					counts[needle]++
				}
				return jsonResp(body), nil
			}
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("not found"))}, nil
	})
}

func dcfg(overrides map[string]string) config.Config {
	env := map[string]string{
		"ADAPTER_BASE_URL": "https://adapter.example.com",
		"OKTA_CLIENT_ID":   "cid",
		"AGENT_ID":         "agent-1",
		"LOG_LEVEL":        "error",
	}
	for k, v := range overrides {
		env[k] = v
	}
	cfg, err := config.Load(env)
	if err != nil {
		panic(err)
	}
	return cfg
}

const (
	prmNeedle  = "oauth-protected-resource"
	asNeedle   = "oauth-authorization-server"
	oidcNeedle = "openid-configuration"
)

func TestResolvePRMtoAS(t *testing.T) {
	ClearDiscoveryCache()
	defer ClearDiscoveryCache()
	doer := routeDoer(map[string]string{
		prmNeedle: `{"authorization_servers":["https://as.example.com"]}`,
		asNeedle: `{"issuer":"https://as.example.com","authorization_endpoint":"https://as.example.com/authorize",` +
			`"token_endpoint":"https://as.example.com/token","registration_endpoint":"https://as.example.com/register"}`,
	}, nil)

	ep, err := ResolveEndpoints(context.Background(), dcfg(nil), doer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Issuer != "https://as.example.com" || ep.TokenEndpoint != "https://as.example.com/token" ||
		ep.AuthorizationEndpoint != "https://as.example.com/authorize" || ep.RegistrationEndpoint != "https://as.example.com/register" {
		t.Fatalf("unexpected endpoints: %+v", ep)
	}
}

func TestOktaIssuerOverride(t *testing.T) {
	ClearDiscoveryCache()
	defer ClearDiscoveryCache()
	doer := routeDoer(map[string]string{
		prmNeedle:  `{"authorization_servers":["https://as.example.com"]}`,
		asNeedle:   `{"authorization_endpoint":"https://as.example.com/authorize","token_endpoint":"https://as.example.com/token"}`,
		oidcNeedle: `{"issuer":"https://okta.example.com","authorization_endpoint":"https://okta.example.com/oauth2/v1/authorize","token_endpoint":"https://okta.example.com/oauth2/v1/token"}`,
	}, nil)

	ep, err := ResolveEndpoints(context.Background(), dcfg(map[string]string{"OKTA_ISSUER": "https://okta.example.com"}), doer, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ep.TokenEndpoint != "https://okta.example.com/oauth2/v1/token" || ep.Issuer != "https://okta.example.com" {
		t.Fatalf("override not applied: %+v", ep)
	}
}

func TestAlgUnsupportedWarns(t *testing.T) {
	ClearDiscoveryCache()
	defer ClearDiscoveryCache()
	doer := routeDoer(map[string]string{
		prmNeedle: `{"authorization_servers":["https://as.example.com"]}`,
		asNeedle:  `{"authorization_endpoint":"https://as.example.com/authorize","token_endpoint":"https://as.example.com/token","dpop_signing_alg_values_supported":["RS256","ES384"]}`,
	}, nil)

	buf := &bytes.Buffer{}
	logger := logx.NewWith(buf, "warn")
	if _, err := ResolveEndpoints(context.Background(), dcfg(nil), doer, logger); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "oauth.dpop.alg_unsupported") {
		t.Fatalf("expected alg_unsupported warning; got %q", buf.String())
	}
}

func TestDiscoveryCaches(t *testing.T) {
	ClearDiscoveryCache()
	defer ClearDiscoveryCache()
	counts := map[string]int{}
	doer := routeDoer(map[string]string{
		prmNeedle: `{"authorization_servers":["https://as.example.com"]}`,
		asNeedle:  `{"authorization_endpoint":"https://as.example.com/authorize","token_endpoint":"https://as.example.com/token"}`,
	}, counts)

	cfg := dcfg(nil)
	if _, err := ResolveEndpoints(context.Background(), cfg, doer, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveEndpoints(context.Background(), cfg, doer, nil); err != nil {
		t.Fatal(err)
	}
	if counts[prmNeedle] != 1 {
		t.Fatalf("expected 1 PRM fetch (cached), got %d", counts[prmNeedle])
	}
}

func TestResolveErrorsWithoutAuthServers(t *testing.T) {
	ClearDiscoveryCache()
	defer ClearDiscoveryCache()
	doer := routeDoer(map[string]string{prmNeedle: `{}`}, nil)
	if _, err := ResolveEndpoints(context.Background(), dcfg(nil), doer, nil); err == nil ||
		!strings.Contains(err.Error(), "authorization_servers") {
		t.Fatalf("expected authorization_servers error, got %v", err)
	}
}
