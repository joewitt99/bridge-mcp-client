// Package oauth implements OAuth endpoint discovery, the PKCE auth-code flow
// over a loopback redirect, and the DPoP token client. Go port of src/oauth/*.ts.
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/joewitt99/bridge-mcp-client/internal/config"
	"github.com/joewitt99/bridge-mcp-client/internal/logx"
)

// Doer is the slice of *http.Client the oauth package needs (eases testing).
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Endpoints are the resolved OAuth endpoints.
type Endpoints struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	RegistrationEndpoint  string
	DpopAlgs              []string
}

var (
	discoveryCacheMu sync.Mutex
	discoveryCache   = map[string]Endpoints{}
)

// ClearDiscoveryCache empties the in-memory cache (used by tests).
func ClearDiscoveryCache() {
	discoveryCacheMu.Lock()
	discoveryCache = map[string]Endpoints{}
	discoveryCacheMu.Unlock()
}

type protectedResourceMeta struct {
	AuthorizationServers []string `json:"authorization_servers"`
}

type authServerMeta struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	DpopSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported"`
}

// ResolveEndpoints resolves the OAuth endpoints via RFC 9728 → RFC 8414, with
// the optional OKTA_ISSUER override (openid-configuration). Results are cached
// per (ADAPTER_BASE_URL, OKTA_ISSUER) for the process lifetime.
func ResolveEndpoints(ctx context.Context, cfg config.Config, doer Doer, logger *logx.Logger) (Endpoints, error) {
	if logger == nil {
		logger = logx.Default
	}
	cacheKey := cfg.AdapterBaseURL + "|" + cfg.OktaIssuer
	discoveryCacheMu.Lock()
	if ep, ok := discoveryCache[cacheKey]; ok {
		discoveryCacheMu.Unlock()
		return ep, nil
	}
	discoveryCacheMu.Unlock()

	base := strings.TrimRight(cfg.AdapterBaseURL, "/")
	var prm protectedResourceMeta
	if err := getJSON(ctx, doer, base+"/.well-known/oauth-protected-resource", "protected-resource metadata", &prm); err != nil {
		return Endpoints{}, err
	}
	if len(prm.AuthorizationServers) == 0 {
		return Endpoints{}, fmt.Errorf("protected-resource metadata has no authorization_servers[0]")
	}
	asBase := strings.TrimRight(prm.AuthorizationServers[0], "/")

	var as authServerMeta
	if err := getJSON(ctx, doer, asBase+"/.well-known/oauth-authorization-server", "authorization-server metadata", &as); err != nil {
		return Endpoints{}, err
	}
	if as.AuthorizationEndpoint == "" || as.TokenEndpoint == "" {
		return Endpoints{}, fmt.Errorf("authorization-server metadata missing authorization_endpoint/token_endpoint")
	}

	ep := Endpoints{
		Issuer:                orDefault(as.Issuer, asBase),
		AuthorizationEndpoint: as.AuthorizationEndpoint,
		TokenEndpoint:         as.TokenEndpoint,
		RegistrationEndpoint:  as.RegistrationEndpoint,
		DpopAlgs:              as.DpopSigningAlgValuesSupported,
	}

	if cfg.OktaIssuer != "" {
		var oidc authServerMeta
		issuer := strings.TrimRight(cfg.OktaIssuer, "/")
		if err := getJSON(ctx, doer, issuer+"/.well-known/openid-configuration", "Okta openid-configuration", &oidc); err != nil {
			return Endpoints{}, err
		}
		if oidc.AuthorizationEndpoint == "" || oidc.TokenEndpoint == "" {
			return Endpoints{}, fmt.Errorf("Okta openid-configuration missing authorization_endpoint/token_endpoint")
		}
		ep.Issuer = orDefault(oidc.Issuer, issuer)
		ep.AuthorizationEndpoint = oidc.AuthorizationEndpoint
		ep.TokenEndpoint = oidc.TokenEndpoint
		if oidc.RegistrationEndpoint != "" {
			ep.RegistrationEndpoint = oidc.RegistrationEndpoint
		}
		if len(oidc.DpopSigningAlgValuesSupported) > 0 {
			ep.DpopAlgs = oidc.DpopSigningAlgValuesSupported
		}
	}

	if len(ep.DpopAlgs) > 0 && !contains(ep.DpopAlgs, cfg.DpopAlg) {
		logger.Warn("oauth.dpop.alg_unsupported", logx.Fields{
			"configured": cfg.DpopAlg,
			"supported":  ep.DpopAlgs,
		})
	}

	logger.Info("oauth.discovery.resolved", logx.Fields{
		"issuer_host":    hostOf(ep.Issuer),
		"authorize_host": hostOf(ep.AuthorizationEndpoint),
		"token_host":     hostOf(ep.TokenEndpoint),
		"override":       cfg.OktaIssuer != "",
	})

	discoveryCacheMu.Lock()
	discoveryCache[cacheKey] = ep
	discoveryCacheMu.Unlock()
	return ep, nil
}

func getJSON(ctx context.Context, doer Doer, rawURL, what string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := doer.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch %s (%s): %w", what, rawURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("failed to fetch %s (%s): HTTP %d", what, rawURL, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(dst); err != nil {
		return fmt.Errorf("failed to decode %s: %w", what, err)
	}
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "?"
	}
	return u.Host
}
