package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"peekaping/internal/config"
	"strings"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

const (
	oidcCallbackPath = "/api/v1/auth/oidc/callback"
	oidcStateTTL     = 10 * 60 // seconds
)

// asymmetric only: a public client has no secret to verify HS* with, and for a
// confidential one a leaked client secret would be enough to forge ID tokens.
var oidcSigningAlgs = []string{
	gooidc.RS256, gooidc.RS384, gooidc.RS512,
	gooidc.PS256, gooidc.PS384, gooidc.PS512,
	gooidc.ES256, gooidc.ES384, gooidc.ES512,
	gooidc.EdDSA,
}

// providerMeta holds the discovery fields go-oidc does not expose itself.
type providerMeta struct {
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	IssParameterSupported             bool     `json:"authorization_response_iss_parameter_supported"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
}

// OIDC is the OpenID Connect login provider. Zero value (Issuer == "") is the
// disabled state; every handler 404s then.
type OIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// CIMD mode: the client ID is a URL pointing at our own metadata document.
	CIMD      bool
	ClientURL string

	logger *zap.SugaredLogger

	// Discovery is lazy and retried: a mutex rather than sync.Once so an OP that
	// is down at boot does not disable OIDC until the next restart.
	mu       sync.Mutex
	provider *gooidc.Provider
	meta     providerMeta
}

func NewOIDC(cfg *config.Config, logger *zap.SugaredLogger) (*OIDC, error) {
	o := &OIDC{logger: logger.Named("[oidc]"), ClientURL: strings.TrimRight(cfg.ClientURL, "/")}
	if cfg.OIDCIssuer == "" {
		return o, nil
	}

	o.Issuer = strings.TrimRight(cfg.OIDCIssuer, "/")
	o.ClientSecret = cfg.OIDCClientSecret
	o.RedirectURL = cfg.OIDCRedirectURL
	if o.RedirectURL == "" {
		o.RedirectURL = o.ClientURL + oidcCallbackPath
	}

	if err := validateOIDCURL("OIDC_ISSUER", o.Issuer); err != nil {
		return nil, err
	}
	if err := validateOIDCURL("OIDC_REDIRECT_URL", o.RedirectURL); err != nil {
		return nil, err
	}

	o.Scopes = strings.Fields(cfg.OIDCScopes)
	if len(o.Scopes) == 0 {
		o.Scopes = []string{gooidc.ScopeOpenID, "email"}
	}
	if !contains(o.Scopes, gooidc.ScopeOpenID) {
		return nil, fmt.Errorf("OIDC_SCOPES must contain %q", gooidc.ScopeOpenID)
	}

	o.ClientID = cfg.OIDCClientID
	if o.ClientID == "" {
		// Client ID Metadata Document mode: the client ID is the URL of the
		// document we serve, which must be derivable from the redirect URL.
		if !strings.HasSuffix(o.RedirectURL, "/auth/oidc/callback") {
			return nil, fmt.Errorf("OIDC_CLIENT_ID is unset and OIDC_REDIRECT_URL does not end in /auth/oidc/callback, so the client metadata document URL cannot be derived")
		}
		if o.ClientSecret != "" {
			return nil, fmt.Errorf("OIDC_CLIENT_SECRET is not supported without OIDC_CLIENT_ID: the client ID metadata document draft forbids shared secrets")
		}
		o.CIMD = true
		o.ClientID = strings.TrimSuffix(o.RedirectURL, "/callback") + "/client"
	}

	return o, nil
}

func (o *OIDC) Enabled() bool { return o.Issuer != "" }

// validateOIDCURL requires https, except on loopback hosts for development.
func validateOIDCURL(name, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%s must use https (http is only allowed on localhost)", name)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// discover fetches and caches the provider metadata. A failure is not cached, so
// the next login attempt retries; password login is never affected.
func (o *OIDC) discover(ctx context.Context) (*gooidc.Provider, providerMeta, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.provider != nil {
		return o.provider, o.meta, nil
	}

	// go-oidc rejects a document whose issuer differs from the configured one.
	provider, err := gooidc.NewProvider(ctx, o.Issuer)
	if err != nil {
		return nil, providerMeta{}, fmt.Errorf("oidc discovery failed: %w", err)
	}

	var meta providerMeta
	if err := provider.Claims(&meta); err != nil {
		return nil, providerMeta{}, fmt.Errorf("oidc discovery document could not be parsed: %w", err)
	}
	if !contains(meta.CodeChallengeMethodsSupported, "S256") {
		return nil, providerMeta{}, fmt.Errorf("OP does not advertise PKCE S256")
	}
	if o.CIMD && !meta.ClientIDMetadataDocumentSupported {
		return nil, providerMeta{}, fmt.Errorf("OP does not advertise client_id_metadata_document_supported; register a client and set OIDC_CLIENT_ID")
	}

	o.provider, o.meta = provider, meta
	return provider, meta, nil
}

func (o *OIDC) oauth2Config(provider *gooidc.Provider) *oauth2.Config {
	endpoint := provider.Endpoint()
	// Never let x/oauth2 auto-detect and retry with client_secret_post.
	endpoint.AuthStyle = oauth2.AuthStyleInHeader

	return &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  o.RedirectURL,
		Scopes:       o.Scopes,
	}
}

func (o *OIDC) verifier(provider *gooidc.Provider) *gooidc.IDTokenVerifier {
	return provider.Verifier(&gooidc.Config{
		ClientID:             o.ClientID,
		SupportedSigningAlgs: oidcSigningAlgs,
	})
}

// clientMetadataDocument is the CIMD document served at /auth/oidc/client. The
// client_id is emitted verbatim: the draft compares it to the document URL by
// simple string comparison.
func (o *OIDC) clientMetadataDocument() map[string]any {
	return map[string]any{
		"client_id":                  o.ClientID,
		"client_name":                "Peekaping",
		"redirect_uris":              []string{o.RedirectURL},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"scope":                      strings.Join(o.Scopes, " "),
	}
}

// secureCookies reports whether the callback URL is https, which decides both
// the Secure flag and whether the __Host- cookie prefix can be used.
func (o *OIDC) secureCookies() bool {
	return strings.HasPrefix(o.RedirectURL, "https://")
}

func (o *OIDC) stateCookieName() string {
	if o.secureCookies() {
		return "__Host-oidc_state"
	}
	return "oidc_state"
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// oidcClaims are the claims we care about, from the ID token or from UserInfo.
type oidcClaims struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	AZP           string `json:"azp"`
}
