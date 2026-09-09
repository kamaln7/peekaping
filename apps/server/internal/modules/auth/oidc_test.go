package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"peekaping/internal/config"
	"peekaping/internal/modules/shared"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------- fake OP ---

// fakeOP is a minimal, spec-shaped OpenID Provider: discovery, JWKS, token and
// userinfo, with every knob the tests need to misbehave.
type fakeOP struct {
	*httptest.Server
	key   *rsa.PrivateKey
	keyID string

	// knobs
	noS256          bool
	issParamSupport bool
	signHS256       bool
	audiences       []string
	azp             string
	subject         string
	email           string
	emailVerified   *bool
	userInfo        map[string]any
	userInfo500     bool
	discoveryDown   bool

	lastVerifier string
}

func newFakeOP(t *testing.T) *fakeOP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	op := &fakeOP{key: key, keyID: "test-key", subject: "sub-1", email: "admin@example.com"}
	verified := true
	op.emailVerified = &verified

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if op.discoveryDown {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		doc := map[string]any{
			"issuer":                                op.URL,
			"authorization_endpoint":                op.URL + "/authorize",
			"token_endpoint":                        op.URL + "/token",
			"userinfo_endpoint":                     op.URL + "/userinfo",
			"jwks_uri":                              op.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256", "HS256"},
			"client_id_metadata_document_supported": true,
			"authorization_response_iss_parameter_supported": op.issParamSupport,
		}
		if !op.noS256 {
			doc["code_challenge_methods_supported"] = []string{"S256"}
		}
		writeJSON(w, doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA",
			"kid": op.keyID,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		op.lastVerifier = r.Form.Get("code_verifier")
		// The nonce is smuggled through the authorization code so the ID token
		// echoes back whatever the login handler generated.
		nonce := strings.TrimPrefix(r.Form.Get("code"), "code:")
		writeJSON(w, map[string]any{
			"access_token": "op-access-token",
			"token_type":   "Bearer",
			"id_token":     op.idToken(t, nonce),
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if op.userInfo500 || op.userInfo == nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(w, op.userInfo)
	})

	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)
	return op
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (op *fakeOP) idToken(t *testing.T, nonce string) string {
	t.Helper()
	aud := op.audiences
	if aud == nil {
		aud = []string{oidcTestClientID}
	}

	claims := jwt.MapClaims{
		"iss":   op.URL,
		"sub":   op.subject,
		"aud":   aud,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"nonce": nonce,
	}
	if op.azp != "" {
		claims["azp"] = op.azp
	}
	if op.email != "" {
		claims["email"] = op.email
	}
	if op.emailVerified != nil {
		claims["email_verified"] = *op.emailVerified
	}

	if op.signHS256 {
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("shared-secret"))
		require.NoError(t, err)
		return signed
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = op.keyID
	signed, err := token.SignedString(op.key)
	require.NoError(t, err)
	return signed
}

// ------------------------------------------------------------ test harness ---

const oidcTestClientID = "peekaping-test"

type harness struct {
	router  *gin.Engine
	repo    Repository
	service Service
	db      *bun.DB
	op      *fakeOP
}

func serviceOf(h *harness) Service { return h.service }

// mockAnyCtx matches any context argument the token maker passes through.
var mockAnyCtx = mock.Anything

func newOIDCTestDB(t *testing.T) *bun.DB {
	t.Helper()
	// A named shared in-memory database so concurrent connections see one table.
	sqldb, err := sql.Open(sqliteshim.ShimName,
		fmt.Sprintf("file:oidc%d?mode=memory&cache=shared", time.Now().UnixNano()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqldb.Close() })

	db := bun.NewDB(sqldb, sqlitedialect.New())
	_, err = db.NewCreateTable().Model((*sqlModel)(nil)).Exec(context.Background())
	require.NoError(t, err)
	_, err = db.ExecContext(context.Background(),
		"CREATE UNIQUE INDEX idx_users_oidc_subject ON users(oidc_subject)")
	require.NoError(t, err)
	return db
}

func newHarness(t *testing.T, op *fakeOP, mutate func(*config.Config)) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	db := newOIDCTestDB(t)
	repo := NewSQLRepository(db)
	logger := zap.NewNop().Sugar()

	settings := &MockSettingService{}
	for _, k := range []string{"ACCESS_TOKEN_SECRET_KEY", "REFRESH_TOKEN_SECRET_KEY"} {
		settings.On("GetByKey", mockAnyCtx, k).Return(&shared.SettingModel{Key: k, Value: "secret-" + k}, nil)
	}
	for _, k := range []string{"ACCESS_TOKEN_EXPIRED_IN", "REFRESH_TOKEN_EXPIRED_IN"} {
		settings.On("GetByKey", mockAnyCtx, k).Return(&shared.SettingModel{Key: k, Value: "15m"}, nil)
	}

	tokenMaker := NewTokenMaker(settings, logger)
	service := NewService(repo, tokenMaker, logger)

	cfg := &config.Config{
		ClientURL:       "https://peekaping.example",
		OIDCIssuer:      op.URL,
		OIDCClientID:    oidcTestClientID,
		OIDCScopes:      "openid email",
		OIDCRedirectURL: "https://peekaping.example/api/v1/auth/oidc/callback",
	}
	if mutate != nil {
		mutate(cfg)
	}

	oidcProvider, err := NewOIDC(cfg, logger)
	require.NoError(t, err)

	controller := NewController(service, tokenMaker, oidcProvider, logger)

	router := gin.New()
	group := router.Group("/api/v1/auth")
	group.GET("/oidc/login", controller.OIDCLogin)
	group.GET("/oidc/callback", controller.OIDCCallback)
	group.GET("/oidc/status", controller.OIDCStatus)
	group.GET("/oidc/client", controller.OIDCClient)

	return &harness{router: router, repo: repo, service: service, db: db, op: op}
}

// signIn walks the whole flow and returns the final redirect Location.
func (h *harness) signIn(t *testing.T) string {
	t.Helper()
	loc, cookie, ok := h.startLogin(t)
	if !ok {
		return loc
	}
	authURL, err := url.Parse(loc)
	require.NoError(t, err)
	q := authURL.Query()
	return h.callback(t, "code:"+q.Get("nonce"), q.Get("state"), cookie, "")
}

func (h *harness) startLogin(t *testing.T) (location string, cookie *http.Cookie, ok bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		return loc, nil, false
	}
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "oidc_state") && c.Value != "" {
			return loc, c, true
		}
	}
	t.Fatalf("no state cookie set, location=%s", loc)
	return "", nil, false
}

func (h *harness) callback(t *testing.T, code, state string, cookie *http.Cookie, extra string) string {
	t.Helper()
	target := fmt.Sprintf("/api/v1/auth/oidc/callback?code=%s&state=%s%s",
		url.QueryEscape(code), url.QueryEscape(state), extra)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	// The state cookie is single-use and must be cleared on every outcome.
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "oidc_state") && c.MaxAge < 0 {
			cleared = true
		}
	}
	assert.True(t, cleared, "callback must clear the state cookie")

	return rec.Header().Get("Location")
}

func assertLoggedIn(t *testing.T, location string) {
	t.Helper()
	assert.Contains(t, location, "#access_token=", "expected tokens, got %s", location)
	assert.Contains(t, location, "refresh_token=")
}

func assertRejected(t *testing.T, location, code string) {
	t.Helper()
	assert.Contains(t, location, "error="+code, "expected %s, got %s", code, location)
}

func (h *harness) mustFindByEmail(t *testing.T, email string) *Model {
	t.Helper()
	user, err := h.repo.FindByEmail(context.Background(), email)
	require.NoError(t, err)
	require.NotNil(t, user)
	return user
}

func (h *harness) seedAdmin(t *testing.T, email string) *Model {
	t.Helper()
	user, err := h.repo.Create(context.Background(), &Model{
		Email: email, Password: "$2a$10$fakehash", Active: true,
	})
	require.NoError(t, err)
	return user
}

// ------------------------------------------------------------------ tests ---

func TestOIDC_BootstrapCreatesBoundAdmin(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)

	assertLoggedIn(t, h.signIn(t))

	user := h.mustFindByEmail(t, "admin@example.com")
	assert.Equal(t, OIDCSubjectKey(op.URL, "sub-1"), user.OIDCSubject)
	assert.Empty(t, user.Password, "bootstrapped admin has no password")

	count, err := h.repo.FindAllCount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	assert.NotEmpty(t, op.lastVerifier, "PKCE verifier must be sent to the token endpoint")
}

func TestOIDC_LinksExistingPasswordAdmin(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	existing := h.seedAdmin(t, "admin@example.com")

	assertLoggedIn(t, h.signIn(t))

	user := h.mustFindByEmail(t, "admin@example.com")
	assert.Equal(t, existing.ID, user.ID, "linked, not replaced")
	assert.Equal(t, OIDCSubjectKey(op.URL, "sub-1"), user.OIDCSubject)
}

func TestOIDC_BoundAdminLogsInAfterEmailChange(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	assertLoggedIn(t, h.signIn(t))

	// The OP moved the address; the binding is by subject, so nothing changes.
	op.email = "someone.else@example.com"
	assertLoggedIn(t, h.signIn(t))

	assert.Equal(t, "admin@example.com", h.mustFindByEmail(t, "admin@example.com").Email)
}

func TestOIDC_BoundLoginWithoutEmailClaimAndUserInfoDown(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	assertLoggedIn(t, h.signIn(t))

	op.email = ""
	op.emailVerified = nil
	op.userInfo500 = true
	assertLoggedIn(t, h.signIn(t))
}

func TestOIDC_DifferentSubjectWithAdminEmailIsRejected(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	assertLoggedIn(t, h.signIn(t))

	// Same verified email, different subject: cannot take over the bound admin.
	op.subject = "sub-2"
	assertRejected(t, h.signIn(t), "oidc_not_admin")
}

func TestOIDC_SubjectsDifferingOnlyInCaseAreDistinct(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	op.subject = "Alice"
	assertLoggedIn(t, h.signIn(t))

	op.subject = "alice"
	// A case-insensitive collation would wrongly match the bound row; the Go-side
	// re-comparison must send this down the link path, which then refuses.
	assertRejected(t, h.signIn(t), "oidc_not_admin")
}

func TestOIDC_ConcurrentFirstLinksYieldOneBinding(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	user := h.seedAdmin(t, "admin@example.com")

	var mu sync.Mutex
	results := map[string]int{}
	var wg sync.WaitGroup
	for _, sub := range []string{"sub-a", "sub-b"} {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			// Each goroutine drives its own subject through the service directly:
			// the HTTP layer shares one fakeOP subject field.
			_, err := serviceOf(h).LinkOIDC(context.Background(), OIDCIdentity{
				Issuer: op.URL, Subject: sub, Email: "admin@example.com", EmailVerified: true,
			})
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				results["ok"]++
			} else {
				results["rejected"]++
			}
		}(sub)
	}
	wg.Wait()

	assert.Equal(t, 1, results["ok"], "exactly one link may win")
	assert.Equal(t, 1, results["rejected"])

	stored, err := h.repo.FindByID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Contains(t, []string{OIDCSubjectKey(op.URL, "sub-a"), OIDCSubjectKey(op.URL, "sub-b")}, stored.OIDCSubject)
}

func TestOIDC_ConcurrentBootstrapsYieldOneUser(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)

	var wg sync.WaitGroup
	for i, email := range []string{"one@example.com", "two@example.com"} {
		wg.Add(1)
		go func(i int, email string) {
			defer wg.Done()
			_, _ = serviceOf(h).LinkOIDC(context.Background(), OIDCIdentity{
				Issuer: op.URL, Subject: fmt.Sprintf("sub-%d", i), Email: email, EmailVerified: true,
			})
		}(i, email)
	}
	wg.Wait()

	count, err := h.repo.FindAllCount(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "only one admin may be bootstrapped")
}

func TestOIDC_EmailOnlyInUserInfo(t *testing.T) {
	op := newFakeOP(t)
	op.email = ""
	op.emailVerified = nil
	op.userInfo = map[string]any{"sub": "sub-1", "email": "admin@example.com", "email_verified": true}

	h := newHarness(t, op, nil)
	assertLoggedIn(t, h.signIn(t))
	assert.Equal(t, "admin@example.com", h.mustFindByEmail(t, "admin@example.com").Email)
}

func TestOIDC_EmailWithoutVerifiedFlagFallsBackToUserInfo(t *testing.T) {
	op := newFakeOP(t)
	op.emailVerified = nil // email present, email_verified absent
	op.userInfo = map[string]any{"sub": "sub-1", "email": "admin@example.com", "email_verified": true}

	h := newHarness(t, op, nil)
	assertLoggedIn(t, h.signIn(t))
}

func TestOIDC_UserInfoSubjectMismatchIsRejected(t *testing.T) {
	op := newFakeOP(t)
	op.email = ""
	op.emailVerified = nil
	op.userInfo = map[string]any{"sub": "someone-else", "email": "admin@example.com", "email_verified": true}

	h := newHarness(t, op, nil)
	assertRejected(t, h.signIn(t), "oidc_failed")
}

func TestOIDC_MissingEmailVerifiedIsRejected(t *testing.T) {
	op := newFakeOP(t)
	op.emailVerified = nil
	op.userInfo = map[string]any{"sub": "sub-1", "email": "admin@example.com"}

	h := newHarness(t, op, nil)
	assertRejected(t, h.signIn(t), "oidc_failed")
}

func TestOIDC_UnverifiedEmailIsRejected(t *testing.T) {
	op := newFakeOP(t)
	no := false
	op.emailVerified = &no

	h := newHarness(t, op, nil)
	assertRejected(t, h.signIn(t), "oidc_failed")
}

func TestOIDC_BadStateIsRejected(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)

	loc, cookie, ok := h.startLogin(t)
	require.True(t, ok)
	nonce := mustQuery(t, loc, "nonce")

	assertRejected(t, h.callback(t, "code:"+nonce, "not-the-state", cookie, ""), "oidc_failed")
}

func TestOIDC_MissingStateCookieIsRejected(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)

	loc, _, ok := h.startLogin(t)
	require.True(t, ok)
	assertRejected(t, h.callback(t, "code:"+mustQuery(t, loc, "nonce"), mustQuery(t, loc, "state"), nil, ""), "oidc_failed")
}

func TestOIDC_DiscoveryFailureRecoversOnRetry(t *testing.T) {
	op := newFakeOP(t)
	op.discoveryDown = true
	h := newHarness(t, op, nil)

	loc, _, ok := h.startLogin(t)
	require.False(t, ok)
	assertRejected(t, loc, "oidc_failed")

	// A failed discovery is not cached: the next attempt tries again.
	op.discoveryDown = false
	assertLoggedIn(t, h.signIn(t))
}

func TestOIDC_ProviderWithoutS256IsRejected(t *testing.T) {
	op := newFakeOP(t)
	op.noS256 = true
	h := newHarness(t, op, nil)

	loc, _, ok := h.startLogin(t)
	require.False(t, ok)
	assertRejected(t, loc, "oidc_failed")
}

func TestOIDC_IssResponseParameterMismatchIsRejected(t *testing.T) {
	op := newFakeOP(t)
	op.issParamSupport = true
	h := newHarness(t, op, nil)

	loc, cookie, ok := h.startLogin(t)
	require.True(t, ok)

	assertRejected(t, h.callback(t, "code:"+mustQuery(t, loc, "nonce"), mustQuery(t, loc, "state"),
		cookie, "&iss=https://evil.example"), "oidc_failed")

	// The matching iss is accepted.
	loc, cookie, ok = h.startLogin(t)
	require.True(t, ok)
	assertLoggedIn(t, h.callback(t, "code:"+mustQuery(t, loc, "nonce"), mustQuery(t, loc, "state"),
		cookie, "&iss="+url.QueryEscape(op.URL)))
}

func TestOIDC_MultipleAudiencesWithoutAZPIsRejected(t *testing.T) {
	op := newFakeOP(t)
	op.audiences = []string{oidcTestClientID, "another-client"}
	h := newHarness(t, op, nil)
	assertRejected(t, h.signIn(t), "oidc_failed")

	// With a matching azp it is accepted (Core 3.1.3.7).
	op.azp = oidcTestClientID
	assertLoggedIn(t, h.signIn(t))
}

func TestOIDC_HS256IDTokenIsRejected(t *testing.T) {
	op := newFakeOP(t)
	op.signHS256 = true
	h := newHarness(t, op, nil)
	assertRejected(t, h.signIn(t), "oidc_failed")
}

func TestOIDC_NonLoopbackHTTPIssuerFailsBoot(t *testing.T) {
	logger := zap.NewNop().Sugar()

	_, err := NewOIDC(&config.Config{
		ClientURL:  "https://peekaping.example",
		OIDCIssuer: "http://op.example.com",
	}, logger)
	assert.Error(t, err)

	// Loopback http is allowed for development.
	_, err = NewOIDC(&config.Config{
		ClientURL:       "http://localhost:5173",
		OIDCIssuer:      "http://localhost:9000",
		OIDCClientID:    "x",
		OIDCScopes:      "openid email",
		OIDCRedirectURL: "http://localhost:8034/api/v1/auth/oidc/callback",
	}, logger)
	assert.NoError(t, err)
}

func TestOIDC_ConfigDerivation(t *testing.T) {
	logger := zap.NewNop().Sugar()

	// CIMD mode: client_id is derived from the redirect URL and equals the URL of
	// the document we serve.
	o, err := NewOIDC(&config.Config{
		ClientURL:  "https://peekaping.example",
		OIDCIssuer: "https://op.example",
		OIDCScopes: "openid email",
	}, logger)
	require.NoError(t, err)
	assert.True(t, o.CIMD)
	assert.Equal(t, "https://peekaping.example/api/v1/auth/oidc/client", o.ClientID)
	assert.Equal(t, o.ClientID, o.clientMetadataDocument()["client_id"])
	assert.Equal(t, "__Host-oidc_state", o.stateCookieName())

	// A secret without a client ID is refused: the draft forbids shared secrets.
	_, err = NewOIDC(&config.Config{
		ClientURL:        "https://peekaping.example",
		OIDCIssuer:       "https://op.example",
		OIDCScopes:       "openid email",
		OIDCClientSecret: "shhh",
	}, logger)
	assert.Error(t, err)

	// Scopes must contain openid.
	_, err = NewOIDC(&config.Config{
		ClientURL:    "https://peekaping.example",
		OIDCIssuer:   "https://op.example",
		OIDCClientID: "x",
		OIDCScopes:   "email",
	}, logger)
	assert.Error(t, err)

	// Unset issuer means disabled, not an error.
	o, err = NewOIDC(&config.Config{ClientURL: "https://peekaping.example"}, logger)
	require.NoError(t, err)
	assert.False(t, o.Enabled())
}

func TestOIDC_DisabledEndpointsAre404(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, func(c *config.Config) { c.OIDCIssuer = "" })

	for _, path := range []string{"/api/v1/auth/oidc/login", "/api/v1/auth/oidc/client"} {
		rec := httptest.NewRecorder()
		h.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		assert.Equal(t, http.StatusNotFound, rec.Code, path)
	}

	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/status", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"enabled":false}`, rec.Body.String())
}

func TestOIDC_ProviderErrorResponseIsReported(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/oidc/callback?error=access_denied&error_description=nope", nil)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)
	assertRejected(t, rec.Header().Get("Location"), "oidc_failed")
}

func TestUpdatePassword_BootstrappedAdminHasNoCurrentPassword(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, nil)
	assertLoggedIn(t, h.signIn(t))

	user := h.mustFindByEmail(t, "admin@example.com")
	require.Empty(t, user.Password)

	err := serviceOf(h).UpdatePassword(context.Background(), user.ID, UpdatePasswordDto{
		CurrentPassword: "anything", NewPassword: "Sup3rSecret!",
	})
	require.NoError(t, err)

	assert.NotEmpty(t, h.mustFindByEmail(t, "admin@example.com").Password)
}

func mustQuery(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	v := u.Query().Get(key)
	require.NotEmpty(t, v, "missing %s in %s", key, rawURL)
	return v
}

func TestCreateFirst(t *testing.T) {
	ctx := context.Background()
	repo := NewSQLRepository(newOIDCTestDB(t))

	created, user, err := repo.CreateFirst(ctx, &Model{Email: "first@example.com", Active: true})
	require.NoError(t, err)
	require.True(t, created)
	assert.Equal(t, bootstrapUserID, user.ID, "the bootstrap admin has a fixed primary key")

	// A second bootstrap, different email: refused, and nothing is written.
	created, _, err = repo.CreateFirst(ctx, &Model{Email: "second@example.com", Active: true})
	require.NoError(t, err)
	assert.False(t, created)

	count, err := repo.FindAllCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestCreateFirst_LegacyAdminKeepsItsRandomID(t *testing.T) {
	ctx := context.Background()
	repo := NewSQLRepository(newOIDCTestDB(t))

	// An admin registered before this change has a random ID, which the fixed
	// bootstrap key would not collide with: the count check is what refuses here.
	legacy, err := repo.Create(ctx, &Model{Email: "legacy@example.com", Password: "hash", Active: true})
	require.NoError(t, err)
	require.NotEqual(t, bootstrapUserID, legacy.ID)

	created, _, err := repo.CreateFirst(ctx, &Model{Email: "new@example.com", Active: true})
	require.NoError(t, err)
	assert.False(t, created)

	count, err := repo.FindAllCount(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestIsUniqueViolation_MatchesTheDriverError(t *testing.T) {
	ctx := context.Background()
	db := newOIDCTestDB(t)
	repo := NewSQLRepository(db)

	created, _, err := repo.CreateFirst(ctx, &Model{Email: "first@example.com", Active: true})
	require.NoError(t, err)
	require.True(t, created)

	// The count check normally short-circuits, so drive the collision the way a
	// concurrent bootstrap would: insert the fixed key straight into the table.
	_, err = db.NewInsert().Model(&sqlModel{
		ID: bootstrapUserID, Email: "second@example.com", Active: true,
	}).Exec(ctx)
	require.Error(t, err)
	assert.True(t, isUniqueViolation(err),
		"the driver's unique violation must be recognised, got: %v", err)
}

func TestOIDC_ClientMetadataDocumentIsServedAndCacheable(t *testing.T) {
	op := newFakeOP(t)
	h := newHarness(t, op, func(c *config.Config) { c.OIDCClientID = "" })

	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/client", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	// An OP has to persist the client it resolves from this document, so a
	// no-store response makes the whole CIMD mode unusable.
	cc := rec.Header().Get("Cache-Control")
	assert.NotContains(t, cc, "no-store")
	assert.Contains(t, cc, "max-age=")

	var doc map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, "https://peekaping.example/api/v1/auth/oidc/client", doc["client_id"])
	assert.Equal(t, "none", doc["token_endpoint_auth_method"])
	assert.Equal(t, []any{"code"}, doc["response_types"])
}
