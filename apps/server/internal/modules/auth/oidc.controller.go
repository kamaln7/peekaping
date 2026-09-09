package auth

import (
	"errors"
	"net/http"
	"net/url"
	"peekaping/internal/modules/bruteforce"
	"peekaping/internal/utils"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// OIDCStatusResponse tells the login page whether to render the SSO button.
type OIDCStatusResponse struct {
	Enabled bool `json:"enabled"`
}

// @Router	/auth/oidc/status [get]
// @Summary	Whether OIDC login is configured
// @Tags		Auth
// @Produce	json
// @Success	200 {object} OIDCStatusResponse
func (c *Controller) OIDCStatus(ctx *gin.Context) {
	// Reported from config, not from discovery: an OP outage must not hide the
	// button, it only makes a login attempt fail.
	ctx.JSON(http.StatusOK, OIDCStatusResponse{Enabled: c.oidc.Enabled()})
}

// @Router	/auth/oidc/client [get]
// @Summary	OAuth client ID metadata document
// @Tags		Auth
// @Produce	json
// @Success	200 {object} map[string]interface{}
// @Failure	404 {object} utils.APIError[any]
func (c *Controller) OIDCClient(ctx *gin.Context) {
	if !c.oidc.Enabled() || !c.oidc.CIMD {
		ctx.JSON(http.StatusNotFound, utils.NewFailResponse("not found"))
		return
	}
	// An explicit lifetime rather than the provider's default. It must never be
	// no-store: an OP has to persist the client it resolves from this document.
	ctx.Header("Cache-Control", "public, max-age=3600")
	ctx.JSON(http.StatusOK, c.oidc.clientMetadataDocument())
}

// @Router	/auth/oidc/login [get]
// @Summary	Start the OIDC authorization code flow
// @Tags		Auth
// @Success	302
// @Failure	404 {object} utils.APIError[any]
func (c *Controller) OIDCLogin(ctx *gin.Context) {
	if !c.oidc.Enabled() {
		ctx.JSON(http.StatusNotFound, utils.NewFailResponse("not found"))
		return
	}

	provider, _, err := c.oidc.discover(ctx)
	if err != nil {
		c.logger.Errorw("oidc discovery failed", "error", err)
		c.redirectError(ctx, "oidc_failed")
		return
	}

	state, err := randomString()
	if err != nil {
		c.redirectError(ctx, "oidc_failed")
		return
	}
	nonce, err := randomString()
	if err != nil {
		c.redirectError(ctx, "oidc_failed")
		return
	}
	verifier := oauth2.GenerateVerifier()

	cookie, err := c.tokenMaker.CreateOIDCStateToken(ctx, state, nonce, verifier, oidcStateTTL*time.Second)
	if err != nil {
		c.logger.Errorw("failed to sign oidc state", "error", err)
		c.redirectError(ctx, "oidc_failed")
		return
	}
	c.setStateCookie(ctx, cookie, oidcStateTTL)

	url := c.oidc.oauth2Config(provider).AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	ctx.Redirect(http.StatusFound, url)
}

// @Router	/auth/oidc/callback [get]
// @Summary	OIDC authorization code callback
// @Tags		Auth
// @Success	302
// @Failure	404 {object} utils.APIError[any]
func (c *Controller) OIDCCallback(ctx *gin.Context) {
	if !c.oidc.Enabled() {
		ctx.JSON(http.StatusNotFound, utils.NewFailResponse("not found"))
		return
	}
	// Cleared up front: gin flushes the headers when the redirect is written, so
	// a Set-Cookie added afterwards would never reach the browser. Reading the
	// cookie below still works, it comes off the request.
	c.clearStateCookie(ctx)

	// The OP refused (e.g. access_denied for a user outside the allowed group).
	// Nothing was guessed, so the bruteforce counters stay untouched.
	if opErr := ctx.Query("error"); opErr != "" {
		c.logger.Warnw("oidc provider returned an error",
			"error", opErr, "description", ctx.Query("error_description"))
		c.redirectError(ctx, "oidc_failed")
		return
	}

	response, errCode := c.oidcCallback(ctx)
	if errCode != "" {
		ctx.Set(bruteforce.FailureKey, true)
		c.redirectError(ctx, errCode)
		return
	}

	ctx.Set(bruteforce.SuccessKey, true)
	// Fragment, not query: never sent to a server and never logged.
	ctx.Redirect(http.StatusFound, c.oidc.ClientURL+"/login#access_token="+
		url.QueryEscape(response.AccessToken)+"&refresh_token="+url.QueryEscape(response.RefreshToken))
}

// oidcCallback does the verification and identity mapping, returning an error
// code for the SPA instead of details (which only go to the server log).
func (c *Controller) oidcCallback(ctx *gin.Context) (*LoginResponse, string) {
	provider, meta, err := c.oidc.discover(ctx)
	if err != nil {
		c.logger.Errorw("oidc discovery failed", "error", err)
		return nil, "oidc_failed"
	}

	cookie, err := ctx.Cookie(c.oidc.stateCookieName())
	if err != nil {
		c.logger.Warnw("oidc callback without a state cookie")
		return nil, "oidc_failed"
	}
	claims, err := c.tokenMaker.VerifyOIDCStateToken(ctx, cookie)
	if err != nil {
		c.logger.Warnw("invalid oidc state cookie", "error", err)
		return nil, "oidc_failed"
	}
	if state := ctx.Query("state"); state == "" || state != claims.State {
		c.logger.Warnw("oidc state mismatch")
		return nil, "oidc_failed"
	}

	// RFC 9207: cheap mix-up defense whenever the OP advertises it.
	if meta.IssParameterSupported {
		if iss := ctx.Query("iss"); iss != c.oidc.Issuer {
			c.logger.Warnw("oidc iss response parameter mismatch", "iss", iss)
			return nil, "oidc_failed"
		}
	}

	code := ctx.Query("code")
	if code == "" {
		return nil, "oidc_failed"
	}

	// The token request always carries the verifier: an OP that accepted the
	// challenge must enforce it, so there is no downgrade path.
	token, err := c.oidc.oauth2Config(provider).Exchange(ctx, code, oauth2.VerifierOption(claims.Verifier))
	if err != nil {
		c.logger.Errorw("oidc code exchange failed", "error", err)
		return nil, "oidc_failed"
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		c.logger.Errorw("oidc token response carried no id_token")
		return nil, "oidc_failed"
	}
	idToken, err := c.oidc.verifier(provider).Verify(ctx, rawIDToken)
	if err != nil {
		c.logger.Errorw("oidc id_token verification failed", "error", err)
		return nil, "oidc_failed"
	}
	if idToken.Nonce != claims.Nonce {
		c.logger.Warnw("oidc nonce mismatch")
		return nil, "oidc_failed"
	}

	var idClaims oidcClaims
	if err := idToken.Claims(&idClaims); err != nil {
		c.logger.Errorw("oidc id_token claims could not be parsed", "error", err)
		return nil, "oidc_failed"
	}
	// go-oidc only checks that aud contains the client ID (Core 3.1.3.7).
	if len(idToken.Audience) > 1 && idClaims.AZP != c.oidc.ClientID {
		c.logger.Warnw("oidc id_token has multiple audiences and no matching azp")
		return nil, "oidc_failed"
	}

	// Bound path first: a bound admin logs in even when the OP omits email or
	// UserInfo is down.
	response, err := c.service.LoginOIDCBound(ctx, c.oidc.Issuer, idToken.Subject)
	if err == nil {
		return response, ""
	}
	if !errors.Is(err, ErrOIDCUnbound) {
		c.logger.Errorw("oidc bound login failed", "error", err)
		return nil, "oidc_failed"
	}

	identity, errCode := c.oidcIdentity(ctx, provider, token, idToken, idClaims)
	if errCode != "" {
		return nil, errCode
	}

	response, err = c.service.LinkOIDC(ctx, identity)
	if err != nil {
		if errors.Is(err, ErrOIDCNotAdmin) {
			c.logger.Warnw("oidc identity is not the peekaping admin",
				"subject", identity.Subject, "email", identity.Email)
			return nil, "oidc_not_admin"
		}
		c.logger.Errorw("oidc link failed", "error", err)
		return nil, "oidc_failed"
	}
	return response, ""
}

// oidcIdentity resolves the email claims used once, to decide which row gets
// bound. The ID token is preferred; UserInfo is a fallback for OPs that deliver
// scope claims only there, and its email/email_verified pair is taken as a unit.
func (c *Controller) oidcIdentity(
	ctx *gin.Context,
	provider *gooidc.Provider,
	token *oauth2.Token,
	idToken *gooidc.IDToken,
	idClaims oidcClaims,
) (OIDCIdentity, string) {
	identity := OIDCIdentity{Issuer: c.oidc.Issuer, Subject: idToken.Subject}

	if idClaims.Email != "" && idClaims.EmailVerified != nil {
		identity.Email = idClaims.Email
		identity.EmailVerified = *idClaims.EmailVerified
	} else {
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			c.logger.Errorw("oidc userinfo request failed", "error", err)
			return identity, "oidc_failed"
		}
		if info.Subject != idToken.Subject {
			c.logger.Warnw("oidc userinfo subject does not match the id_token subject")
			return identity, "oidc_failed"
		}
		var uiClaims oidcClaims
		if err := info.Claims(&uiClaims); err != nil {
			c.logger.Errorw("oidc userinfo claims could not be parsed", "error", err)
			return identity, "oidc_failed"
		}
		identity.Email = uiClaims.Email
		identity.EmailVerified = uiClaims.EmailVerified != nil && *uiClaims.EmailVerified
	}

	// email_verified is optional in OIDC Core, so an OP that never sets it can
	// neither link nor bootstrap; already-bound logins are unaffected.
	if identity.Email == "" || !identity.EmailVerified {
		c.logger.Warnw("oidc identity has no verified email claim", "subject", identity.Subject)
		return identity, "oidc_failed"
	}
	return identity, ""
}

func (c *Controller) redirectError(ctx *gin.Context, code string) {
	ctx.Redirect(http.StatusFound, c.oidc.ClientURL+"/login?error="+url.QueryEscape(code))
}

func (c *Controller) setStateCookie(ctx *gin.Context, value string, maxAge int) {
	// __Host- requires Secure, Path=/ and no Domain, so no subdomain can plant it.
	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie(c.oidc.stateCookieName(), value, maxAge, "/", "", c.oidc.secureCookies(), true)
}

func (c *Controller) clearStateCookie(ctx *gin.Context) {
	c.setStateCookie(ctx, "", -1)
}

// @Router	/auth/me [get]
// @Summary	Current user
// @Tags		Auth
// @Produce	json
// @Security JwtAuth
// @Success	200	{object}	utils.ApiResponse[Model]
// @Failure	401	{object}	utils.APIError[any]
func (c *Controller) Me(ctx *gin.Context) {
	userId, exists := ctx.Get("userId")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, utils.NewFailResponse("Unauthorized"))
		return
	}

	user, err := c.service.GetByID(ctx, userId.(string))
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, utils.NewFailResponse(err.Error()))
		return
	}
	ctx.JSON(http.StatusOK, utils.NewSuccessResponse("ok", user))
}
