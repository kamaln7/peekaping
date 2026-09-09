package auth

import (
	"context"
	"errors"
	"fmt"
	"peekaping/internal/modules/shared"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type Claims struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	Type   string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

type TokenMaker struct {
	settingService shared.SettingService
	logger         *zap.SugaredLogger
}

func NewTokenMaker(settingService shared.SettingService, logger *zap.SugaredLogger) *TokenMaker {
	return &TokenMaker{
		settingService: settingService,
		logger:         logger.Named("[token-maker]"),
	}
}

func (maker *TokenMaker) CreateAccessToken(ctx context.Context, user *Model) (string, error) {
	// Get access token expiration
	expirySetting, err := maker.settingService.GetByKey(ctx, "ACCESS_TOKEN_EXPIRED_IN")
	if err != nil {
		return "", fmt.Errorf("failed to get access token expiration: %w", err)
	}
	if expirySetting == nil {
		return "", fmt.Errorf("access token expiration setting not found")
	}

	accessExpiry, err := time.ParseDuration(expirySetting.Value)
	if err != nil {
		return "", fmt.Errorf("invalid access token expiration format: %w", err)
	}

	// Get access token secret key
	secretSetting, err := maker.settingService.GetByKey(ctx, "ACCESS_TOKEN_SECRET_KEY")
	if err != nil {
		return "", fmt.Errorf("failed to get access token secret key: %w", err)
	}
	if secretSetting == nil {
		return "", fmt.Errorf("access token secret key setting not found")
	}

	return maker.createToken(user, "access", accessExpiry, secretSetting.Value)
}

func (maker *TokenMaker) CreateRefreshToken(ctx context.Context, user *Model) (string, error) {
	// Get refresh token expiration
	expirySetting, err := maker.settingService.GetByKey(ctx, "REFRESH_TOKEN_EXPIRED_IN")
	if err != nil {
		return "", fmt.Errorf("failed to get refresh token expiration: %w", err)
	}
	if expirySetting == nil {
		return "", fmt.Errorf("refresh token expiration setting not found")
	}

	refreshExpiry, err := time.ParseDuration(expirySetting.Value)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token expiration format: %w", err)
	}

	// Get refresh token secret key
	secretSetting, err := maker.settingService.GetByKey(ctx, "REFRESH_TOKEN_SECRET_KEY")
	if err != nil {
		return "", fmt.Errorf("failed to get refresh token secret key: %w", err)
	}
	if secretSetting == nil {
		return "", fmt.Errorf("refresh token secret key setting not found")
	}

	return maker.createToken(user, "refresh", refreshExpiry, secretSetting.Value)
}

func (maker *TokenMaker) createToken(user *Model, tokenType string, duration time.Duration, secretKey string) (string, error) {
	claims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Type:   tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func (maker *TokenMaker) VerifyToken(ctx context.Context, tokenString string, tokenType string) (*Claims, error) {
	var secretKey string
	var err error

	// Get the appropriate secret key based on token type
	switch tokenType {
	case "access":
		secretSetting, err := maker.settingService.GetByKey(ctx, "ACCESS_TOKEN_SECRET_KEY")
		if err != nil {
			return nil, fmt.Errorf("failed to get access token secret key: %w", err)
		}
		if secretSetting == nil {
			return nil, fmt.Errorf("access token secret key setting not found")
		}
		secretKey = secretSetting.Value
	case "oidc":
		// Short-lived state cookie; shares the access token secret.
		secretSetting, err := maker.settingService.GetByKey(ctx, "ACCESS_TOKEN_SECRET_KEY")
		if err != nil {
			return nil, fmt.Errorf("failed to get access token secret key: %w", err)
		}
		if secretSetting == nil {
			return nil, fmt.Errorf("access token secret key setting not found")
		}
		secretKey = secretSetting.Value
	case "refresh":
		secretSetting, err := maker.settingService.GetByKey(ctx, "REFRESH_TOKEN_SECRET_KEY")
		if err != nil {
			return nil, fmt.Errorf("failed to get refresh token secret key: %w", err)
		}
		if secretSetting == nil {
			return nil, fmt.Errorf("refresh token secret key setting not found")
		}
		secretKey = secretSetting.Value
	default:
		return nil, ErrInvalidToken
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// OIDCStateClaims travels in the __Host-oidc_state cookie so no server-side
// session store is needed and API replicas stay stateless.
type OIDCStateClaims struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Type     string `json:"type"`
	jwt.RegisteredClaims
}

func (maker *TokenMaker) accessSecret(ctx context.Context) (string, error) {
	secretSetting, err := maker.settingService.GetByKey(ctx, "ACCESS_TOKEN_SECRET_KEY")
	if err != nil {
		return "", fmt.Errorf("failed to get access token secret key: %w", err)
	}
	if secretSetting == nil {
		return "", fmt.Errorf("access token secret key setting not found")
	}
	return secretSetting.Value, nil
}

func (maker *TokenMaker) CreateOIDCStateToken(ctx context.Context, state, nonce, verifier string, ttl time.Duration) (string, error) {
	secret, err := maker.accessSecret(ctx)
	if err != nil {
		return "", err
	}

	claims := &OIDCStateClaims{
		State:    state,
		Nonce:    nonce,
		Verifier: verifier,
		Type:     "oidc",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

func (maker *TokenMaker) VerifyOIDCStateToken(ctx context.Context, tokenString string) (*OIDCStateClaims, error) {
	secret, err := maker.accessSecret(ctx)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(tokenString, &OIDCStateClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*OIDCStateClaims)
	if !ok || !token.Valid || claims.Type != "oidc" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
