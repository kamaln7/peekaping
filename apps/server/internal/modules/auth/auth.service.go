package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Register(ctx context.Context, dto RegisterDto) (*LoginResponse, error)
	Login(ctx context.Context, dto LoginDto) (*LoginResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*LoginResponse, error)
	UpdatePassword(ctx context.Context, userId string, dto UpdatePasswordDto) error
	GetByID(ctx context.Context, userId string) (*Model, error)

	// OIDC
	LoginOIDCBound(ctx context.Context, issuer, subject string) (*LoginResponse, error)
	LinkOIDC(ctx context.Context, identity OIDCIdentity) (*LoginResponse, error)

	// 2FA methods
	SetupTwoFA(ctx context.Context, userId, password string) (secret string, provisioningURI string, err error)
	VerifyTwoFA(ctx context.Context, userId, code string) (bool, error)
	DisableTwoFA(ctx context.Context, userId, password string) error
}

type ServiceImpl struct {
	repo       Repository
	tokenMaker *TokenMaker
	logger     *zap.SugaredLogger
}

func NewService(
	repo Repository,
	tokenMaker *TokenMaker,
	logger *zap.SugaredLogger,
) Service {
	return &ServiceImpl{
		repo:       repo,
		tokenMaker: tokenMaker,
		logger:     logger.Named("[auth-service]"),
	}
}

func (s *ServiceImpl) Register(ctx context.Context, dto RegisterDto) (*LoginResponse, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user, err := s.createFirstUser(ctx, &Model{
		Email:    strings.ToLower(dto.Email),
		Password: string(hashedPassword),
		Active:   true,
	})
	if err != nil {
		return nil, err
	}

	// Generate access token
	accessToken, err := s.tokenMaker.CreateAccessToken(ctx, user)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.tokenMaker.CreateRefreshToken(ctx, user)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *ServiceImpl) Login(ctx context.Context, dto LoginDto) (*LoginResponse, error) {
	// Find admin by email
	user, err := s.repo.FindByEmail(ctx, dto.Email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if user == nil {
		return nil, errors.New("invalid credentials")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(dto.Password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Enforce 2FA if enabled
	if user.TwoFASecret != "" && user.TwoFAStatus {
		if dto.Token == "" {
			return nil, errors.New("2FA token required")
		}
		if !totp.Validate(dto.Token, user.TwoFASecret) {
			return nil, errors.New("invalid 2FA token")
		}
	}

	// Generate access token
	accessToken, err := s.tokenMaker.CreateAccessToken(ctx, user)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.tokenMaker.CreateRefreshToken(ctx, user)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

func (s *ServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (*LoginResponse, error) {
	// Verify refresh token
	claims, err := s.tokenMaker.VerifyToken(ctx, refreshToken, "refresh")
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if it's a refresh token
	if claims.Type != "refresh" {
		return nil, errors.New("invalid token type")
	}

	// Find admin by ID
	user, err := s.repo.FindByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return nil, errors.New("user not found")
	}

	// Generate new access token
	accessToken, err := s.tokenMaker.CreateAccessToken(ctx, user)
	if err != nil {
		return nil, err
	}

	// Generate new refresh token
	newRefreshToken, err := s.tokenMaker.CreateRefreshToken(ctx, user)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		User:         user,
		RefreshToken: newRefreshToken,
		AccessToken:  accessToken,
	}, nil
}

func (s *ServiceImpl) UpdatePassword(ctx context.Context, userId string, dto UpdatePasswordDto) error {
	// Find user by ID
	user, err := s.repo.FindByID(ctx, userId)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// An OIDC-bootstrapped admin has no password yet; bcrypt never matches an
	// empty hash, so skip the check to let them set the first one.
	if user.Password != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(dto.CurrentPassword)); err != nil {
			return errors.New("current password is incorrect")
		}
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(dto.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("failed to hash new password")
	}

	password := string(hashedPassword)
	updateModel := &UpdateModel{
		Password: &password,
	}

	// Update user in DB
	err = s.repo.Update(ctx, userId, updateModel)
	if err != nil {
		return errors.New("failed to update password")
	}

	return nil
}

func (s *ServiceImpl) SetupTwoFA(ctx context.Context, userId, password string) (string, string, error) {
	user, err := s.repo.FindByID(ctx, userId)
	if err != nil || user == nil {
		return "", "", errors.New("user not found")
	}

	// Require password verification
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", "", errors.New("invalid password")
	}
	var secretStr, provisioningURI string
	if user.TwoFASecret == "" {
		// Generate new secret and provisioning URI
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "peekaping",
			AccountName: user.Email,
		})
		if err != nil {
			return "", "", err
		}
		secretStr = key.Secret()
		provisioningURI = key.URL()
		updateModel := &UpdateModel{
			TwoFASecret: &secretStr,
		}
		err = s.repo.Update(ctx, userId, updateModel)
		if err != nil {
			return "", "", err
		}
	} else {
		// If already set, just return existing
		secretStr = user.TwoFASecret
		// Recreate the provisioning URI
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "peekaping",
			AccountName: user.Email,
			Secret:      []byte(user.TwoFASecret),
		})
		if err != nil {
			return "", "", err
		}
		provisioningURI = key.URL()
	}
	return secretStr, provisioningURI, nil
}

func (s *ServiceImpl) VerifyTwoFA(ctx context.Context, userId, code string) (bool, error) {
	user, err := s.repo.FindByID(ctx, userId)
	if err != nil || user == nil {
		return false, errors.New("user not found")
	}
	if user.TwoFASecret == "" {
		return false, errors.New("2FA not setup")
	}
	valid := totp.Validate(code, user.TwoFASecret)
	if valid {
		status := true
		updateModel := &UpdateModel{
			TwoFAStatus: &status,
		}
		s.repo.Update(ctx, userId, updateModel)
	}
	return valid, nil
}

func (s *ServiceImpl) DisableTwoFA(ctx context.Context, userId, password string) error {
	user, err := s.repo.FindByID(ctx, userId)
	if err != nil || user == nil {
		return errors.New("user not found")
	}
	// Require password verification
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return errors.New("invalid password")
	}

	// Prepare values for pointers
	secret := ""
	status := false

	updateModel := &UpdateModel{
		TwoFASecret: &secret,
		TwoFAStatus: &status,
	}

	err = s.repo.Update(ctx, userId, updateModel)
	if err != nil {
		return errors.New("failed to disable 2FA")
	}

	return nil
}

// ErrOIDCUnbound means no user carries this OIDC subject yet.
var ErrOIDCUnbound = errors.New("oidc subject not bound")

// ErrOIDCNotAdmin means the identity may not become (or take over) the admin.
var ErrOIDCNotAdmin = errors.New("not the peekaping admin")

// OIDCIdentity is the verified identity the callback handler gathered.
type OIDCIdentity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

// OIDCSubjectKey is the value stored in users.oidc_subject.
func OIDCSubjectKey(issuer, sub string) string {
	return issuer + "|" + sub
}

func (s *ServiceImpl) GetByID(ctx context.Context, userId string) (*Model, error) {
	user, err := s.repo.FindByID(ctx, userId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}
	return user, nil
}

// createFirstUser inserts the one admin this install may have, atomically.
func (s *ServiceImpl) createFirstUser(ctx context.Context, user *Model) (*Model, error) {
	user.CreatedAt = time.Now().UTC()
	user.UpdatedAt = time.Now().UTC()

	created, out, err := s.repo.CreateFirst(ctx, user)
	if err != nil {
		return nil, err
	}
	if !created {
		return nil, errors.New("admin already exists")
	}
	return out, nil
}

func (s *ServiceImpl) issueTokens(ctx context.Context, user *Model) (*LoginResponse, error) {
	accessToken, err := s.tokenMaker.CreateAccessToken(ctx, user)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.tokenMaker.CreateRefreshToken(ctx, user)
	if err != nil {
		return nil, err
	}
	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}, nil
}

// LoginOIDCBound logs in a user already bound to this subject. Email is never
// consulted, so renaming the address at the OP changes nothing.
func (s *ServiceImpl) LoginOIDCBound(ctx context.Context, issuer, subject string) (*LoginResponse, error) {
	key := OIDCSubjectKey(issuer, subject)

	user, err := s.repo.FindByOIDCSubject(ctx, key)
	if err != nil {
		return nil, err
	}
	// Re-compare in Go: a case-insensitive collation on any backend must not be
	// able to hand tokens to a different account.
	if user == nil || user.OIDCSubject != key {
		return nil, ErrOIDCUnbound
	}

	return s.issueTokens(ctx, user)
}

// LinkOIDC binds an unbound subject to the admin account, bootstrapping it on a
// fresh install. Email is consulted exactly once, here, to decide which row gets
// the binding; after that the subject alone identifies the user.
func (s *ServiceImpl) LinkOIDC(ctx context.Context, identity OIDCIdentity) (*LoginResponse, error) {
	if identity.Email == "" || !identity.EmailVerified {
		return nil, ErrOIDCNotAdmin
	}
	key := OIDCSubjectKey(identity.Issuer, identity.Subject)
	email := strings.ToLower(identity.Email)

	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if user == nil {
		// Fresh install: whoever the OP lets through first becomes the admin.
		created, err := s.createFirstUser(ctx, &Model{
			Email:       email,
			Password:    "", // set later from the profile page
			Active:      true,
			OIDCSubject: key,
		})
		if err != nil {
			return nil, ErrOIDCNotAdmin
		}
		return s.issueTokens(ctx, created)
	}

	if user.OIDCSubject != "" {
		// Already bound elsewhere: email reassignment at the OP cannot take over.
		return nil, ErrOIDCNotAdmin
	}

	linked, err := s.repo.LinkOIDCSubject(ctx, user.ID, key)
	if err != nil {
		return nil, err
	}
	if !linked {
		// Lost the race against a concurrent link; only continue if the winner
		// was us.
		user, err = s.repo.FindByID(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if user == nil || user.OIDCSubject != key {
			return nil, ErrOIDCNotAdmin
		}
	} else {
		user.OIDCSubject = key
	}

	return s.issueTokens(ctx, user)
}
