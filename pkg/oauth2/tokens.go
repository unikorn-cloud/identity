/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	"github.com/unikorn-cloud/identity/pkg/jose"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")
)

// CustomAccessTokenClaims contains all application specific claims in a single
// top-level claim that won't clash with the ones defined by IETF.
type CustomAccessTokenClaims struct {
	// Provider is the provider name for the token.
	Provider string
	// AccessToken as defined for the IdP.
	AccessToken string `json:"at"`
}

// AccessTokenClaims is an application specific set of claims.
// TODO: this technically isn't conformant to oauth2 in that we don't specify
// the client_id claim, and there are probably others.
type AccessTokenClaims struct {
	jwt.Claims `json:",inline"`

	// Custom claims are application specific extensions.
	Custom *CustomAccessTokenClaims `json:"cat,omitempty"`
}

// CustomRefreshTokenClaims contains all application specific claims in a single
// top-level claim that won't clash with the ones defined by IETF.
type CustomRefreshTokenClaims struct {
	// Provider is the provider name for the token.
	Provider string
	// RefreshToken as defined for the IdP.
	RefreshToken string `json:"rt"`
}

// RefreshTokenClaims is a basic set of JWT claims, plus a wrapper for the
// IdP's refresh token.
type RefreshTokenClaims struct {
	jwt.Claims `json:",inline"`

	// Custom claims are application specific extensions.
	Custom *CustomRefreshTokenClaims `json:"crt,omitempty"`
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type IssueInfo struct {
	Issuer               string
	Audience             string
	Subject              string
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	Tokens               Tokens
	Provider             string
}

// Issue issues a new JWT access token.
func (a *Authenticator) Issue(ctx context.Context, info *IssueInfo) (*Tokens, error) {
	now := time.Now()

	nowRFC7519 := jwt.NewNumericDate(now)
	atExpiresAtRFC7519 := jwt.NewNumericDate(now.Add(info.AccessTokenDuration))
	rtExpiresAtRFC7519 := jwt.NewNumericDate(now.Add(info.RefreshTokenDuration))

	atClaims := &AccessTokenClaims{
		Claims: jwt.Claims{
			ID:      uuid.New().String(),
			Subject: info.Subject,
			Audience: jwt.Audience{
				info.Audience,
			},
			Issuer:    info.Issuer,
			IssuedAt:  nowRFC7519,
			NotBefore: nowRFC7519,
			Expiry:    atExpiresAtRFC7519,
		},
		Custom: &CustomAccessTokenClaims{
			Provider:    info.Provider,
			AccessToken: info.Tokens.AccessToken,
		},
	}

	at, err := a.issuer.EncodeJWEToken(ctx, atClaims, jose.TokenTypeAccessToken)
	if err != nil {
		return nil, err
	}

	rtClaims := &RefreshTokenClaims{
		Claims: jwt.Claims{
			ID:      uuid.New().String(),
			Subject: info.Subject,
			Audience: jwt.Audience{
				info.Audience,
			},
			Issuer:    info.Issuer,
			IssuedAt:  nowRFC7519,
			NotBefore: nowRFC7519,
			Expiry:    rtExpiresAtRFC7519,
		},
		Custom: &CustomRefreshTokenClaims{
			Provider:     info.Provider,
			RefreshToken: info.Tokens.RefreshToken,
		},
	}

	rt, err := a.issuer.EncodeJWEToken(ctx, rtClaims, jose.TokenTypeRefreshToken)
	if err != nil {
		return nil, err
	}

	tokens := &Tokens{
		AccessToken:  at,
		RefreshToken: rt,
	}

	return tokens, nil
}

type VerifyInfo struct {
	Issuer   string
	Audience string
	Token    string
}

// Verify checks the access token parses and validates.
func (a *Authenticator) Verify(ctx context.Context, info *VerifyInfo) (*AccessTokenClaims, error) {
	// Parse and verify the claims with the public key.
	claims := &AccessTokenClaims{}

	if err := a.issuer.DecodeJWEToken(ctx, info.Token, claims, jose.TokenTypeAccessToken); err != nil {
		return nil, fmt.Errorf("failed to decrypt claims: %w", err)
	}

	// Verify the claims.
	expected := jwt.Expected{
		Audience: jwt.Audience{
			info.Audience,
		},
		Issuer: info.Issuer,
		Time:   time.Now(),
	}

	if err := claims.Claims.ValidateWithLeeway(expected, a.options.TokenVerificationLeeway); err != nil {
		return nil, fmt.Errorf("failed to validate claims: %w", err)
	}

	return claims, nil
}
