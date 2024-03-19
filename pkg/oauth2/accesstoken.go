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
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")
)

// UnikornClaims contains all application specific claims in a single
// top-level claim that won't clash with the ones defined by IETF.
type UnikornClaims struct {
	// Groups is a list of groups the user has on the backend IdP.
	Groups []string `json:"groups,omitempty"`
}

// Claims is an application specific set of claims.
// TODO: this technically isn't conformant to oauth2 in that we don't specify
// the client_id claim, and there are probably others.
type Claims struct {
	jwt.Claims `json:",inline"`

	// Unikorn claims are application specific extensions.
	Unikorn *UnikornClaims `json:"unikorn,omitempty"`
}

// Issue issues a new JWT access token.
func (a *Authenticator) Issue(r *http.Request, code *Code, expiresAt time.Time) (string, error) {
	now := time.Now()

	nowRFC7519 := jwt.NumericDate(now.Unix())
	expiresAtRFC7519 := jwt.NumericDate(expiresAt.Unix())

	claims := &Claims{
		Claims: jwt.Claims{
			ID:      uuid.New().String(),
			Subject: code.Subject,
			Audience: jwt.Audience{
				r.Host,
			},
			Issuer:    "https://" + r.Host,
			IssuedAt:  &nowRFC7519,
			NotBefore: &nowRFC7519,
			Expiry:    &expiresAtRFC7519,
		},
		Unikorn: &UnikornClaims{
			Groups: code.Groups,
		},
	}

	token, err := a.issuer.EncodeJWEToken(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

// Verify checks the access token parses and validates.
func (a *Authenticator) Verify(r *http.Request, tokenString string) (*Claims, error) {
	// Parse and verify the claims with the public key.
	claims := &Claims{}

	if err := a.issuer.DecodeJWEToken(tokenString, claims); err != nil {
		return nil, fmt.Errorf("failed to decrypt claims: %w", err)
	}

	// Verify the claims.
	expected := jwt.Expected{
		Audience: jwt.Audience{
			r.Host,
		},
		Issuer: "https://" + r.Host,
		Time:   time.Now(),
	}

	if err := claims.Claims.Validate(expected); err != nil {
		return nil, fmt.Errorf("failed to validate claims: %w", err)
	}

	return claims, nil
}
