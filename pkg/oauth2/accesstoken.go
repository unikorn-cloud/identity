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
	"slices"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	"github.com/unikorn-cloud/core/pkg/authorization/oauth2/claims"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")
)

// Issue issues a new JWT access token.
func (a *Authenticator) Issue(i *jose.JWTIssuer, r *http.Request, code *Code, expiresAt time.Time) (string, error) {
	var organization unikornv1.Organization

	if err := a.client.Get(r.Context(), client.ObjectKey{Namespace: a.namespace, Name: code.Organization}, &organization); err != nil {
		return "", err
	}

	//nolint:prealloc
	var groups []claims.Group

	for _, group := range organization.Spec.Groups {
		// TODO: we should also check if the IdP has mapped the user to a group here.
		if !slices.Contains(group.Users, code.Subject) {
			continue
		}

		groups = append(groups, claims.Group{
			ID:    group.ID,
			Roles: group.Roles,
		})
	}

	now := time.Now()

	nowRFC7519 := jwt.NumericDate(now.Unix())
	expiresAtRFC7519 := jwt.NumericDate(expiresAt.Unix())

	claims := &claims.Claims{
		Claims: jwt.Claims{
			ID:      uuid.New().String(),
			Subject: code.Subject,
			Audience: jwt.Audience{
				code.ClientID,
			},
			Issuer:    "https://" + r.Host,
			IssuedAt:  &nowRFC7519,
			NotBefore: &nowRFC7519,
			Expiry:    &expiresAtRFC7519,
		},
		Unikorn: &claims.UnikornClaims{
			Organization: code.Organization,
			Groups:       groups,
		},
	}

	token, err := i.EncodeJWT(claims)
	if err != nil {
		return "", err
	}

	return token, nil
}

// Verify checks the access token parses and validates.
func Verify(i *jose.JWTIssuer, r *http.Request, tokenString string) (*claims.Claims, error) {
	// Parse and verify the claims with the public key.
	claims := &claims.Claims{}

	if err := i.DecodeJWT(tokenString, claims); err != nil {
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
