/*
Copyright 2022-2024 EscherCloud.

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

package authorization

import (
	"net/http"
	"time"

	"github.com/unikorn-cloud/identity/pkg/authorization/jose"
	"github.com/unikorn-cloud/identity/pkg/authorization/oauth2"
	"github.com/unikorn-cloud/identity/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/generated"
)

// Authenticator provides Keystone authentication functionality.
type Authenticator struct {
	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	// OAuth2 is the oauth2 deletgating authenticator.
	OAuth2 *oauth2.Authenticator
}

// NewAuthenticator returns a new authenticator with required fields populated.
// You must call AddFlags after this.
func NewAuthenticator(issuer *jose.JWTIssuer, oauth2 *oauth2.Authenticator) *Authenticator {
	return &Authenticator{
		issuer: issuer,
		OAuth2: oauth2,
	}
}

// Token performs token based authentication against Keystone with a scope, and returns a new token.
// Used to upgrade from unscoped, or to refresh a token.
func (a *Authenticator) Token(r *http.Request) (*generated.Token, error) {
	tokenClaims, err := oauth2.ClaimsFromContext(r.Context())
	if err != nil {
		return nil, errors.OAuth2ServerError("failed get claims").WithError(err)
	}

	// Add some scope to the claims to allow the token to do more.
	oAuth2Scope := &oauth2.ScopeList{
		Scopes: []oauth2.APIScope{
			oauth2.ScopeProject,
		},
	}

	ttl := time.Hour
	expiry := time.Now().Add(ttl)

	accessToken, err := oauth2.Issue(a.issuer, r, tokenClaims.Subject, oAuth2Scope, expiry)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to create access token").WithError(err)
	}

	result := &generated.Token{
		TokenType:   "Bearer",
		AccessToken: accessToken,
		ExpiresIn:   int(ttl.Seconds()),
	}

	return result, nil
}

func (a *Authenticator) JWKS() (interface{}, error) {
	result, err := a.issuer.JWKS()
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to generate json web key set").WithError(err)
	}

	return result, nil
}
