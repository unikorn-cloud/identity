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

package authorization

import (
	"net/http"

	"github.com/unikorn-cloud/core/pkg/authorization/accesstoken"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
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

func (a *Authenticator) Userinfo(r *http.Request) (interface{}, error) {
	token := accesstoken.FromContext(r.Context())

	claims, err := a.OAuth2.Verify(r, token)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (a *Authenticator) JWKS() (interface{}, error) {
	result, err := a.issuer.JWKS()
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to generate json web key set").WithError(err)
	}

	return result, nil
}
