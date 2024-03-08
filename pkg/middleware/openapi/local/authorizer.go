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

package local

import (
	"net/http"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/middleware/openapi"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
)

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer
}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(issuer *jose.JWTIssuer) *Authorizer {
	return &Authorizer{
		issuer: issuer,
	}
}

// getHTTPAuthenticationScheme grabs the scheme and token from the HTTP
// Authorization header.
func getHTTPAuthenticationScheme(r *http.Request) (string, string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", "", errors.OAuth2InvalidRequest("authorization header missing")
	}

	parts := strings.Split(header, " ")
	if len(parts) != 2 {
		return "", "", errors.OAuth2InvalidRequest("authorization header malformed")
	}

	return parts[0], parts[1], nil
}

// authorizeOAuth2 checks APIs that require and oauth2 bearer token.
func (a *Authorizer) authorizeOAuth2(authContext *openapi.AuthorizationContext, r *http.Request, scopes []string) error {
	authorizationScheme, token, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	// Check the token is from us, for us, and in date.
	claims, err := oauth2.Verify(a.issuer, r, token)
	if err != nil {
		return errors.OAuth2AccessDenied("token validation failed").WithError(err)
	}

	// Check the token is authorized to do what the schema says.
	for _, scope := range scopes {
		if !slices.Contains(claims.Scope, scope) {
			return errors.OAuth2InvalidScope("token missing required scope").WithValues("scope", scope)
		}
	}

	// Set the claims in the context for use by the handlers.
	authContext.Claims = *claims

	return nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(ctx *openapi.AuthorizationContext, authentication *openapi3filter.AuthenticationInput) error {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(ctx, authentication.RequestValidationInput.Request, authentication.Scopes)
	}

	return errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}
