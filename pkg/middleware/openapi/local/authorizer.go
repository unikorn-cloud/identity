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
	"strings"

	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
)

// Authorizer provides OpenAPI based authorization middleware.
type Authorizer struct {
	authenticator *oauth2.Authenticator
}

// NewAuthorizer returns a new authorizer with required parameters.
func NewAuthorizer(authenticator *oauth2.Authenticator) *Authorizer {
	return &Authorizer{
		authenticator: authenticator,
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
func (a *Authorizer) authorizeOAuth2(r *http.Request) (string, *userinfo.UserInfo, error) {
	authorizationScheme, token, err := getHTTPAuthenticationScheme(r)
	if err != nil {
		return "", nil, err
	}

	if !strings.EqualFold(authorizationScheme, "bearer") {
		return "", nil, errors.OAuth2InvalidRequest("authorization scheme not allowed").WithValues("scheme", authorizationScheme)
	}

	// Check the token is from us, for us, and in date.
	claims, err := a.authenticator.Verify(r, token)
	if err != nil {
		return "", nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
	}

	permissions, err := a.authenticator.GetRBAC().UserPermissions(r.Context(), claims.Subject)
	if err != nil {
		return "", nil, errors.OAuth2AccessDenied("failed to get user permissions").WithError(err)
	}

	ui := &userinfo.UserInfo{
		Claims: claims.Claims,
		RBAC:   permissions,
	}

	return token, ui, nil
}

// Authorize checks the request against the OpenAPI security scheme.
func (a *Authorizer) Authorize(authentication *openapi3filter.AuthenticationInput) (string, *userinfo.UserInfo, error) {
	if authentication.SecurityScheme.Type == "oauth2" {
		return a.authorizeOAuth2(authentication.RequestValidationInput.Request)
	}

	return "", nil, errors.OAuth2InvalidRequest("authorization scheme unsupported").WithValues("scheme", authentication.SecurityScheme.Type)
}
