/*
Copyright 2025 the Unikorn Authors.

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

package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/identity/pkg/oauth2/common"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"
)

var (
	ErrMissingField = errors.New("missing field")
)

// Config returns a oauth2 configuration via service discovery.
func Config(ctx context.Context, parameters *types.ConfigParameters, scopes []string) (*oidc.Provider, *oauth2.Config, error) {
	oidcProvider, err := oidc.NewProvider(ctx, parameters.Provider.Spec.Issuer)
	if err != nil {
		return nil, nil, err
	}

	scopes = slices.Concat([]string{oidc.ScopeOpenID, "profile", "email"}, scopes)

	config := common.Config(parameters, scopes)
	config.Endpoint = oidcProvider.Endpoint()

	return oidcProvider, config, nil
}

// Authorization gets the oauth2 authorization URL.
func Authorization(config *oauth2.Config, parameters *types.AuthorizationParamters, requestParameters []oauth2.AuthCodeOption) (string, error) {
	requestParameters = append(requestParameters,
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", parameters.CodeChallenge),
		oidc.Nonce(parameters.Nonce),
	)

	// If the user provided an email as part of the loging screen, send that to the IdP to
	// optimize the process.
	if parameters.Email != "" {
		requestParameters = append(requestParameters, oauth2.SetAuthURLParam("login_hint", parameters.Email))
	}

	return common.Authorization(config, parameters, requestParameters), nil
}

// CodeExchange exchanges a code with an OIDC compliant server.
func CodeExchange(ctx context.Context, parameters *types.CodeExchangeParameters) (*oauth2.Token, *IDToken, error) {
	oidcProvider, config, err := Config(ctx, &parameters.ConfigParameters, nil)
	if err != nil {
		return nil, nil, err
	}

	// Exchange the code for an id_token, access_token and refresh_token with
	// the extracted code verifier.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", parameters.Provider.Spec.ClientID),
		oauth2.SetAuthURLParam("code_verifier", parameters.CodeVerifier),
	}

	token, err := config.Exchange(ctx, parameters.Code, authURLParams...)
	if err != nil {
		return nil, nil, err
	}

	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, fmt.Errorf("%w: id_token not in response", ErrMissingField)
	}

	oidcConfig := &oidc.Config{
		ClientID:        parameters.Provider.Spec.ClientID,
		SkipIssuerCheck: parameters.SkipIssuerCheck,
	}

	idToken, err := oidcProvider.Verifier(oidcConfig).Verify(ctx, idTokenRaw)
	if err != nil {
		return nil, nil, err
	}

	idTokenClaims := &IDToken{}

	if err := idToken.Claims(idTokenClaims); err != nil {
		return nil, nil, err
	}

	return token, idTokenClaims, nil
}
