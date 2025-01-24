/*
Copyright 2024-2025 the Unikorn Authors.

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

package common

import (
	"context"

	"golang.org/x/oauth2"

	"github.com/unikorn-cloud/identity/pkg/oauth2/types"
)

// Config returns an oauth2 configuration.
func Config(parameters *types.ConfigParameters, scopes []string) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     parameters.Provider.Spec.ClientID,
		ClientSecret: parameters.Provider.Spec.ClientSecret,
		RedirectURL:  "https://" + parameters.Host + "/oidc/callback",
		Scopes:       scopes,
	}

	if parameters.Provider.Spec.AuthorizationURI != nil && parameters.Provider.Spec.TokenURI != nil {
		config.Endpoint.AuthURL = *parameters.Provider.Spec.AuthorizationURI
		config.Endpoint.TokenURL = *parameters.Provider.Spec.TokenURI
	}

	return config
}

// Authorization gets the oauth2 authorization URL.
func Authorization(config *oauth2.Config, parameters *types.AuthorizationParamters, requestParameters []oauth2.AuthCodeOption) string {
	return config.AuthCodeURL(parameters.State, requestParameters...)
}

// CodeExchange exchanges a code with an oauth2 server.
func CodeExchange(ctx context.Context, parameters *types.CodeExchangeParameters) (*oauth2.Token, error) {
	return Config(&parameters.ConfigParameters, nil).Exchange(ctx, parameters.Code)
}
