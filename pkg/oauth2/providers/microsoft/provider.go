/*
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

package microsoft

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

type Provider struct {
}

func New() *Provider {
	return &Provider{}
}

func (*Provider) Scopes() []string {
	return []string{}
}

func (p *Provider) Groups(ctx context.Context, organization *unikornv1.Organization, idToken *oidc.IDToken, accessToken string) ([]string, error) {
	var claims struct {
		Groups []string `json:"groups"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	return claims.Groups, nil
}
