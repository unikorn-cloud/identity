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

package providers

import (
	"context"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers/types"
)

// nullProvider does nothing.
type nullProvider struct{}

func newNullProvider() Provider {
	return &nullProvider{}
}

func (*nullProvider) AuthorizationRequestParameters() map[string]string {
	return nil
}

func (*nullProvider) Scopes() []string {
	return nil
}

func (*nullProvider) RequiresAccessToken() bool {
	return false
}

func (*nullProvider) Groups(ctx context.Context, organization *unikornv1.Organization, accessToken string) ([]types.Group, error) {
	return nil, nil
}
