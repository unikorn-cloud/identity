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

type Provider interface {
	// AuthorizationRequestParameters allows the autorization request parameters
	// to be tweaked on a per-provider basis.
	AuthorizationRequestParameters() map[string]string

	// Scopes returns a set of scopes that are required by the access token
	// to operate correctly.
	Scopes() []string

	// RequiresAccessToken defines whether the access and refresh tokens are
	// required for operation.
	// TODO: this is because Microsoft's tokens are massive and blow nginx's
	// request size limit (4096).  We really need to cache these securely and
	// internally so we don't have to pass them around.  For example hand to
	// the client an ID and private key that can decrpyt from storage, in memory
	// on demand.
	RequiresAccessToken() bool

	// Groups returns a list of groups the user belongs to.
	Groups(ctx context.Context, organization *unikornv1.Organization, accessToken string) ([]types.Group, error)
}
