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

package providers

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

type Provider interface {
	// Scopes returns a set of scopes that are required by the access token
	// to operate correctly.
	Scopes() []string

	// Groups returns a list of groups the user belongs to.
	Groups(ctx context.Context, organization *unikornv1.Organization, idToken *oidc.IDToken, accessToken string) ([]string, error)
}
