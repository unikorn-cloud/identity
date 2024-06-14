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

package authorization

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/unikorn-cloud/core/pkg/authorization/constants"
	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

var (
	ErrResponse = errors.New("unexpected response")
)

// IdentityACLGetter grabs an ACL for the user from the identity API.
// Used for any non-identity API.
type IdentityACLGetter struct {
	// client and initialized identity client.
	client identityapi.ClientWithResponsesInterface
	// The organization this user is trying to access.
	organizationID string
}

// Ensure the interface is correctly implemented.
var _ rbac.ACLGetter = &IdentityACLGetter{}

func NewIdentityACLGetter(client identityapi.ClientWithResponsesInterface, organizationID string) *IdentityACLGetter {
	return &IdentityACLGetter{
		client:         client,
		organizationID: organizationID,
	}
}

// TODO: this is a typed mess!
func convertPermission(in string) constants.Permission {
	return constants.Permission(in)
}

func convertPermissions(in identityapi.AclPermissions) []constants.Permission {
	if in == nil {
		return nil
	}

	out := make([]constants.Permission, len(in))

	for i, permission := range in {
		out[i] = convertPermission(permission)
	}

	return out
}

func convertScope(in *identityapi.AclScope) *rbac.Scope {
	out := &rbac.Scope{
		Name:        in.Name,
		Permissions: convertPermissions(in.Permissions),
	}

	return out
}

func convertScopes(in *identityapi.AclScopes) []*rbac.Scope {
	if in == nil {
		return nil
	}

	in2 := *in

	out := make([]*rbac.Scope, len(*in))

	for i := range in2 {
		out[i] = convertScope(&in2[i])
	}

	return out
}

func convert(in identityapi.Acl) *rbac.ACL {
	out := &rbac.ACL{
		Scopes: convertScopes(in.Scopes),
	}

	if in.IsSuperAdmin != nil {
		out.IsSuperAdmin = *in.IsSuperAdmin
	}

	return out
}

func (a *IdentityACLGetter) Get(ctx context.Context) (*rbac.ACL, error) {
	resp, err := a.client.GetApiV1OrganizationsOrganizationIDAclWithResponse(ctx, a.organizationID)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: status code not as expected", ErrResponse)
	}

	result := *resp.JSON200

	return convert(result), nil
}
