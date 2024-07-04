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

package rbac

import (
	"context"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/openapi"
)

// allowEndpoints iterates through all endpoints and tries to match the required name and
// operation.
func allowEndpoints(endpoints openapi.AclEndpoints, endpoint string, operation openapi.AclOperation) error {
	for _, e := range endpoints {
		if e.Name != endpoint {
			continue
		}

		if !slices.Contains(e.Operations, operation) {
			continue
		}

		return nil
	}

	return errors.HTTPForbidden("operation is not allowed by rbac (no matching endpoint)")
}

// AllowGlobalScope tries to allow the requested operation at the global scope.
func AllowGlobalScope(ctx context.Context, endpoint string, operation openapi.AclOperation) error {
	acl := FromContext(ctx)

	if acl.Global == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no global endpoints)")
	}

	return allowEndpoints(*acl.Global, endpoint, operation)
}

// AllowOrganizationScope tries to allow the requested operation at the global scope, then
// the organization scope.
func AllowOrganizationScope(ctx context.Context, endpoint string, operation openapi.AclOperation, organizationID string) error {
	if AllowGlobalScope(ctx, endpoint, operation) == nil {
		return nil
	}

	acl := FromContext(ctx)

	if acl.Organization == nil || acl.Organization.Id != organizationID {
		return errors.HTTPForbidden("operation is not allowed by rbac (no matching organization endpoints)")
	}

	return allowEndpoints(acl.Organization.Endpoints, endpoint, operation)
}

// AllowProjectScope tries to allow the requested operation at the global scope, then
// the organization scope, and finally at the project scope.
func AllowProjectScope(ctx context.Context, endpoint string, operation openapi.AclOperation, organizationID, projectID string) error {
	if AllowOrganizationScope(ctx, endpoint, operation, organizationID) == nil {
		return nil
	}

	acl := FromContext(ctx)

	if acl.Projects == nil {
		return errors.HTTPForbidden("operation is not allowed by rbac (no project endpoints)")
	}

	for _, project := range *acl.Projects {
		if project.Id != projectID {
			continue
		}

		if err := allowEndpoints(project.Endpoints, endpoint, operation); err == nil {
			return nil
		}
	}

	return errors.HTTPForbidden("operation is not allowed by rbac (no matching project endpoints)")
}
