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
	"strings"

	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	"github.com/unikorn-cloud/core/pkg/authorization/roles"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// RBAC contains all the scoping rules for services across the platform.
type RBAC struct {
	client    client.Client
	namespace string
}

// New creates a new RBAC client.
func New(client client.Client, namespace string) *RBAC {
	return &RBAC{
		client:    client,
		namespace: namespace,
	}
}

// GetOrganizatons grabs all organizations for the system.
func (r *RBAC) GetOrganizatons(ctx context.Context) (*unikornv1.OrganizationList, error) {
	var organizations unikornv1.OrganizationList

	if err := r.client.List(ctx, &organizations, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return nil, err
	}

	return &organizations, nil
}

// UserPermissions builds up a hierarchy of permissions for a user, this is used
// both internally and given out to resource servers via token introspection.
//
//nolint:cyclop
func (r *RBAC) UserPermissions(ctx context.Context, email string) (*rbac.Permissions, error) {
	permissions := &rbac.Permissions{}

	organizations, err := r.GetOrganizatons(ctx)
	if err != nil {
		return nil, err
	}

	for _, organization := range organizations.Items {
		var isAdmin bool

		var groups []rbac.GroupPermissions

		for _, group := range organization.Spec.Groups {
			// TODO: implicit groups.
			if !slices.Contains(group.Users, email) {
				continue
			}

			// Hoist super admin powers.
			if slices.Contains(group.Roles, roles.SuperAdmin) {
				permissions.IsSuperAdmin = true
			}

			// Hoist admin powers.
			if slices.Contains(group.Roles, roles.Admin) {
				isAdmin = true
			}

			// Remove any special roles.
			minifiedRoles := slices.DeleteFunc(group.Roles, func(role roles.Role) bool {
				return role == roles.SuperAdmin || role == roles.Admin
			})

			if len(minifiedRoles) == 0 {
				continue
			}

			groups = append(groups, rbac.GroupPermissions{
				ID:    group.ID,
				Roles: minifiedRoles,
			})
		}

		if !isAdmin && len(groups) == 0 {
			continue
		}

		permissions.Organizations = append(permissions.Organizations, rbac.OrganizationPermissions{
			Name:    organization.Name,
			IsAdmin: isAdmin,
			Groups:  groups,
		})
	}

	return permissions, nil
}

// UserExists is an optimized version of the permissions builder that is used to
// authorize authentication requests.  Failure here means the user need to signup
// and register themselves with an organization uing a back-channel.
func (r *RBAC) UserExists(ctx context.Context, email string) (bool, error) {
	parts := strings.Split(email, "@")

	domain := parts[1]

	organizations, err := r.GetOrganizatons(ctx)
	if err != nil {
		return false, err
	}

	for _, organization := range organizations.Items {
		if organization.Spec.Domain != nil && *organization.Spec.Domain == domain {
			return true, nil
		}

		for _, group := range organization.Spec.Groups {
			if slices.Contains(group.Users, email) {
				return true, nil
			}
		}
	}

	return false, nil
}
