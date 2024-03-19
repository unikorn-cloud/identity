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

	"github.com/unikorn-cloud/core/pkg/authorization/roles"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GroupPermissions are privilege grants for a project.
type GroupPermissions struct {
	// ID is the unique, immutable project identifier.
	ID string `json:"id"`
	// Roles are the privileges a user has for the group.
	Roles []roles.Role `json:"roles"`
}

// OrganizationPermissions are privilege grants for an organization.
type OrganizationPermissions struct {
	// IsAdmin allows the user to play with all resources in an organization.
	IsAdmin bool `json:"isAdmin,omitempty"`
	// Name is the name of the organization.
	Name string `json:"name"`
	// Groups are any groups the user belongs to in an organization.
	Groups []GroupPermissions `json:"groups,omitempty"`
}

// Permissions are privilege grants for the entire system.
type Permissions struct {
	// IsSuperAdmin HAS SUPER COW POWERS!!!
	IsSuperAdmin bool `json:"isSuperAdmin,omitempty"`
	// Organizations are any organizations the user has access to.
	Organizations []OrganizationPermissions `json:"organizations,omitempty"`
}

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
func (r *RBAC) UserPermissions(ctx context.Context, email string) (*Permissions, error) {
	permissions := &Permissions{}

	organizations, err := r.GetOrganizatons(ctx)
	if err != nil {
		return nil, err
	}

	for _, organization := range organizations.Items {
		organizationPermissions := OrganizationPermissions{}

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
				organizationPermissions.IsAdmin = true
			}

			organizationPermissions.Groups = append(organizationPermissions.Groups, GroupPermissions{
				ID:    group.ID,
				Roles: group.Roles,
			})
		}

		if organizationPermissions.IsAdmin || len(organizationPermissions.Groups) > 0 {
			permissions.Organizations = append(permissions.Organizations, organizationPermissions)
		}
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
