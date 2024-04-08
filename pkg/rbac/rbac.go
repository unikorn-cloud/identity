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

	"github.com/unikorn-cloud/core/pkg/authorization/constants"
	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

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

// getOrganizatons grabs all organizations for the system.
func (r *RBAC) getOrganizatons(ctx context.Context) (*unikornv1.OrganizationList, error) {
	var organizations unikornv1.OrganizationList

	if err := r.client.List(ctx, &organizations, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return nil, err
	}

	return &organizations, nil
}

func (r *RBAC) organizationGroups(organization *unikornv1.Organization, email string) ([]rbac.GroupPermissions, bool) {
	//nolint:prealloc
	var groups []rbac.GroupPermissions

	for _, group := range organization.Spec.Groups {
		// TODO: implicit groups.
		if !slices.Contains(group.Users, email) {
			continue
		}

		// Hoist super admin powers.
		if slices.Contains(group.Roles, constants.SuperAdmin) {
			return nil, true
		}

		// Remove any special roles.
		minifiedRoles := slices.DeleteFunc(group.Roles, func(role string) bool {
			return role == constants.SuperAdmin
		})

		if len(minifiedRoles) == 0 {
			continue
		}

		groups = append(groups, rbac.GroupPermissions{
			ID:    group.ID,
			Roles: minifiedRoles,
		})
	}

	return groups, false
}

func (r *RBAC) organizationProjects(ctx context.Context, organization *unikornv1.Organization, groups []rbac.GroupPermissions) ([]rbac.ProjectPermissions, error) {
	orgRequirement, err := labels.NewRequirement(coreconstants.OrganizationLabel, selection.Equals, []string{organization.Name})
	if err != nil {
		return nil, err
	}

	selector := labels.NewSelector()
	selector = selector.Add(*orgRequirement)

	options := &client.ListOptions{
		LabelSelector: selector,
	}

	result := &unikornv1.ProjectList{}

	if err := r.client.List(ctx, result, options); err != nil {
		return nil, err
	}

	//nolint:prealloc
	var projectPermissions []rbac.ProjectPermissions

	for _, project := range result.Items {
		var roles []string

		// Accumulate any roles we have on a project if we are a member of a
		// group that has access to the project, or if we have admin access.
		for _, group := range groups {
			if !slices.Contains(project.Spec.GroupIDs, group.ID) && !slices.Contains(group.Roles, "admin") {
				continue
			}

			roles = append(roles, group.Roles...)
		}

		if len(roles) == 0 {
			continue
		}

		slices.Sort(roles)

		projectPermissions = append(projectPermissions, rbac.ProjectPermissions{
			Name:  project.Name,
			Roles: slices.Compact(roles),
		})
	}

	return projectPermissions, nil
}

// UserPermissions builds up a hierarchy of permissions for a user, this is used
// both internally and given out to resource servers via token introspection.
func (r *RBAC) UserPermissions(ctx context.Context, email string) (*rbac.Permissions, error) {
	permissions := &rbac.Permissions{}

	organizations, err := r.getOrganizatons(ctx)
	if err != nil {
		return nil, err
	}

	for i := range organizations.Items {
		organization := &organizations.Items[i]

		groups, isSuperAdmin := r.organizationGroups(organization, email)
		if isSuperAdmin {
			permissions.IsSuperAdmin = true
		}

		if len(groups) == 0 {
			continue
		}

		projects, err := r.organizationProjects(ctx, organization, groups)
		if err != nil {
			return nil, err
		}

		permissions.Organizations = append(permissions.Organizations, rbac.OrganizationPermissions{
			Name:     organization.Name,
			Groups:   groups,
			Projects: projects,
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

	organizations, err := r.getOrganizatons(ctx)
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

// GetACL returns a granualr set of permissions for a user based on their scope.
// This is used for API leval access control and UX.
func (r *RBAC) GetACL(ctx context.Context, permissions *rbac.Permissions, organization string) (*rbac.ACL, error) {
	// Super user gets everything, so shortcut.
	if permissions.IsSuperAdmin {
		acl := &rbac.ACL{
			IsSuperAdmin: true,
		}

		return acl, nil
	}

	// If this is scoped to an organization, do the lookup and deny entry if the user
	// is not part of the organization.
	var organizationPermissions *rbac.OrganizationPermissions

	if organization != "" {
		temp, err := permissions.LookupOrganization(organization)
		if err != nil {
			return nil, err
		}

		organizationPermissions = temp
	}

	var roles unikornv1.RoleList

	if err := r.client.List(ctx, &roles, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return nil, err
	}

	acl := &rbac.ACL{}

	for _, role := range roles.Items {
		// If it's not a default role that everyone gets, or the user doesn't have
		// access to it, ignore.
		if !role.Spec.IsDefault && !organizationPermissions.HasRole(role.Name) {
			continue
		}

		for _, scope := range role.Spec.Scopes {
			// Lookup the scope, it may be defined by a different role already,
			// if it doesn't exist, create it and add to the ACL.
			aclScope := acl.GetScope(scope.Name)

			if aclScope == nil {
				aclScope = &rbac.Scope{
					Name: scope.Name,
				}

				acl.Scopes = append(acl.Scopes, aclScope)
			}

			// Do a boolean union of existing permissions and any new ones.
			permissions := slices.Concat(aclScope.Permissions, scope.Permissions)

			slices.Sort(permissions)

			aclScope.Permissions = slices.Compact(permissions)
		}
	}

	return acl, nil
}
