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

package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrResourceReference = errors.New("resource reference error")
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

// groupContainsUser checks if the group contains the user.
func groupContainsUser(group *unikornv1.Group, userID string) bool {
	// Simple check to see if the user is explicitly a member.
	return slices.Contains(group.Spec.UserIDs, userID)
}

// groupContainsServiceAccount checks if the sobject is actuall a service acccount ID.
// TODO: we should be able to derive what the subject is explicitly from the access token.
func groupContainsServiceAccount(group *unikornv1.Group, serviceAccountID string) bool {
	return slices.Contains(group.Spec.ServiceAccountIDs, serviceAccountID)
}

// GetActiveSubjects returns all users who match the subject across all organizations.
func (r *RBAC) GetActiveSubjects(ctx context.Context, subject string) (*unikornv1.UserList, error) {
	result := &unikornv1.UserList{}

	if err := r.client.List(ctx, result, &client.ListOptions{}); err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(user unikornv1.User) bool {
		return user.Spec.Subject != subject && user.Spec.State != unikornv1.UserStateActive
	})

	return result, nil
}

// getUserGroups returns a map of groups the user is a member of, indexed by ID.
func (r *RBAC) getUserGroups(ctx context.Context, user *unikornv1.User) (map[string]*unikornv1.Group, error) {
	result := &unikornv1.GroupList{}

	if err := r.client.List(ctx, result, &client.ListOptions{Namespace: user.Namespace}); err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(group unikornv1.Group) bool {
		return !groupContainsUser(&group, user.Name) && !groupContainsServiceAccount(&group, user.Name)
	})

	out := map[string]*unikornv1.Group{}

	for i := range result.Items {
		out[result.Items[i].Name] = &result.Items[i]
	}

	return out, nil
}

// getRoles returns a map of roles in the system indexed by ID.
func (r *RBAC) getRoles(ctx context.Context) (map[string]*unikornv1.Role, error) {
	result := &unikornv1.RoleList{}

	if err := r.client.List(ctx, result, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return nil, err
	}

	out := map[string]*unikornv1.Role{}

	for i := range result.Items {
		out[result.Items[i].Name] = &result.Items[i]
	}

	return out, nil
}

// getProjects grabs all projects for an organization.
func (r *RBAC) getProjects(ctx context.Context, organizationID string) (*unikornv1.ProjectList, error) {
	requirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationID})
	if err != nil {
		return nil, err
	}

	selector := labels.NewSelector().Add(*requirement)

	result := &unikornv1.ProjectList{}

	if err := r.client.List(ctx, result, &client.ListOptions{LabelSelector: selector}); err != nil {
		return nil, err
	}

	return result, nil
}

// UserExists tells us whether the user is active in any organization.
func (r *RBAC) UserExists(ctx context.Context, subject string) (bool, error) {
	users, err := r.GetActiveSubjects(ctx, subject)
	if err != nil {
		return false, err
	}

	return len(users.Items) > 0, nil
}

func convertOperation(in unikornv1.Operation) openapi.AclOperation {
	switch in {
	case unikornv1.Create:
		return openapi.Create
	case unikornv1.Read:
		return openapi.Read
	case unikornv1.Update:
		return openapi.Update
	case unikornv1.Delete:
		return openapi.Delete
	}

	return ""
}

func convertOperationList(in []unikornv1.Operation) openapi.AclOperations {
	out := make(openapi.AclOperations, len(in))

	for i := range in {
		out[i] = convertOperation(in[i])
	}

	return out
}

// addScopesToEndpointList adds a new scope to the existing list if it doesn't exist,
// or perges permissions with an existing entry.
func addScopesToEndpointList(e *openapi.AclEndpoints, scopes []unikornv1.RoleScope) {
	for _, scope := range scopes {
		operations := convertOperationList(scope.Operations)

		indexFunc := func(ep openapi.AclEndpoint) bool {
			return ep.Name == scope.Name
		}

		// If an existing entry exists, create a union of operations.
		if index := slices.IndexFunc(*e, indexFunc); index >= 0 {
			endpoint := &(*e)[index]

			endpoint.Operations = slices.Concat(endpoint.Operations, operations)
			slices.Sort(endpoint.Operations)

			endpoint.Operations = slices.Compact(endpoint.Operations)

			continue
		}

		// If not add a new entry.
		*e = append(*e, openapi.AclEndpoint{
			Name:       scope.Name,
			Operations: operations,
		})
	}
}

// GetACL returns a granular set of permissions for a user based on their scope.
// This is used for API level access control and UX.
//
//nolint:cyclop,gocognit
func (r *RBAC) GetACL(ctx context.Context, organizationID, subject string) (*openapi.Acl, error) {
	roles, err := r.getRoles(ctx)
	if err != nil {
		return nil, err
	}

	var globalACL openapi.AclEndpoints

	organizationACL := openapi.AclScopedEndpoints{
		Id: organizationID,
	}

	var projectACLs []openapi.AclScopedEndpoints

	// A subject may be part of any organization's group, and may have global endpoints
	// defined, if so add them.
	users, err := r.GetActiveSubjects(ctx, subject)
	if err != nil {
		return nil, err
	}

	for i := range users.Items {
		user := &users.Items[i]

		userOrganizationID, ok := user.Labels[constants.OrganizationLabel]
		if !ok {
			return nil, fmt.Errorf("%w: organization missing from user %s", ErrResourceReference, user.Name)
		}

		groups, err := r.getUserGroups(ctx, user)
		if err != nil {
			return nil, err
		}

		for groupID, group := range groups {
			for _, roleID := range group.Spec.RoleIDs {
				role, ok := roles[roleID]
				if !ok {
					return nil, fmt.Errorf("%w: role %s referenced by group %s does not exist", ErrResourceReference, roleID, groupID)
				}

				// Accumulate global permissions.
				addScopesToEndpointList(&globalACL, role.Spec.Scopes.Global)

				if userOrganizationID == organizationID {
					// Accumulate organization permissions if this user is
					// for the requested scoped organization.
					addScopesToEndpointList(&organizationACL.Endpoints, role.Spec.Scopes.Organization)
				}
			}
		}

		// Pass 2: accumulate any project permissions.
		if userOrganizationID == organizationID {
			projects, err := r.getProjects(ctx, organizationID)
			if err != nil {
				return nil, err
			}

			for _, project := range projects.Items {
				projectACL := openapi.AclScopedEndpoints{
					Id: project.Name,
				}

				for _, groupID := range project.Spec.GroupIDs {
					group, ok := groups[groupID]
					if !ok {
						// This is okay as projects may reference groups
						// we aren't a member of.
						continue
					}

					for _, roleID := range group.Spec.RoleIDs {
						role, ok := roles[roleID]
						if !ok {
							return nil, fmt.Errorf("%w: role %s referenced by group %s does not exist", ErrResourceReference, roleID, groupID)
						}

						addScopesToEndpointList(&projectACL.Endpoints, role.Spec.Scopes.Project)
					}
				}

				if len(projectACL.Endpoints) != 0 {
					projectACLs = append(projectACLs, projectACL)
				}
			}
		}
	}

	acl := &openapi.Acl{}

	if len(globalACL) != 0 {
		acl.Global = &globalACL
	}

	if len(organizationACL.Endpoints) != 0 {
		acl.Organization = &organizationACL
	}

	if len(projectACLs) != 0 {
		acl.Projects = &projectACLs
	}

	return acl, nil
}
