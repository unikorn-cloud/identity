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
	"slices"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"

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

// getOrganizations grabs all organizations for the system.
func (r *RBAC) getOrganizations(ctx context.Context) (*unikornv1.OrganizationList, error) {
	var organizations unikornv1.OrganizationList

	if err := r.client.List(ctx, &organizations, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return nil, err
	}

	return &organizations, nil
}

// groupContainsUser checks if the group contains the user.
// TODO: implied group membership needs doing.
func groupContainsUser(group *unikornv1.Group, subject string) bool {
	// Simple check to see if the user is explicitly a member.
	return slices.Contains(group.Spec.Users, subject)
}

// groupContainsServiceAccount checks if the sobject is actuall a service acccount ID.
// TODO: we should be able to derive what the subject is explicitly from the access token.
func groupContainsServiceAccount(group *unikornv1.Group, subject string) bool {
	return slices.Contains(group.Spec.ServiceAccountIDs, subject)
}

// getGroupsWithMembership grabs all groups for an organization that contain the subject.
func (r *RBAC) getGroupsWithMembership(ctx context.Context, organization *unikornv1.Organization, subject string) (*unikornv1.GroupList, error) {
	result := &unikornv1.GroupList{}

	if err := r.client.List(ctx, result, &client.ListOptions{Namespace: organization.Status.Namespace}); err != nil {
		return nil, err
	}

	result.Items = slices.DeleteFunc(result.Items, func(resource unikornv1.Group) bool {
		return !groupContainsUser(&resource, subject) && !groupContainsServiceAccount(&resource, subject)
	})

	return result, nil
}

// OrganizationMemberships is an organization with groups a user is a member of.
type OrganizationMemberships struct {
	Organization *unikornv1.Organization
	Groups       *unikornv1.GroupList
}

func (o *OrganizationMemberships) GetGroup(groupID string) *unikornv1.Group {
	for i := range o.Groups.Items {
		if o.Groups.Items[i].Name == groupID {
			return &o.Groups.Items[i]
		}
	}

	return nil
}

// GetOrganizationMemberships returns a list of organizations we have membership of and
// the groups we are members of.
func (r *RBAC) GetOrganizationMemberships(ctx context.Context, subject string) ([]OrganizationMemberships, error) {
	organizations, err := r.getOrganizations(ctx)
	if err != nil {
		return nil, err
	}

	var result []OrganizationMemberships

	for i := range organizations.Items {
		organization := &organizations.Items[i]

		groups, err := r.getGroupsWithMembership(ctx, organization, subject)
		if err != nil {
			return nil, err
		}

		if len(groups.Items) > 0 {
			result = append(result, OrganizationMemberships{
				Organization: organization,
				Groups:       groups,
			})
		}
	}

	return result, nil
}

// getProjects grabs all projects for an organization.
func (r *RBAC) getProjects(ctx context.Context, organization *unikornv1.Organization) (*unikornv1.ProjectList, error) {
	result := &unikornv1.ProjectList{}

	if err := r.client.List(ctx, result, &client.ListOptions{Namespace: organization.Status.Namespace}); err != nil {
		return nil, err
	}

	return result, nil
}

// UserExists is an optimized version of the permissions builder that is used to
// authorize authentication requests.  Failure here means the user need to signup
// and register themselves with an organization uing a back-channel.
func (r *RBAC) UserExists(ctx context.Context, subject string) (bool, error) {
	organizations, err := r.getOrganizations(ctx)
	if err != nil {
		return false, err
	}

	for i := range organizations.Items {
		organization := &organizations.Items[i]

		// If the user is a member of a group in an organization, let them in.
		// Doing otherwise would be pointless as the user wouldn't be able to
		// do anything, and we shouldn't allow global APIs to be accessed without
		// some form of authorization.
		groups, err := r.getGroupsWithMembership(ctx, organization, subject)
		if err != nil {
			return false, err
		}

		if len(groups.Items) > 0 {
			return true, nil
		}
	}

	return false, nil
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
	var globalACL openapi.AclEndpoints

	organizationACL := openapi.AclScopedEndpoints{
		Id: organizationID,
	}

	var projectACLs []openapi.AclScopedEndpoints

	// A subject may be part of any organization's group, and may have global endpoints
	// defined, if so add them.
	memberships, err := r.GetOrganizationMemberships(ctx, subject)
	if err != nil {
		return nil, err
	}

	for _, membership := range memberships {
		for _, group := range membership.Groups.Items {
			for _, roleID := range group.Spec.RoleIDs {
				var role unikornv1.Role

				if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: roleID}, &role); err != nil {
					return nil, err
				}

				addScopesToEndpointList(&globalACL, role.Spec.Scopes.Global)

				// While we are here, if the organization is the correct one
				// add any organization endpoints to the organization scope.
				if organizationID == membership.Organization.Name {
					addScopesToEndpointList(&organizationACL.Endpoints, role.Spec.Scopes.Organization)
				}
			}
		}

		// If the organization is the one we are requesting, we need to check each project
		// for user membership, if so add any project scoped endpoints to the ACL.
		if organizationID == membership.Organization.Name {
			projects, err := r.getProjects(ctx, membership.Organization)
			if err != nil {
				return nil, err
			}

			for _, project := range projects.Items {
				projectACL := openapi.AclScopedEndpoints{
					Id: project.Name,
				}

				for _, groupID := range project.Spec.GroupIDs {
					group := membership.GetGroup(groupID)
					if group == nil {
						continue
					}

					for _, roleID := range group.Spec.RoleIDs {
						var role unikornv1.Role

						if err := r.client.Get(ctx, client.ObjectKey{Namespace: r.namespace, Name: roleID}, &role); err != nil {
							return nil, err
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
