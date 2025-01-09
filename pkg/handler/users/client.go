/*
Copyright 2025 the Unikorn Authors.

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

package users

import (
	"context"
	"maps"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Client is responsible for user management.
type Client struct {
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
}

// New creates a new user client.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// listGroups returns an exhaustive list of all groups a user can be a member of.
func (c *Client) listGroups(ctx context.Context, organization *organizations.Meta) (*unikornv1.GroupList, error) {
	result := &unikornv1.GroupList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list groups").WithError(err)
	}

	return result, nil
}

// updateGroups takes a user name and a requested list of groups and adds to
// the groups it should be a member of and removes itself from groups it shouldn't.
func (c *Client) updateGroups(ctx context.Context, userName string, groupIDs openapi.GroupIDs, groups *unikornv1.GroupList) error {
	for i := range groups.Items {
		current := &groups.Items[i]

		updated := current.DeepCopy()

		if slices.Contains(groupIDs, current.Name) {
			// Add to a group where it should be a member but isn't.
			if slices.Contains(current.Spec.Users, userName) {
				continue
			}

			updated.Spec.Users = append(updated.Spec.Users, userName)
		} else {
			// Remove from any groups its a member of but shouldn't be.
			if !slices.Contains(current.Spec.Users, userName) {
				continue
			}

			updated.Spec.Users = slices.DeleteFunc(updated.Spec.Users, func(name string) bool {
				return name == userName
			})
		}

		if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
			return errors.OAuth2ServerError("failed to patch group").WithError(err)
		}
	}

	return nil
}

// generateUsers aggregates users from groups in the organization, accumulating group IDs
// along the way.
func (c *Client) generateUsers(groups *unikornv1.GroupList) openapi.Users {
	users := map[string]openapi.User{}

	for _, group := range groups.Items {
		for _, user := range group.Spec.Users {
			u, ok := users[user]
			if !ok {
				u = openapi.User{
					Name: user,
				}
			}

			u.GroupIDs = append(u.GroupIDs, group.Name)

			users[user] = u
		}
	}

	usernames := slices.Collect(maps.Keys(users))
	slices.Sort(usernames)

	out := make(openapi.Users, len(usernames))

	for i, username := range usernames {
		out[i] = users[username]
	}

	return out
}

// Create makes a new user and issues an access token.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.User) (*openapi.User, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if slices.IndexFunc(c.generateUsers(groups), func(user openapi.User) bool { return user.Name == request.Name }) >= 0 {
		return nil, errors.HTTPConflict()
	}

	if err := c.updateGroups(ctx, request.Name, request.GroupIDs, groups); err != nil {
		return nil, err
	}

	return request, nil
}

// List retrieves information about all users in the organization.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.Users, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	return c.generateUsers(groups), nil
}

// Update modifies any metadata for the user if it exists.  If a matching account
// doesn't exist it raises an error.
func (c *Client) Update(ctx context.Context, organizationID, username string, request *openapi.User) (*openapi.User, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, request.Name, request.GroupIDs, groups); err != nil {
		return nil, err
	}

	return request, nil
}

// Delete removes the user and revokes the access token.
func (c *Client) Delete(ctx context.Context, organizationID, username string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return err
	}

	if err := c.updateGroups(ctx, username, nil, groups); err != nil {
		return err
	}

	return nil
}
