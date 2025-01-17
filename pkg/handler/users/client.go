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
	"slices"
	"strings"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

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
func (c *Client) updateGroups(ctx context.Context, userID string, groupIDs openapi.GroupIDs, groups *unikornv1.GroupList) error {
	for i := range groups.Items {
		current := &groups.Items[i]

		updated := current.DeepCopy()

		if slices.Contains(groupIDs, current.Name) {
			// Add to a group where it should be a member but isn't.
			if slices.Contains(current.Spec.UserIDs, userID) {
				continue
			}

			updated.Spec.UserIDs = append(updated.Spec.UserIDs, userID)
		} else {
			// Remove from any groups its a member of but shouldn't be.
			if !slices.Contains(current.Spec.UserIDs, userID) {
				continue
			}

			updated.Spec.UserIDs = slices.DeleteFunc(updated.Spec.UserIDs, func(id string) bool {
				return id == userID
			})
		}

		if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
			return errors.OAuth2ServerError("failed to patch group").WithError(err)
		}
	}

	return nil
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, userID string) (*unikornv1.User, error) {
	result := &unikornv1.User{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: userID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get user").WithError(err)
	}

	return result, nil
}

func generateUserState(in openapi.UserState) unikornv1.UserState {
	switch in {
	case openapi.Active:
		return unikornv1.UserStateActive
	case openapi.Pending:
		return unikornv1.UserStatePending
	case openapi.Suspended:
		return unikornv1.UserStateSuspended
	}

	return ""
}

func generate(ctx context.Context, organization *organizations.Meta, in *openapi.UserWrite) (*unikornv1.User, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("userinfo is not set").WithError(err)
	}

	metadata := &coreopenapi.ResourceWriteMetadata{
		Name: "undefined",
	}

	out := &unikornv1.User{
		ObjectMeta: conversion.NewObjectMetadata(metadata, organization.Namespace, userinfo.Sub).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.UserSpec{
			Subject: in.Spec.Subject,
			State:   generateUserState(in.Spec.State),
		},
	}

	if in.Metadata != nil {
		out.Spec.Tags = conversion.GenerateTagList(in.Metadata.Tags)
	}

	return out, nil
}

func convertUserState(in unikornv1.UserState) openapi.UserState {
	switch in {
	case unikornv1.UserStateActive:
		return openapi.Active
	case unikornv1.UserStatePending:
		return openapi.Pending
	case unikornv1.UserStateSuspended:
		return openapi.Suspended
	}

	return ""
}

func convert(in *unikornv1.User, groups *unikornv1.GroupList) *openapi.UserRead {
	out := &openapi.UserRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags, coreopenapi.ResourceProvisioningStatusProvisioned),
		Spec: openapi.UserSpec{
			Subject: in.Spec.Subject,
			State:   convertUserState(in.Spec.State),
		},
	}

	if in.Spec.LastActive != nil {
		out.Status.LastActive = &in.Spec.LastActive.Time
	}

	for _, group := range groups.Items {
		if slices.Contains(group.Spec.UserIDs, in.Name) {
			out.Spec.GroupIDs = append(out.Spec.GroupIDs, group.Name)
		}
	}

	return out
}

func convertList(in *unikornv1.UserList, groups *unikornv1.GroupList) openapi.Users {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.User) int {
		return strings.Compare(a.Spec.Subject, b.Spec.Subject)
	})

	out := make(openapi.Users, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i], groups)
	}

	return out
}

// Create makes a new user and issues an access token.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.UserWrite) (*openapi.UserRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("failed to create user").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, resource.Name, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	return convert(resource, groups), nil
}

// List retrieves information about all users in the organization.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.Users, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.UserList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list users").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	return convertList(result, groups), nil
}

// Update modifies any metadata for the user if it exists.  If a matching account
// doesn't exist it raises an error.
func (c *Client) Update(ctx context.Context, organizationID, userID string, request *openapi.UserWrite) (*openapi.UserRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, organization, userID)
	if err != nil {
		return nil, err
	}

	required, err := generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, nil, nil); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch group").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return nil, err
	}

	if err := c.updateGroups(ctx, userID, request.Spec.GroupIDs, groups); err != nil {
		return nil, err
	}

	// Reload post update...
	if groups, err = c.listGroups(ctx, organization); err != nil {
		return nil, err
	}

	return convert(updated, groups), nil
}

// Delete removes the user and revokes the access token.
func (c *Client) Delete(ctx context.Context, organizationID, userID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization, userID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to get user for delete").WithError(err)
	}

	groups, err := c.listGroups(ctx, organization)
	if err != nil {
		return err
	}

	if err := c.updateGroups(ctx, userID, nil, groups); err != nil {
		return err
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete user").WithError(err)
	}

	return nil
}
