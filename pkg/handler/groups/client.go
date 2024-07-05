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

package groups

import (
	"context"
	"fmt"
	"slices"
	"strings"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Client struct {
	client    client.Client
	namespace string
}

func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func convert(in *unikornv1.Group) *openapi.GroupRead {
	out := &openapi.GroupRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, coreopenapi.ResourceProvisioningStatusProvisioned),
		Spec: openapi.GroupSpec{
			RoleIDs: in.Spec.RoleIDs,
		},
	}

	if len(in.Spec.Users) > 0 {
		out.Spec.Users = &in.Spec.Users
	}

	if len(in.Spec.ProviderGroupNames) > 0 {
		out.Spec.ProviderGroups = &in.Spec.ProviderGroupNames
	}

	return out
}

func convertList(in *unikornv1.GroupList) openapi.Groups {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.Group) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.Groups, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Groups, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.GroupList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list groups").WithError(err)
	}

	return convertList(result), nil
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, groupID string) (*unikornv1.Group, error) {
	result := &unikornv1.Group{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: groupID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get group").WithError(err)
	}

	return result, nil
}

func (c *Client) Get(ctx context.Context, organizationID, groupID string) (*openapi.GroupRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization, groupID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.GroupWrite) (*unikornv1.Group, error) {
	// Validate roles exist.
	for _, roleID := range in.Spec.RoleIDs {
		var resource unikornv1.Role

		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: roleID}, &resource); err != nil {
			if kerrors.IsNotFound(err) {
				return nil, errors.OAuth2InvalidRequest(fmt.Sprintf("role ID %s does not exist", roleID)).WithError(err)
			}

			return nil, errors.OAuth2ServerError("failed to validate role ID").WithError(err)
		}
	}

	// TODO: validate groups exist.
	out := &unikornv1.Group{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace).WithOrganization(organization.ID).Get(ctx),
		Spec: unikornv1.GroupSpec{
			RoleIDs: in.Spec.RoleIDs,
		},
	}

	if in.Spec.Users != nil {
		out.Spec.Users = *in.Spec.Users
	}

	if in.Spec.ProviderGroups != nil {
		out.Spec.ProviderGroupNames = *in.Spec.ProviderGroups
	}

	return out, nil
}

func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.GroupWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.generate(ctx, organization, request)
	if err != nil {
		return err
	}

	if err := c.client.Create(ctx, resource); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return errors.HTTPConflict()
		}

		return errors.OAuth2ServerError("failed to create group").WithError(err)
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationID, groupID string, request *openapi.GroupWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization, groupID)
	if err != nil {
		return err
	}

	required, err := c.generate(ctx, organization, request)
	if err != nil {
		return err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	conversion.UpdateObjectMetadata(updated, required)

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch group").WithError(err)
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationID, groupID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	// TODO: remove the group from any projects.
	resource := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Name:      groupID,
			Namespace: organization.Namespace,
		},
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete group").WithError(err)
	}

	return nil
}
