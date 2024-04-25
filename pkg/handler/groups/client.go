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
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/generated"

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

func convert(in *unikornv1.OrganizationGroup) *generated.Group {
	out := &generated.Group{
		Id:    in.ID,
		Name:  in.Name,
		Roles: in.Roles,
	}

	if len(in.Users) > 0 {
		out.Users = &in.Users
	}

	if len(in.ProviderGroupNames) > 0 {
		out.ProviderGroups = &in.ProviderGroupNames
	}

	return out
}

func convertList(in []unikornv1.OrganizationGroup) generated.Groups {
	slices.SortStableFunc(in, func(a, b unikornv1.OrganizationGroup) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(generated.Groups, len(in))

	for i := range in {
		out[i] = *convert(&in[i])
	}

	return out
}

func (c *Client) List(ctx context.Context, organizationName string) (generated.Groups, error) {
	var organization unikornv1.Organization

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationName}, &organization); err != nil {
		return nil, err
	}

	return convertList(organization.Spec.Groups), nil
}

func (c *Client) Get(ctx context.Context, organizationName, groupID string) (*generated.Group, error) {
	var organization unikornv1.Organization

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationName}, &organization); err != nil {
		return nil, errors.OAuth2ServerError("failed to read organization").WithError(err)
	}

	index := slices.IndexFunc(organization.Spec.Groups, func(group unikornv1.OrganizationGroup) bool {
		return group.ID == groupID
	})

	if index < 0 {
		return nil, errors.HTTPNotFound()
	}

	return convert(&organization.Spec.Groups[index]), nil
}

func generate(in *generated.Group) unikornv1.OrganizationGroup {
	out := unikornv1.OrganizationGroup{
		ID:    uuid.New().String(),
		Name:  in.Name,
		Roles: in.Roles,
	}

	if in.Users != nil {
		out.Users = *in.Users
	}

	if in.ProviderGroups != nil {
		out.ProviderGroupNames = *in.ProviderGroups
	}

	return out
}

func (c *Client) Create(ctx context.Context, organizationName string, group *generated.Group) error {
	var organization unikornv1.Organization

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationName}, &organization); err != nil {
		return errors.OAuth2ServerError("failed to read organization").WithError(err)
	}

	organization.Spec.Groups = append(organization.Spec.Groups, generate(group))

	if err := c.client.Update(ctx, &organization); err != nil {
		return errors.OAuth2ServerError("failed to update organization").WithError(err)
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationName, groupID string, group *generated.Group) error {
	var organization unikornv1.Organization

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationName}, &organization); err != nil {
		return errors.OAuth2ServerError("failed to read organization").WithError(err)
	}

	// Preserve the group ID, generate() will create a new one.
	newGroup := generate(group)
	newGroup.ID = groupID

	temp := organization.DeepCopy()

	for i, existing := range temp.Spec.Groups {
		if newGroup.ID != existing.ID {
			continue
		}

		temp.Spec.Groups[i] = newGroup

		break
	}

	if err := c.client.Patch(ctx, temp, client.MergeFrom(&organization)); err != nil {
		return errors.OAuth2ServerError("failed to patch cluster").WithError(err)
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationName, groupID string) error {
	var organization unikornv1.Organization

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationName}, &organization); err != nil {
		return errors.OAuth2ServerError("failed to read organization").WithError(err)
	}

	organization.Spec.Groups = slices.DeleteFunc(organization.Spec.Groups, func(group unikornv1.OrganizationGroup) bool {
		return group.ID == groupID
	})

	if err := c.client.Update(ctx, &organization); err != nil {
		return errors.OAuth2ServerError("failed to update organization").WithError(err)
	}

	return nil
}
