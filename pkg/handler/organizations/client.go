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

package organizations

import (
	"context"
	"slices"
	"strings"

	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/generated"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

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

// Meta describes the organization.
type Meta struct {
	// Name is the organization's Kubernetes name, so a higher level resource
	// can reference it.
	Name string

	// Namespace is the namespace that is provisioned by the organization.
	// Should be usable set when the organization is active.
	Namespace string

	// Deleting tells us if we should allow new child objects to be created
	// in this resource's namespace.
	Deleting bool
}

// GetMetadata retrieves the organization metadata.
// Clients should consult at least the Active status before doing anything
// with the organization.
func (c *Client) GetMetadata(ctx context.Context, name string) (*Meta, error) {
	result, err := c.get(ctx, name)
	if err != nil {
		return nil, err
	}

	metadata := &Meta{
		Name:      name,
		Namespace: result.Status.Namespace,
		Deleting:  result.DeletionTimestamp != nil,
	}

	return metadata, nil
}

func convert(in *unikornv1.Organization) *generated.Organization {
	// Note: do not expose more to a regular user than is required here
	// e.g. group membership etc.
	out := &generated.Organization{
		Name:         in.Name,
		Domain:       in.Spec.Domain,
		ProviderName: in.Spec.ProviderName,
	}

	return out
}

func convertList(in *unikornv1.OrganizationList) []generated.Organization {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.Organization) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make([]generated.Organization, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func hasAccess(permissions *rbac.Permissions, name string) bool {
	if permissions.IsSuperAdmin {
		return true
	}

	for _, organization := range permissions.Organizations {
		if organization.Name == name {
			return true
		}
	}

	return false
}

// get returns the implicit organization identified by the JWT claims.
func (c *Client) get(ctx context.Context, name string) (*unikornv1.Organization, error) {
	// TODO: hasAccess()
	result := &unikornv1.Organization{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: name}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get organization").WithError(err)
	}

	return result, nil
}

func (c *Client) List(ctx context.Context) ([]generated.Organization, error) {
	var result unikornv1.OrganizationList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	userinfo := userinfo.FromContext(ctx)

	result.Items = slices.DeleteFunc(result.Items, func(item unikornv1.Organization) bool {
		return !hasAccess(userinfo.RBAC, item.Name)
	})

	return convertList(&result), nil
}
