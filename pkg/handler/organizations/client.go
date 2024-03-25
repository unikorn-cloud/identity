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

func (c *Client) List(ctx context.Context) ([]generated.Organization, error) {
	var result unikornv1.OrganizationList

	// TODO: we should use RBAC, but that needs an organiation to start with.
	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	userinfo := userinfo.FromContext(ctx)

	result.Items = slices.DeleteFunc(result.Items, func(item unikornv1.Organization) bool {
		return !hasAccess(userinfo.RBAC, item.Name)
	})

	return convertList(&result), nil
}
