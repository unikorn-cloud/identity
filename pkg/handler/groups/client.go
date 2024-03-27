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

	"github.com/unikorn-cloud/core/pkg/authorization/roles"
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

func convertRoleList(in []roles.Role) generated.RoleList {
	out := make([]string, len(in))

	for i, role := range in {
		out[i] = string(role)
	}

	return out
}

func convert(in *unikornv1.OrganizationGroup) *generated.Group {
	out := &generated.Group{
		Id:    in.ID,
		Name:  in.Name,
		Roles: convertRoleList(in.Roles),
	}

	if len(in.Users) > 0 {
		out.Users = &in.Users
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
