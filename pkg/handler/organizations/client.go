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

func (c *Client) List(ctx context.Context) ([]generated.Organization, error) {
	var result unikornv1.OrganizationList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return convertList(&result), nil
}
