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

package oauth2providers

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

func convert(in *unikornv1.OAuth2Provider) *generated.Oauth2Provider {
	out := &generated.Oauth2Provider{
		Name:        in.Name,
		DisplayName: in.Spec.DisplayName,
		Issuer:      in.Spec.Issuer,
		ClientID:    in.Spec.ClientID,
	}

	return out
}

func convertList(in *unikornv1.OAuth2ProviderList) []generated.Oauth2Provider {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.OAuth2Provider) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make([]generated.Oauth2Provider, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context) ([]generated.Oauth2Provider, error) {
	var result unikornv1.OAuth2ProviderList

	if err := c.client.List(ctx, &result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, err
	}

	return convertList(&result), nil
}
