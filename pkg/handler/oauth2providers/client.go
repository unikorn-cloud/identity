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

	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/generated"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"

	kerrors "k8s.io/apimachinery/pkg/api/errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	organizationProviderName = "default"
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

func showDetails(permissions *rbac.Permissions, global bool) bool {
	// Super admin can see everything, and you can see you own organization.
	return permissions.IsSuperAdmin && !global
}

func convert(permissions *rbac.Permissions, in *unikornv1.OAuth2Provider, global bool) *generated.Oauth2Provider {
	out := &generated.Oauth2Provider{
		Name:        in.Name,
		DisplayName: in.Spec.DisplayName,
		Issuer:      in.Spec.Issuer,
	}

	if in.Spec.Type != nil {
		out.Type = util.ToPointer(generated.Oauth2ProviderType(*in.Spec.Type))
	}

	// Only show sensitive details for organizations you are an admin of.
	if showDetails(permissions, global) {
		out.ClientID = &in.Spec.ClientID
		out.ClientSecret = in.Spec.ClientSecret
	}

	return out
}

func convertList(permissions *rbac.Permissions, in *unikornv1.OAuth2ProviderList, global bool) []generated.Oauth2Provider {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.OAuth2Provider) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make([]generated.Oauth2Provider, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(permissions, &in.Items[i], global)
	}

	return out
}

func (c *Client) ListGlobal(ctx context.Context) ([]generated.Oauth2Provider, error) {
	options := &client.ListOptions{
		Namespace: c.namespace,
	}

	var result unikornv1.OAuth2ProviderList

	if err := c.client.List(ctx, &result, options); err != nil {
		return nil, err
	}

	userinfo := userinfo.FromContext(ctx)

	return convertList(userinfo.RBAC, &result, true), nil
}

func (c *Client) Get(ctx context.Context, organizationName string) (*generated.Oauth2Provider, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.OAuth2Provider{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: organizationProviderName}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound()
		}

		return nil, errors.OAuth2ServerError("failed to get organization oauth2 provider").WithError(err)
	}

	userinfo := userinfo.FromContext(ctx)

	return convert(userinfo.RBAC, result, false), nil
}

func (c *Client) Create(ctx context.Context, organizationName string, request *generated.Oauth2Provider) error {
	_, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationName string, request *generated.Oauth2Provider) error {
	_, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationName string) error {
	_, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return err
	}

	return nil
}
