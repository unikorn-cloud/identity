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
	coreconstants "github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/constants"
	"github.com/unikorn-cloud/identity/pkg/generated"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"

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

func showDetails(permissions *rbac.Permissions) bool {
	return permissions != nil && permissions.IsSuperAdmin
}

func (c *Client) get(ctx context.Context, namespace, name string) (*unikornv1.OAuth2Provider, error) {
	result := &unikornv1.OAuth2Provider{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get oauth2 provider").WithError(err)
	}

	return result, nil
}

func convert(permissions *rbac.Permissions, in *unikornv1.OAuth2Provider) *generated.Oauth2Provider {
	out := &generated.Oauth2Provider{
		Name:        in.Name,
		DisplayName: in.Spec.DisplayName,
		Issuer:      in.Spec.Issuer,
	}

	if in.Spec.Type != nil {
		out.Type = util.ToPointer(generated.Oauth2ProviderType(*in.Spec.Type))
	}

	// Only show sensitive details for organizations you are an admin of.
	if showDetails(permissions) {
		out.ClientID = &in.Spec.ClientID
		out.ClientSecret = in.Spec.ClientSecret
	}

	return out
}

func convertList(permissions *rbac.Permissions, in *unikornv1.OAuth2ProviderList) []generated.Oauth2Provider {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.OAuth2Provider) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make([]generated.Oauth2Provider, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(permissions, &in.Items[i])
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

	return convertList(userinfo.FromContext(ctx).RBAC, &result), nil
}

func (c *Client) List(ctx context.Context, organizationName string) (generated.Oauth2Providers, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.OAuth2ProviderList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound()
		}

		return nil, errors.OAuth2ServerError("failed to get organization oauth2 provider").WithError(err)
	}

	return convertList(nil, result), nil
}

func (c *Client) generate(organization *organizations.Meta, in *generated.Oauth2ProviderCreate) *unikornv1.OAuth2Provider {
	out := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: organization.Namespace,
			Name:      in.Name,
			Labels: map[string]string{
				coreconstants.VersionLabel:      constants.Version,
				coreconstants.OrganizationLabel: organization.Name,
			},
		},
		Spec: unikornv1.OAuth2ProviderSpec{
			DisplayName:  in.DisplayName,
			Issuer:       in.Issuer,
			ClientID:     in.ClientID,
			ClientSecret: in.ClientSecret,
		},
	}

	return out
}

func (c *Client) Create(ctx context.Context, organizationName string, request *generated.Oauth2ProviderCreate) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return err
	}

	resource := c.generate(organization, request)

	if err := c.client.Create(ctx, resource); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return errors.HTTPConflict()
		}

		return errors.OAuth2ServerError("failed to create oauth2 provider").WithError(err)
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationName string, name string, request *generated.Oauth2ProviderCreate) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization.Namespace, name)
	if err != nil {
		return err
	}

	newResource := c.generate(organization, request)

	temp := resource.DeepCopy()
	temp.Spec = newResource.Spec

	if err := c.client.Patch(ctx, temp, client.MergeFrom(resource)); err != nil {
		return errors.OAuth2ServerError("failed to patch oauth2 provider").WithError(err)
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationName, name string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationName)
	if err != nil {
		return err
	}

	resource := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: organization.Namespace,
		},
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete oauth2 provider").WithError(err)
	}

	return nil
}
