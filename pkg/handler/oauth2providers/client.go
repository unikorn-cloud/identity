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

func showDetails(permissions *rbac.Permissions) bool {
	return permissions != nil && permissions.IsSuperAdmin
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, providerID string) (*unikornv1.OAuth2Provider, error) {
	result := &unikornv1.OAuth2Provider{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: providerID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get oauth2 provider").WithError(err)
	}

	return result, nil
}

func convert(permissions *rbac.Permissions, in *unikornv1.OAuth2Provider) *openapi.Oauth2ProviderRead {
	out := &openapi.Oauth2ProviderRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, coreopenapi.ResourceProvisioningStatusProvisioned),
		Spec: openapi.Oauth2ProviderSpec{
			ClientID: in.Spec.ClientID,
		},
	}

	if in.Spec.Type != nil {
		t := openapi.Oauth2ProviderType(*in.Spec.Type)
		out.Spec.Type = &t
	}

	// Only show sensitive details for organizations you are an admin of.
	if showDetails(permissions) {
		out.Spec.ClientSecret = in.Spec.ClientSecret
	}

	return out
}

func convertList(permissions *rbac.Permissions, in *unikornv1.OAuth2ProviderList) openapi.Oauth2Providers {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.OAuth2Provider) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.Oauth2Providers, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(permissions, &in.Items[i])
	}

	return out
}

func (c *Client) ListGlobal(ctx context.Context) (openapi.Oauth2Providers, error) {
	options := &client.ListOptions{
		Namespace: c.namespace,
	}

	var result unikornv1.OAuth2ProviderList

	if err := c.client.List(ctx, &result, options); err != nil {
		return nil, err
	}

	return convertList(userinfo.FromContext(ctx).RBAC, &result), nil
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Oauth2Providers, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.OAuth2ProviderList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to get organization oauth2 provider").WithError(err)
	}

	return convertList(nil, result), nil
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.Oauth2ProviderWrite) *unikornv1.OAuth2Provider {
	userinfo := userinfo.FromContext(ctx)

	out := &unikornv1.OAuth2Provider{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace).WithOrganization(organization.ID).WithUser(userinfo.Subject).Get(),
		Spec: unikornv1.OAuth2ProviderSpec{
			Issuer:       in.Spec.Issuer,
			ClientID:     in.Spec.ClientID,
			ClientSecret: in.Spec.ClientSecret,
		},
	}

	return out
}

func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.Oauth2ProviderWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource := c.generate(ctx, organization, request)

	if err := c.client.Create(ctx, resource); err != nil {
		if kerrors.IsAlreadyExists(err) {
			return errors.HTTPConflict()
		}

		return errors.OAuth2ServerError("failed to create oauth2 provider").WithError(err)
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationID, providerID string, request *openapi.Oauth2ProviderWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization, providerID)
	if err != nil {
		return err
	}

	required := c.generate(ctx, organization, request)

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	conversion.UpdateObjectMetadata(updated, required)

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch oauth2 provider").WithError(err)
	}

	return nil
}

func (c *Client) Delete(ctx context.Context, organizationID, providerID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource := &unikornv1.OAuth2Provider{
		ObjectMeta: metav1.ObjectMeta{
			Name:      providerID,
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
