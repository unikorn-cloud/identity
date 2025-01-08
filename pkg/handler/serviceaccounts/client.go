/*
Copyright 2025 the Unikorn Authors.

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

package serviceaccounts

import (
	"context"
	"slices"
	"time"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Options struct {
	// defaultDuration is the length of time an access token lives for if not
	// specified.
	defaultDuration time.Duration
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.defaultDuration, "default-service-account-token-lifetime", time.Hour*24*90, "Default service account token lifetime, defaults to 90 days")
}

// Client is responsible for service account management.
type Client struct {
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
	// host is the hostname of this service.
	host string
	// oauth2 is used to issue access tokens.
	oauth2 *oauth2.Authenticator
	// options are any deployment defaults.
	options *Options
}

// New creates a new service account client.
func New(client client.Client, namespace, host string, oauth2 *oauth2.Authenticator, options *Options) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		host:      host,
		oauth2:    oauth2,
		options:   options,
	}
}

// convert converts from Kubernetes into OpenAPI for normal read requests.
func convert(in *unikornv1.ServiceAccount) *openapi.ServiceAccountRead {
	out := &openapi.ServiceAccountRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, in.Spec.Tags, coreopenapi.ResourceProvisioningStatusProvisioned),
		Spec: openapi.ServiceAccountSpec{
			Expiry: in.Spec.Expiry.Time,
		},
	}

	return out
}

// convertCreate converts from Kubernetes into OpenAPi for create/update requests that
// have extra information e.g. the access token.
func convertCreate(in *unikornv1.ServiceAccount) *openapi.ServiceAccountCreate {
	temp := convert(in)

	out := &openapi.ServiceAccountCreate{
		Metadata: temp.Metadata,
		Spec:     temp.Spec,
		Status: openapi.ServiceAccountStatus{
			AccessToken: in.Spec.AccessToken,
		},
	}

	return out
}

func convertList(in *unikornv1.ServiceAccountList) openapi.ServiceAccounts {
	out := make(openapi.ServiceAccounts, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) generate(ctx context.Context, organization *organizations.Meta, in *openapi.ServiceAccountWrite) (*unikornv1.ServiceAccount, error) {
	userinfo, err := authorization.UserinfoFromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("userinfo is not set").WithError(err)
	}

	issueInfo := &oauth2.IssueInfo{
		Issuer:   "https://" + c.host,
		Audience: c.host,
		Subject:  in.Metadata.Name,
		ServiceAccount: &oauth2.ServiceAccount{
			OrganizationID: organization.ID,
			// TODO: allow the client to override this, but keep it capped to
			// some server controlled value.
			Duration: &c.options.defaultDuration,
		},
	}

	tokens, err := c.oauth2.Issue(ctx, issueInfo)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to issue access token").WithError(err)
	}

	out := &unikornv1.ServiceAccount{
		ObjectMeta: conversion.NewObjectMetadata(&in.Metadata, organization.Namespace, userinfo.Sub).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.ServiceAccountSpec{
			Tags:        conversion.GenerateTagList(in.Metadata.Tags),
			AccessToken: tokens.AccessToken,
			Expiry: &metav1.Time{
				Time: tokens.Expiry,
			},
		},
	}

	return out, nil
}

// Create makes a new service account and issues an access token.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.ServiceAccountWrite) (*openapi.ServiceAccountCreate, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	resource, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to generate service account").WithError(err)
	}

	if err := c.client.Create(ctx, resource); err != nil {
		return nil, errors.OAuth2ServerError("failed to create service account").WithError(err)
	}

	return convertCreate(resource), nil
}

// get retrieves the service account.
func (c *Client) get(ctx context.Context, organization *organizations.Meta, serviceAccountID string) (*unikornv1.ServiceAccount, error) {
	result := &unikornv1.ServiceAccount{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: serviceAccountID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get service account").WithError(err)
	}

	return result, nil
}

// Get retrieves information about a service account.
func (c *Client) Get(ctx context.Context, organizationID, serviceAccountID string) (*openapi.ServiceAccountRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

// List retrieves information about all service accounts in the organization.
func (c *Client) List(ctx context.Context, organizationID string) (openapi.ServiceAccounts, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result := &unikornv1.ServiceAccountList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list service accounts").WithError(err)
	}

	return convertList(result), nil
}

// Update modifies any metadata for the service account if it exists.  If a matching account
// doesn't exist it raises an error.
func (c *Client) Update(ctx context.Context, organizationID, serviceAccountID string, request *openapi.ServiceAccountWrite) (*openapi.ServiceAccountRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	required, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, nil, nil); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations

	// Preserve the access token etc. across metadata updates.
	updated.Spec = current.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch group").WithError(err)
	}

	return convert(updated), nil
}

// Rotate is a special version of Update where everything about the resource is preserved
// with the exception of the access token.
func (c *Client) Rotate(ctx context.Context, organizationID, serviceAccountID string) (*openapi.ServiceAccountCreate, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		return nil, err
	}

	request := &openapi.ServiceAccountWrite{
		Metadata: coreopenapi.ResourceWriteMetadata{
			Name: current.Labels[constants.NameLabel],
		},
	}

	required, err := c.generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	if err := conversion.UpdateObjectMetadata(required, current, nil, nil); err != nil {
		return nil, errors.OAuth2ServerError("failed to merge metadata").WithError(err)
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch group").WithError(err)
	}

	c.oauth2.InvalidateToken(ctx, current.Spec.AccessToken)

	return convertCreate(updated), nil
}

// Delete removes the service account and revokes the access token.
func (c *Client) Delete(ctx context.Context, organizationID, serviceAccountID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource, err := c.get(ctx, organization, serviceAccountID)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to get service account for delete").WithError(err)
	}

	// Unlink the service account from any groups that reference it.
	groups := &unikornv1.GroupList{}

	if err := c.client.List(ctx, groups, &client.ListOptions{Namespace: organization.Namespace}); err != nil {
		return errors.OAuth2ServerError("failed to list organization groups").WithError(err)
	}

	groups.Items = slices.DeleteFunc(groups.Items, func(group unikornv1.Group) bool {
		return !slices.Contains(group.Spec.Users, resource.Labels[constants.NameLabel])
	})

	for i := range groups.Items {
		group := &groups.Items[i]

		group.Spec.Users = slices.DeleteFunc(group.Spec.Users, func(name string) bool {
			return name == resource.Labels[constants.NameLabel]
		})

		if err := c.client.Update(ctx, group); err != nil {
			return errors.OAuth2ServerError("failed to remove service account from group").WithError(err)
		}
	}

	if err := c.client.Delete(ctx, resource); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete service account").WithError(err)
	}

	c.oauth2.InvalidateToken(ctx, resource.Spec.AccessToken)

	return nil
}
