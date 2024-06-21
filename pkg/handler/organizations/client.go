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

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/openapi"

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
	// ID is the organization's Kubernetes name, so a higher level resource
	// can reference it.
	ID string

	// Namespace is the namespace that is provisioned by the organization.
	// Should be usable set when the organization is active.
	Namespace string
}

// GetMetadata retrieves the organization metadata.
// Clients should consult at least the Active status before doing anything
// with the organization.
func (c *Client) GetMetadata(ctx context.Context, organizationID string) (*Meta, error) {
	result, err := c.get(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	metadata := &Meta{
		ID:        organizationID,
		Namespace: result.Status.Namespace,
	}

	return metadata, nil
}

func convertOrganizationType(in *unikornv1.Organization) openapi.OrganizationType {
	if in.Spec.Domain != nil {
		return openapi.Domain
	}

	return openapi.Adhoc
}

func convert(in *unikornv1.Organization) *openapi.OrganizationRead {
	provisioningStatus := coreopenapi.ResourceProvisioningStatusUnknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.OrganizationRead{
		Metadata: conversion.ResourceReadMetadata(in, provisioningStatus),
		Spec: openapi.OrganizationSpec{
			OrganizationType: convertOrganizationType(in),
		},
	}

	if in.Spec.Domain != nil {
		out.Spec.Domain = in.Spec.Domain
		out.Spec.ProviderScope = util.ToPointer(openapi.ProviderScope(*in.Spec.ProviderScope))
		out.Spec.ProviderID = in.Spec.ProviderID
	}

	// TODO: We should cross reference with the provider type and
	// only emit what's allowed.
	if in.Spec.ProviderOptions != nil {
		if in.Spec.ProviderOptions.Google != nil {
			out.Spec.GoogleCustomerID = in.Spec.ProviderOptions.Google.CustomerID
		}
	}

	return out
}

func convertList(in *unikornv1.OrganizationList) openapi.Organizations {
	slices.SortStableFunc(in.Items, func(a, b unikornv1.Organization) int {
		return strings.Compare(a.Name, b.Name)
	})

	out := make(openapi.Organizations, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func hasAccess(permissions *rbac.Permissions, organizationID string) bool {
	if permissions.IsSuperAdmin {
		return true
	}

	for _, organization := range permissions.Organizations {
		if organization.Name == organizationID {
			return true
		}
	}

	return false
}

// get returns the implicit organization identified by the JWT claims.
func (c *Client) get(ctx context.Context, organizationID string) (*unikornv1.Organization, error) {
	// TODO: hasAccess()
	result := &unikornv1.Organization{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: organizationID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get organization").WithError(err)
	}

	return result, nil
}

func (c *Client) List(ctx context.Context) (openapi.Organizations, error) {
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

func (c *Client) Get(ctx context.Context, organizationID string) (*openapi.OrganizationRead, error) {
	result, err := c.get(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func (c *Client) generate(in *openapi.OrganizationWrite) *unikornv1.Organization {
	out := &unikornv1.Organization{
		ObjectMeta: conversion.ObjectMetadata(&in.Metadata, c.namespace),
	}

	if in.Spec.OrganizationType == openapi.Domain {
		out.Spec.Domain = in.Spec.Domain
		out.Spec.ProviderScope = util.ToPointer(unikornv1.ProviderScope(*in.Spec.ProviderScope))
		out.Spec.ProviderID = in.Spec.ProviderID

		// TODO: we should cross reference with the provider type and do only
		// what must be done.
		if in.Spec.GoogleCustomerID != nil {
			out.Spec.ProviderOptions = &unikornv1.OrganizationProviderOptions{
				Google: &unikornv1.OrganizationProviderGoogleSpec{
					CustomerID: in.Spec.GoogleCustomerID,
				},
			}
		}
	}

	return out
}

func (c *Client) Update(ctx context.Context, organizationID string, request *openapi.OrganizationWrite) error {
	current, err := c.get(ctx, organizationID)
	if err != nil {
		return err
	}

	required := c.generate(request)

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	conversion.UpdateObjectMetadata(updated, required)

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch organization").WithError(err)
	}

	return nil
}
