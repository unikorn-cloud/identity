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

package quotas

import (
	"context"
	goerrors "errors"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/conversion"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/common"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	"k8s.io/apimachinery/pkg/api/resource"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrConsistency = goerrors.New("consistency error")
)

// Client is responsible for user management.
type Client struct {
	// client is the Kubernetes client.
	client client.Client
	// namespace is the namespace the identity service is running in.
	namespace string
}

// New creates a new user client.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func generateQuota(in *openapi.Quota) *unikornv1.ResourceQuota {
	out := &unikornv1.ResourceQuota{
		Kind:     in.Kind,
		Quantity: resource.NewQuantity(int64(in.Quantity), resource.DecimalSI),
	}

	return out
}

func generateQuotaList(in openapi.QuotaList) []unikornv1.ResourceQuota {
	out := make([]unikornv1.ResourceQuota, len(in))

	for i := range in {
		out[i] = *generateQuota(&in[i])
	}

	return out
}

func generate(ctx context.Context, organization *organizations.Meta, in *openapi.QuotasWrite) (*unikornv1.Quota, error) {
	info, err := authorization.FromContext(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("userinfo is not set").WithError(err)
	}

	metadata := &coreopenapi.ResourceWriteMetadata{
		Name: "undefined",
	}

	out := &unikornv1.Quota{
		ObjectMeta: conversion.NewObjectMetadata(metadata, organization.Namespace, info.Userinfo.Sub).WithOrganization(organization.ID).Get(),
		Spec: unikornv1.QuotaSpec{
			Quotas: generateQuotaList(in.Capacity),
		},
	}

	return out, nil
}

type allocation struct {
	committed int64
	reserved  int64
}

func (c *Client) convert(ctx context.Context, in *unikornv1.Quota, organizationID string) (*openapi.QuotasRead, error) {
	out := &openapi.QuotasRead{
		Capacity:  make(openapi.QuotaList, len(in.Spec.Quotas)),
		Free:      make(openapi.QuotaList, len(in.Spec.Quotas)),
		Allocated: make(openapi.QuotaListDetailed, len(in.Spec.Quotas)),
	}

	// Grab the totals across all allocations.
	allocations, err := common.New(c.client).GetAllocations(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	allocated := map[string]allocation{}

	for i := range allocations.Items {
		allocation := &allocations.Items[i]

		for j := range allocation.Spec.Allocations {
			resource := &allocation.Spec.Allocations[j]

			allocation := allocated[resource.Kind]
			allocation.committed += resource.Committed.Value()
			allocation.reserved += resource.Reserved.Value()

			allocated[resource.Kind] = allocation
		}
	}

	for i := range in.Spec.Quotas {
		capacity := &in.Spec.Quotas[i]

		out.Capacity[i] = openapi.Quota{
			Kind:     capacity.Kind,
			Quantity: int(capacity.Quantity.Value()),
		}

		out.Free[i] = openapi.Quota{
			Kind:     capacity.Kind,
			Quantity: int(capacity.Quantity.Value() - (allocated[capacity.Kind].committed + allocated[capacity.Kind].reserved)),
		}

		out.Allocated[i] = openapi.QuotaDetailed{
			Kind:      capacity.Kind,
			Committed: int(allocated[capacity.Kind].committed),
			Reserved:  int(allocated[capacity.Kind].reserved),
		}
	}

	return out, nil
}

func (c *Client) GetMetadata(ctx context.Context) (openapi.QuotaMetadataRead, error) {
	result := &unikornv1.QuotaMetadataList{}

	if err := c.client.List(ctx, result, &client.ListOptions{Namespace: c.namespace}); err != nil {
		return nil, errors.OAuth2InvalidRequest("unnable to read quota metadata").WithError(err)
	}

	out := make(openapi.QuotaMetadataRead, len(result.Items))

	for i := range result.Items {
		out[i] = openapi.QuotaMetadata{
			Name:        result.Items[i].Name,
			DisplayName: result.Items[i].Spec.DisplayName,
			Description: result.Items[i].Spec.Description,
			Default:     int(result.Items[i].Spec.Default.Value()),
		}
	}

	return out, nil
}

func (c *Client) Get(ctx context.Context, organizationID string) (*openapi.QuotasRead, error) {
	result, err := common.New(c.client).GetQuota(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	return c.convert(ctx, result, organizationID)
}

func (c *Client) Update(ctx context.Context, organizationID string, request *openapi.QuotasWrite) (*openapi.QuotasRead, error) {
	common := common.New(c.client)

	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	current, err := common.GetQuota(ctx, organizationID)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("unnable to read quota").WithError(err)
	}

	required, err := generate(ctx, organization, request)
	if err != nil {
		return nil, err
	}

	updated := current.DeepCopy()
	updated.Labels = required.Labels
	updated.Annotations = required.Annotations
	updated.Spec = required.Spec

	if err := common.CheckQuotaConsistency(ctx, organizationID, updated, nil); err != nil {
		return nil, errors.OAuth2InvalidRequest("allocation exceeded quota").WithError(err)
	}

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return nil, errors.OAuth2ServerError("failed to patch quotas").WithError(err)
	}

	return c.convert(ctx, updated, organizationID)
}
