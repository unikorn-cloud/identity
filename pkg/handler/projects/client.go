/*
Copyright 2022-2024 EscherCloud.
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

package projects

import (
	"context"
	"slices"
	"strings"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
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

// Client wraps up project related management handling.
type Client struct {
	// client allows Kubernetes API access.
	client    client.Client
	namespace string
}

// New returns a new client with required parameters.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

func convert(in *unikornv1.Project) *openapi.ProjectRead {
	provisioningStatus := coreopenapi.Unknown

	if condition, err := in.StatusConditionRead(unikornv1core.ConditionAvailable); err == nil {
		provisioningStatus = conversion.ConvertStatusCondition(condition)
	}

	out := &openapi.ProjectRead{
		Metadata: conversion.OrganizationScopedResourceReadMetadata(in, provisioningStatus),
	}

	if in.Spec.GroupIDs != nil {
		out.Spec.GroupIDs = &in.Spec.GroupIDs
	}

	return out
}

func convertList(in *unikornv1.ProjectList) openapi.Projects {
	out := make(openapi.Projects, len(in.Items))

	for i := range in.Items {
		out[i] = *convert(&in.Items[i])
	}

	return out
}

func (c *Client) List(ctx context.Context, organizationID string) (openapi.Projects, error) {
	scoper := NewScoper(ctx, c.client, organizationID)

	result, err := scoper.ListProjects(ctx)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to list projects").WithError(err)
	}

	slices.SortStableFunc(result.Items, func(a, b unikornv1.Project) int {
		return strings.Compare(a.Name, b.Name)
	})

	return convertList(result), nil
}

func (c *Client) get(ctx context.Context, organization *organizations.Meta, projectID string) (*unikornv1.Project, error) {
	result := &unikornv1.Project{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: organization.Namespace, Name: projectID}, result); err != nil {
		if kerrors.IsNotFound(err) {
			return nil, errors.HTTPNotFound().WithError(err)
		}

		return nil, errors.OAuth2ServerError("failed to get project").WithError(err)
	}

	return result, nil
}

func (c *Client) Get(ctx context.Context, organizationID, projectID string) (*openapi.ProjectRead, error) {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return nil, err
	}

	result, err := c.get(ctx, organization, projectID)
	if err != nil {
		return nil, err
	}

	return convert(result), nil
}

func generate(organization *organizations.Meta, request *openapi.ProjectWrite) *unikornv1.Project {
	resource := &unikornv1.Project{
		ObjectMeta: conversion.OrganizationScopedObjectMetadata(&request.Metadata, organization.Namespace, organization.ID),
	}

	if request.Spec.GroupIDs != nil {
		resource.Spec.GroupIDs = *request.Spec.GroupIDs
	}

	return resource
}

// Create creates the implicit project indentified by the JTW claims.
func (c *Client) Create(ctx context.Context, organizationID string, request *openapi.ProjectWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	resource := generate(organization, request)

	if err := c.client.Create(ctx, resource); err != nil {
		// TODO: we can do a cached lookup to save the API traffic.
		if kerrors.IsAlreadyExists(err) {
			return errors.HTTPConflict()
		}

		return errors.OAuth2ServerError("failed to create project").WithError(err)
	}

	return nil
}

func (c *Client) Update(ctx context.Context, organizationID, projectID string, request *openapi.ProjectWrite) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	current, err := c.get(ctx, organization, projectID)
	if err != nil {
		return err
	}

	required := generate(organization, request)

	updated := current.DeepCopy()
	updated.Spec = required.Spec

	conversion.UpdateObjectMetadata(updated, required)

	if err := c.client.Patch(ctx, updated, client.MergeFrom(current)); err != nil {
		return errors.OAuth2ServerError("failed to patch project").WithError(err)
	}

	return nil
}

// Delete deletes the project.
func (c *Client) Delete(ctx context.Context, organizationID, projectID string) error {
	organization, err := organizations.New(c.client, c.namespace).GetMetadata(ctx, organizationID)
	if err != nil {
		return err
	}

	project := &unikornv1.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name:      projectID,
			Namespace: organization.Namespace,
		},
	}

	if err := c.client.Delete(ctx, project); err != nil {
		if kerrors.IsNotFound(err) {
			return errors.HTTPNotFound().WithError(err)
		}

		return errors.OAuth2ServerError("failed to delete project").WithError(err)
	}

	return nil
}
