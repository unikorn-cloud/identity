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
	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/generated"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

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

func showDetails(permissions *rbac.Permissions, item *unikornv1.OAuth2Provider) bool {
	// Super admin can see everything.
	if permissions.IsSuperAdmin {
		return true
	}

	// If it's a private one, show the details.
	if _, ok := item.Labels[constants.OrganizationLabel]; ok {
		return false
	}

	return false
}

func convert(permissions *rbac.Permissions, in *unikornv1.OAuth2Provider) *generated.Oauth2Provider {
	out := &generated.Oauth2Provider{
		Name:        in.Name,
		DisplayName: in.Spec.DisplayName,
		Issuer:      in.Spec.Issuer,
	}

	// Only show sensitive details for organizations you are an admin of.
	if showDetails(permissions, in) {
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

func (c *Client) List(ctx context.Context, organizationName string) ([]generated.Oauth2Provider, error) {
	// Get any generic public providers.
	publicRequirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.DoesNotExist, nil)
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to create selection requirement").WithError(err)
	}

	publicSelector := labels.NewSelector()
	publicSelector = publicSelector.Add(*publicRequirement)

	publicOptions := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: publicSelector,
	}

	var public unikornv1.OAuth2ProviderList

	if err := c.client.List(ctx, &public, publicOptions); err != nil {
		return nil, err
	}

	// Get any private providers.
	organizationRequirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{organizationName})
	if err != nil {
		return nil, errors.OAuth2ServerError("unable to create selection requirement").WithError(err)
	}

	privateSelector := labels.NewSelector()
	privateSelector = privateSelector.Add(*organizationRequirement)

	privateOptions := &client.ListOptions{
		Namespace:     c.namespace,
		LabelSelector: privateSelector,
	}

	var private unikornv1.OAuth2ProviderList

	if err := c.client.List(ctx, &private, privateOptions); err != nil {
		return nil, err
	}

	userinfo := userinfo.FromContext(ctx)

	return slices.Concat(convertList(userinfo.RBAC, &public), convertList(userinfo.RBAC, &private)), nil
}
