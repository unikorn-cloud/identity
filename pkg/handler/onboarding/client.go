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

package onboarding

import (
	"context"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/util/wait"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Options defines configurable onboarding options.
type Options struct {
	// InitialAccountRole defines the role name to be used for onboarding administrators
	InitialAccountRole string
}

// AddFlags adds the options flags to the given flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.InitialAccountRole, "initial-account-role", "administrator", "The role to assign to new accounts")
}

var (
	// ErrInitialAccountRoleNotFound is returned when the initial account role cannot be found.
	ErrInitialAccountRoleNotFound = errors.OAuth2ServerError("initial-account-role not found")
	// ErrInitialAccountRoleNotFoundInNamespace is returned when the initial account role cannot be found in a specific namespace.
	ErrInitialAccountRoleNotFoundInNamespace = errors.OAuth2ServerError("initial-account-role not found in namespace")
)

type Client struct {
	client    client.Client
	namespace string
	options   *Options
}

// New creates a new onboarding client.
func NewClient(client client.Client, namespace string, options *Options) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
		options:   options,
	}
}

// CreateAccount creates a new account with all necessary resources.
func (c *Client) CreateAccount(ctx context.Context, request *openapi.CreateAccountRequest) (*openapi.OrganizationRead, error) {
	// Find and assign admin role first.
	adminRole, err := c.validateAndGetAdminRole(ctx)
	if err != nil {
		return nil, err
	}

	// Generate a unique ID for the organization.
	organizationID := util.GenerateResourceID()

	// Create the organization object
	org := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      organizationID,
			Labels: map[string]string{
				constants.NameLabel: request.OrganizationName,
			},
		},
		Spec: unikornv1.OrganizationSpec{},
	}
	if err := c.client.Create(ctx, org); err != nil {
		return nil, errors.OAuth2ServerError("failed to create organization").WithError(err)
	}

	logger := log.FromContext(ctx)

	if err := wait.NewResourceWaiter(c.client, c.namespace).WaitForResourceWithValidators(ctx, org, wait.NewAvailableConditionValidator()); err != nil {
		logger.Error(err, "timeout waiting for organization namespace")
		return nil, errors.OAuth2ServerError("timeout waiting for organization namespace").WithError(err)
	}

	adminGroupID := util.GenerateResourceID()
	adminGroup := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: org.Status.Namespace,
			Name:      adminGroupID,
			Labels: map[string]string{
				constants.OrganizationLabel: org.Name,
				constants.NameLabel:         "administrators",
			},
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{adminRole.Name},
			Users:   []string{request.AdminUser},
		},
	}

	if err := c.client.Create(ctx, adminGroup); err != nil {
		if err := wait.NewResourceWaiter(c.client, c.namespace).WaitForResourceWithValidators(ctx, org, wait.NewAvailableConditionValidator()); err != nil {
			logger.Error(err, "timeout waiting for organization namespace")
		}

		return nil, errors.OAuth2ServerError("failed to create admin group").WithError(err)
	}

	return organizations.Convert(org), nil
}

// validateAndGetAdminRole retrieves the administrator role from the cluster.
func (c *Client) validateAndGetAdminRole(ctx context.Context) (*unikornv1.Role, error) {
	var roleList unikornv1.RoleList

	if err := c.client.List(ctx, &roleList, &client.ListOptions{
		Namespace: c.namespace,
	}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list roles").WithError(err)
	}

	if c.options.InitialAccountRole == "" {
		return nil, errors.OAuth2ServerError("initial account role not configured")
	}

	for _, role := range roleList.Items {
		if role.Labels[constants.NameLabel] == c.options.InitialAccountRole {
			return &role, nil
		}
	}

	return nil, errors.OAuth2ServerError("initial account role not found in namespace")
}
