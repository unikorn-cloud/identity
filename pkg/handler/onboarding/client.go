package onboarding

import (
	"context"
	"time"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrAdminRoleNotFound is returned when the administrator role cannot be found.
	ErrAdminRoleNotFound = errors.OAuth2ServerError("administrator role not found")
	// ErrAdminRoleNotFoundInNamespace is returned when the administrator role cannot be found in a specific namespace.
	ErrAdminRoleNotFoundInNamespace = errors.OAuth2ServerError("administrator role not found in namespace")
)

type Client struct {
	client    client.Client
	namespace string
}

// New creates a new onboarding client.
func NewClient(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// CreateAccount creates a new account with all necessary resources.
func (c *Client) CreateAccount(ctx context.Context, request *openapi.CreateAccountRequest) (*openapi.OrganizationRead, error) {
	// Find and assign admin role first.
	adminRole, err := c.getAdminRole(ctx)
	if err != nil {
		return nil, err
	}

	if adminRole == nil {
		return nil, ErrAdminRoleNotFound
	}

	// Generate a unique ID for the organization
	organizationID := util.GenerateResourceID()

	// Create the organization object
	org := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      organizationID,
			Labels: map[string]string{
				constants.NameLabel: request.Organization.Metadata.Name,
			},
		},
		Spec: unikornv1.OrganizationSpec{},
	}

	if err := c.client.Create(ctx, org); err != nil {
		return nil, errors.OAuth2ServerError("failed to create organization").WithError(err)
	}

	// Wait for the organization to be provisioned and have a namespace.
	if err := wait.PollUntilContextTimeout(ctx, time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		if err := c.client.Get(ctx, client.ObjectKey{Namespace: c.namespace, Name: org.Name}, org); err != nil {
			return false, err
		}

		return org.Status.Namespace != "", nil
	}); err != nil {
		return nil, errors.OAuth2ServerError("timeout waiting for organization namespace").WithError(err)
	}

	adminGroup := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: org.Status.Namespace,
			Name:      util.GenerateResourceID(),
			Labels: map[string]string{
				constants.OrganizationLabel: org.Name,
				constants.NameLabel:         "admin",
			},
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{adminRole.Name},
			Users:   []string{request.AdminUser},
		},
	}

	if err := c.client.Create(ctx, adminGroup); err != nil {
		// Cleanup organization if group creation fails.
		_ = c.client.Delete(ctx, org)
		return nil, errors.OAuth2ServerError("failed to create admin group").WithError(err)
	}

	// Wait until the group is provisioned.
	if err := wait.PollUntilContextTimeout(ctx, time.Second, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		if err := c.client.Get(ctx, client.ObjectKey{Namespace: org.Status.Namespace, Name: adminGroup.Name}, adminGroup); err != nil {
			return false, err
		}

		return true, nil
	}); err != nil {
		return nil, errors.OAuth2ServerError("timeout waiting for admin group").WithError(err)
	}

	return organizations.Convert(org), nil
}

// getAdminRole retrieves the administrator role from the cluster.
func (c *Client) getAdminRole(ctx context.Context) (*unikornv1.Role, error) {
	var roleList unikornv1.RoleList
	if err := c.client.List(ctx, &roleList, &client.ListOptions{
		Namespace: c.namespace,
	}); err != nil {
		return nil, errors.OAuth2ServerError("failed to list roles").WithError(err)
	}

	for _, role := range roleList.Items {
		if role.Labels[constants.NameLabel] == "administrator" {
			return &role, nil
		}
	}

	return nil, errors.OAuth2ServerError("administrator role not found in namespace")
}
