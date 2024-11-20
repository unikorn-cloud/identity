package onboarding

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/util/wait"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
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
				constants.NameLabel: request.Organization.Metadata.Name,
			},
		},
		Spec: unikornv1.OrganizationSpec{},
	}

	if err := c.client.Create(ctx, org); err != nil {
		return nil, errors.OAuth2ServerError("failed to create organization").WithError(err)
	}

	if err := c.waitForOrganizationProvisioning(ctx, org); err != nil {
		if cleanupErr := wait.NewResourceWaiter(c.client, c.namespace).CleanupOnFailure(ctx, org); cleanupErr != nil {
			log.FromContext(ctx).Error(cleanupErr, "failed to cleanup organization after timeout")
		}
		return nil, errors.OAuth2ServerError("timeout waiting for organization namespace")
	}

	adminGroupID := util.GenerateResourceID()
	adminGroup := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: org.Status.Namespace,
			Name:      adminGroupID,
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
		if cleanupErr := wait.NewResourceWaiter(c.client, c.namespace).CleanupOnFailure(ctx, org); cleanupErr != nil {
			log.FromContext(ctx).Error(cleanupErr, "failed to cleanup organization after group creation failure")
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

	for _, role := range roleList.Items {
		if role.Labels[constants.NameLabel] == "administrator" {
			return &role, nil
		}
	}

	return nil, errors.OAuth2ServerError("administrator role not found in namespace")
}

// waitForOrganizationProvisioning waits for the organization to be provisioned and has a namespace.
func (c *Client) waitForOrganizationProvisioning(ctx context.Context, org *unikornv1.Organization) error {
	waiter := wait.NewResourceWaiter(c.client, c.namespace)
	return waiter.WaitForResource(ctx, org, func(obj client.Object) (bool, error) {
		org, ok := obj.(*unikornv1.Organization)
		if !ok {
			return false, fmt.Errorf("expected Organization type, got %T", obj)
		}

		// Check if namespace is set.
		if org.Status.Namespace == "" {
			return false, nil
		}

		// Check Available condition status.
		condition, err := org.StatusConditionRead(unikornv1core.ConditionAvailable)
		if err != nil {
			return false, err
		}

		if condition.Reason != unikornv1core.ConditionReasonProvisioned {
			return false, nil
		}

		if err := ctx.Err(); err != nil {
			return false, err
		}

		return true, nil
	})
}
