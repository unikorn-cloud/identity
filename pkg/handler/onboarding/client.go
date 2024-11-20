package onboarding

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/openapi"
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
	logger, _ := logr.FromContext(ctx)
	logger.Info("creating new account via onboarding")

	// Generate a unique ID for the organization
	organizationID := util.GenerateResourceID()

	logger.Info("generated organization ID", "organizationID", organizationID)

	// Create the organization object
	org := &unikornv1.Organization{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Name:      organizationID,
			Labels: map[string]string{
				constants.NameLabel: request.Organization.Metadata.Name,
			},
		},
		Spec: unikornv1.OrganizationSpec{}, // Initialize empty spec
	}

	logger.Info("creating organization", "organization", org)

	if err := c.client.Create(ctx, org); err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	logger.Info("created organization", "organization", org)

	// Find and assign admin role
	adminRole, err := c.getAdminRole(ctx)

	logger.Info("found admin role", "adminRole", adminRole)

	// Create the admin group
	adminGroup := &unikornv1.Group{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: c.namespace,
			Labels: map[string]string{
				"unikorn.cloud/organization": org.Name,
				"unikorn.cloud/name":         "admin",
			},
		},
		Spec: unikornv1.GroupSpec{
			RoleIDs: []string{adminRole.Name},
			Users:   []string{request.AdminUser},
		},
	}

	logger.Info("creating admin group", "adminGroup", adminGroup)

	if err := c.client.Create(ctx, adminGroup); err != nil {
		// Cleanup organization if group creation fails
		_ = c.client.Delete(ctx, org)
		return nil, fmt.Errorf("failed to create admin group: %w", err)
	}

	logger.Info("created admin group", "adminGroup", adminGroup)
	if err != nil {
		// Cleanup created resources
		_ = c.client.Delete(ctx, adminGroup)
		_ = c.client.Delete(ctx, org)
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}

	adminGroup.Spec.RoleIDs = []string{adminRole.Name}

	logger.Info("updating admin group with role", "adminGroup", adminGroup)

	if err := c.client.Update(ctx, adminGroup); err != nil {
		// Cleanup created resources
		_ = c.client.Delete(ctx, adminGroup)
		_ = c.client.Delete(ctx, org)
		return nil, fmt.Errorf("failed to update admin group with role: %w", err)
	}

	logger.Info("updated admin group with role", "adminGroup", adminGroup)

	out := organizations.Convert(org)

	return out, nil
}

// getAdminRole retrieves the administrator role from the cluster.
func (c *Client) getAdminRole(ctx context.Context) (*unikornv1.Role, error) {
	var roleList unikornv1.RoleList
	if err := c.client.List(ctx, &roleList, &client.ListOptions{
		Namespace: c.namespace,
	}); err != nil {
		return nil, err
	}

	for _, role := range roleList.Items {
		if role.Labels["unikorn.cloud/name"] == "administrator" {
			return &role, nil
		}
	}

	return nil, errors.NewNotFound(unikornv1.Resource("role"), "administrator")
}
