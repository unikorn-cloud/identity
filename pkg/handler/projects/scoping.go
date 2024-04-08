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

package projects

import (
	"context"
	"errors"
	"slices"

	"github.com/unikorn-cloud/core/pkg/authorization/rbac"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrNoScope = errors.New("nothing in scope")
)

type Scoper struct {
	client       client.Client
	permissions  *rbac.Permissions
	organization string
}

func NewScoper(ctx context.Context, client client.Client, organization string) *Scoper {
	userinfo := userinfo.FromContext(ctx)

	return &Scoper{
		client:       client,
		permissions:  userinfo.RBAC,
		organization: organization,
	}
}

func (s *Scoper) MustApplyScope() bool {
	// Super admin sees all.
	if s.permissions.IsSuperAdmin {
		return false
	}

	// NOTE: RBAC should have determined this exists by now.
	organization, _ := s.permissions.LookupOrganization(s.organization)

	// Organization admin sees all.
	for _, group := range organization.Groups {
		if slices.Contains(group.Roles, "admin") {
			return false
		}
	}

	return true
}

func (s *Scoper) ListProjects(ctx context.Context) (*unikornv1.ProjectList, error) {
	selector := labels.NewSelector()

	orgRequirement, err := labels.NewRequirement(constants.OrganizationLabel, selection.Equals, []string{s.organization})
	if err != nil {
		return nil, err
	}

	selector = selector.Add(*orgRequirement)

	options := &client.ListOptions{
		LabelSelector: selector,
	}

	result := &unikornv1.ProjectList{}

	if err := s.client.List(ctx, result, options); err != nil {
		return nil, err
	}

	if !s.permissions.IsSuperAdmin {
		organization, err := s.permissions.LookupOrganization(s.organization)
		if err != nil {
			return nil, err
		}

		names := make([]string, len(organization.Projects))

		for i, project := range organization.Projects {
			names[i] = project.Name
		}

		result.Items = slices.DeleteFunc(result.Items, func(project unikornv1.Project) bool {
			return !slices.Contains(names, project.Name)
		})
	}

	return result, nil
}
