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

package rbac

import (
	"context"
	"slices"
	"strings"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type RBAC struct {
	client    client.Client
	namespace string
}

func New(client client.Client, namespace string) *RBAC {
	return &RBAC{
		client:    client,
		namespace: namespace,
	}
}

func (r *RBAC) UserExists(ctx context.Context, email string) (bool, error) {
	parts := strings.Split(email, "@")

	domain := parts[1]

	var organizations unikornv1.OrganizationList

	if err := r.client.List(ctx, &organizations, &client.ListOptions{Namespace: r.namespace}); err != nil {
		return false, err
	}

	for _, organization := range organizations.Items {
		if organization.Spec.Domain != nil && *organization.Spec.Domain == domain {
			return true, nil
		}

		for _, group := range organization.Spec.Groups {
			if slices.Contains(group.Users, email) {
				return true, nil
			}
		}
	}

	return false, nil
}
