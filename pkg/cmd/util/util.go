/*
Copyright 2024-2025 the Unikorn Authors.

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

package util

import (
	"context"
	"fmt"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cmd/errors"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetOrganization(ctx context.Context, cli client.Client, namespace, organizatonName string) (*unikornv1.Organization, error) {
	requirement, err := labels.NewRequirement(constants.NameLabel, selection.Equals, []string{organizatonName})
	if err != nil {
		return nil, err
	}

	options := &client.ListOptions{
		Namespace:     namespace,
		LabelSelector: labels.NewSelector().Add(*requirement),
	}

	var resources unikornv1.OrganizationList

	if err := cli.List(ctx, &resources, options); err != nil {
		return nil, err
	}

	if len(resources.Items) != 1 {
		return nil, fmt.Errorf("%w: unable to find organization with name %s", errors.ErrValidation, organizatonName)
	}

	if resources.Items[0].Status.Namespace == "" {
		return nil, fmt.Errorf("%w: unable to find organization namespace", errors.ErrValidation)
	}

	return &resources.Items[0], nil
}
