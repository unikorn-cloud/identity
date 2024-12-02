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

package wait

import (
	"context"
	"fmt"
	"time"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type ResourceWaiter struct {
	Client    client.Client
	Interval  time.Duration
	Timeout   time.Duration
	Namespace string
}

func NewResourceWaiter(client client.Client, namespace string) *ResourceWaiter {
	return &ResourceWaiter{
		Client:    client,
		Interval:  time.Second,
		Timeout:   30 * time.Second,
		Namespace: namespace,
	}
}

// Validator interface defines the contract for resource validation.
type Validator interface {
	Valid(resource unikornv1core.ManagableResourceInterface) error
}

// AvailableConditionValidator validates if a resource is in Available condition.
type AvailableConditionValidator struct{}

var (
	// ErrResourceNotAvailable is returned when a resource is not in the Available condition.
	ErrResourceNotAvailable = fmt.Errorf("resource not available")
)

func NewAvailableConditionValidator() *AvailableConditionValidator {
	return &AvailableConditionValidator{}
}

func (v *AvailableConditionValidator) Valid(resource unikornv1core.ManagableResourceInterface) error {
	condition, err := resource.StatusConditionRead(unikornv1core.ConditionAvailable)
	if err != nil {
		return err
	}

	if condition.Status != corev1.ConditionTrue {
		return fmt.Errorf("%w: status=%v, message=%q, lastTransitionTime=%v",
			ErrResourceNotAvailable, condition.Status, condition.Message, condition.LastTransitionTime)
	}

	return nil
}

// WaitForResource waits for a resource to meet certain conditions.
func (w *ResourceWaiter) WaitForResource(ctx context.Context, obj unikornv1core.ManagableResourceInterface, condition func(obj unikornv1core.ManagableResourceInterface) (bool, error)) error {
	return wait.PollUntilContextTimeout(ctx, w.Interval, w.Timeout, true, func(ctx context.Context) (bool, error) {
		// Check context before making the call.
		if err := ctx.Err(); err != nil {
			return false, err
		}

		err := w.Client.Get(ctx, client.ObjectKey{
			Namespace: w.Namespace,
			Name:      obj.GetName(),
		}, obj)

		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}

			return false, err
		}

		met, err := condition(obj)

		if err != nil {
			return false, err
		}

		if !met {
			return false, nil
		}

		return true, nil
	})
}

// WaitForResourceWithValidators waits for a resource to pass all validators.
func (w *ResourceWaiter) WaitForResourceWithValidators(ctx context.Context, resource unikornv1core.ManagableResourceInterface, validators ...Validator) error {
	logger := log.FromContext(ctx)

	return w.WaitForResource(ctx, resource, func(resource unikornv1core.ManagableResourceInterface) (bool, error) {
		for _, validator := range validators {
			if err := validator.Valid(resource); err != nil {
				logger.Error(err, "resource is not valid")
				return false, nil
			}
		}

		return true, nil
	})
}
