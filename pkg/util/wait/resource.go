package wait

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// WaitForResource waits for a resource to meet certain conditions.
func (w *ResourceWaiter) WaitForResource(ctx context.Context, obj client.Object, condition func(obj client.Object) (bool, error)) error {
	logger := log.FromContext(ctx)

	return wait.PollUntilContextTimeout(ctx, w.Interval, w.Timeout, true, func(ctx context.Context) (bool, error) {
		// Check context before making the call
		if err := ctx.Err(); err != nil {
			return false, err
		}

		if err := w.Client.Get(ctx, client.ObjectKey{
			Namespace: w.Namespace,
			Name:      obj.GetName(),
		}, obj); err != nil {
			// Handle different types of errors appropriately
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("resource not found, waiting",
					"namespace", w.Namespace,
					"name", obj.GetName())

				return false, nil
			}
			// For other errors, log and return the error to stop polling
			logger.Error(err, "failed to get resource",
				"namespace", w.Namespace,
				"name", obj.GetName())

			return false, err
		}

		// Run the condition check
		met, err := condition(obj)
		if err != nil {
			logger.Error(err, "condition check failed",
				"namespace", w.Namespace,
				"name", obj.GetName())

			return false, err
		}

		if !met {
			logger.V(1).Info("condition not met, waiting",
				"namespace", w.Namespace,
				"name", obj.GetName())
		}

		return met, nil
	})
}

// CleanupOnFailure handles cleanup of the resource if waiting fails.
func (w *ResourceWaiter) CleanupOnFailure(ctx context.Context, obj client.Object) error {
	logger := log.FromContext(ctx)

	if err := w.Client.Delete(ctx, obj); err != nil {
		if !apierrors.IsNotFound(err) {
			logger.Error(err, "failed to cleanup resource",
				"namespace", w.Namespace,
				"name", obj.GetName())

			return fmt.Errorf("failed to cleanup resource: %w", err)
		}
	}

	return nil
}
