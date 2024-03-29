/*
Copyright 2022-2024 EscherCloud.
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

package client

import (
	"context"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	"k8s.io/apimachinery/pkg/runtime"
	kubernetesscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"

	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// SchemeAdder allows custom resources to be added to the scheme.
type SchemeAdder func(*runtime.Scheme) error

// NewScheme returns a scheme with all types that are required by unikorn.
func NewScheme() (*runtime.Scheme, error) {
	// Create a scheme and ensure it knows about Kubernetes and Unikorn
	// resource types.
	scheme := runtime.NewScheme()

	if err := kubernetesscheme.AddToScheme(scheme); err != nil {
		return nil, err
	}

	if err := unikornv1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return scheme, nil
}

// New returns a new controller runtime caching client, initialized with core and
// unikorn resources for typed operation.
func New(ctx context.Context, namespace string) (client.Client, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	// Create a scheme and ensure it knows about Kubernetes and Unikorn
	// resource types.
	scheme, err := NewScheme()
	if err != nil {
		return nil, err
	}

	cacheOptions := cache.Options{
		Scheme: scheme,
	}

	if namespace != "" {
		cacheOptions.DefaultNamespaces = map[string]cache.Config{
			namespace: {},
		}
	}

	cache, err := cache.New(config, cacheOptions)
	if err != nil {
		return nil, err
	}

	go func() {
		_ = cache.Start(ctx)
	}()

	clientOptions := client.Options{
		Scheme: scheme,
		Cache: &client.CacheOptions{
			Reader:       cache,
			Unstructured: true,
		},
	}

	c, err := client.New(config, clientOptions)
	if err != nil {
		return nil, err
	}

	return c, nil
}
