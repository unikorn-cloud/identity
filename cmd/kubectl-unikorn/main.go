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

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cmd/create"
	"github.com/unikorn-cloud/identity/pkg/cmd/factory"

	"k8s.io/client-go/kubernetes/scheme"
)

func main() {
	if err := unikornv1.AddToScheme(scheme.Scheme); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   "kubectl-unikorn",
		Short: "Unikorn kubectl plugin",
	}

	factory := factory.NewFactory()
	factory.AddFlags(cmd.PersistentFlags())

	if err := factory.RegisterCompletionFunctions(cmd); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cmd.AddCommand(
		create.GetCommand(factory),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
