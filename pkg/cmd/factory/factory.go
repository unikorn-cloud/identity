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

package factory

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"

	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
	utilcomp "k8s.io/kubectl/pkg/util/completion"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Factory struct {
	ConfigFlags *genericclioptions.ConfigFlags
	factory     cmdutil.Factory
}

func NewFactory() *Factory {
	configFlags := genericclioptions.NewConfigFlags(true)

	return &Factory{
		ConfigFlags: configFlags,
		factory:     cmdutil.NewFactory(configFlags),
	}
}

func (f *Factory) AddFlags(flags *pflag.FlagSet) {
	f.ConfigFlags.AddFlags(flags)
}

func (f *Factory) RegisterCompletionFunctions(cmd *cobra.Command) error {
	namespaceCompletion := func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return utilcomp.CompGetResource(f.factory, "namespace", toComplete), cobra.ShellCompDirectiveNoFileComp
	}

	if err := cmd.RegisterFlagCompletionFunc("namespace", namespaceCompletion); err != nil {
		return err
	}

	return nil
}

func (f *Factory) Client() (client.Client, error) {
	config, err := cmdutil.NewFactory(f.ConfigFlags).ToRESTConfig()
	if err != nil {
		return nil, err
	}

	return client.New(config, client.Options{})
}

func (f *Factory) ResourceNameCompletionFunc(resourceType string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		template := fmt.Sprintf(`{{ range .items }}{{ index .metadata.labels "%s" }} {{ end }}`, constants.NameLabel)

		return utilcomp.CompGetFromTemplate(&template, f.factory, "", []string{resourceType}, toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}
