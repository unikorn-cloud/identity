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

package create

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/unikorn-cloud/core/pkg/constants"
	coreutil "github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cmd/factory"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type createUserOptions struct {
	ConfigFlags *genericclioptions.ConfigFlags

	user string
}

func (o *createUserOptions) AddFlags(cmd *cobra.Command, factory *factory.Factory) error {
	cmd.Flags().StringVar(&o.user, "user", "", "User users, may be specified more than once.")

	if err := cmd.MarkFlagRequired("user"); err != nil {
		return err
	}

	return nil
}

func (o *createUserOptions) validate(ctx context.Context, cli client.Client) error {
	validators := []func(context.Context, client.Client) error{}

	for _, validator := range validators {
		if err := validator(ctx, cli); err != nil {
			return err
		}
	}

	return nil
}

func (o *createUserOptions) execute(ctx context.Context, cli client.Client) error {
	user := &unikornv1.User{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: *o.ConfigFlags.Namespace,
			Name:      coreutil.GenerateResourceID(),
			Labels: map[string]string{
				constants.NameLabel: constants.UndefinedName,
			},
		},
		Spec: unikornv1.UserSpec{
			Subject: o.user,
			State:   unikornv1.UserStateActive,
		},
	}

	if err := cli.Create(ctx, user); err != nil {
		return err
	}

	return nil
}

func createUser(factory *factory.Factory) *cobra.Command {
	o := createUserOptions{
		ConfigFlags: factory.ConfigFlags,
	}

	cmd := &cobra.Command{
		Use:   "user",
		Short: "Create a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			client, err := factory.Client()
			if err != nil {
				return err
			}

			if err := o.validate(ctx, client); err != nil {
				return err
			}

			if err := o.execute(ctx, client); err != nil {
				return err
			}

			return nil
		},
	}

	if err := o.AddFlags(cmd, factory); err != nil {
		panic(err)
	}

	return cmd
}
