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

package get

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/unikorn-cloud/core/pkg/constants"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/cmd/factory"
	"github.com/unikorn-cloud/identity/pkg/cmd/flags"
	"github.com/unikorn-cloud/identity/pkg/cmd/util"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/printers"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ErrConsistency = errors.New("consistency error")
)

type createUserOptions struct {
	ConfigFlags *genericclioptions.ConfigFlags

	organization flags.HostnameVar
	email        string

	organizationID        string
	organizationNamespace string
}

func (o *createUserOptions) AddFlags(cmd *cobra.Command, factory *factory.Factory) error {
	cmd.Flags().Var(&o.organization, "organization", "Organization name.")
	cmd.Flags().StringVar(&o.email, "email", "", "User subject email address.")

	if err := cmd.RegisterFlagCompletionFunc("organization", factory.ResourceNameCompletionFunc("organization.identity.unikorn-cloud.org", "")); err != nil {
		return err
	}

	return nil
}

// validateOrganization ensures the organization doesn't already exist.
func (o *createUserOptions) validateOrganization(ctx context.Context, cli client.Client) error {
	if o.organization.String() == "" {
		return nil
	}

	organization, err := util.GetOrganization(ctx, cli, *o.ConfigFlags.Namespace, o.organization.String())
	if err != nil {
		return err
	}

	o.organizationID = organization.Name
	o.organizationNamespace = organization.Status.Namespace

	return nil
}

func (o *createUserOptions) validate(ctx context.Context, cli client.Client) error {
	validators := []func(context.Context, client.Client) error{
		o.validateOrganization,
	}

	for _, validator := range validators {
		if err := validator(ctx, cli); err != nil {
			return err
		}
	}

	return nil
}

//nolint:cyclop
func (o *createUserOptions) execute(ctx context.Context, cli client.Client) error {
	users := &unikornv1.UserList{}

	if err := cli.List(ctx, users, &client.ListOptions{}); err != nil {
		return err
	}

	userIndex := make(map[string]*unikornv1.User, len(users.Items))

	for i := range users.Items {
		userIndex[users.Items[i].Name] = &users.Items[i]
	}

	organizations := &unikornv1.OrganizationList{}

	if err := cli.List(ctx, organizations, &client.ListOptions{}); err != nil {
		return err
	}

	organizationIndex := make(map[string]*unikornv1.Organization, len(organizations.Items))

	for i := range organizations.Items {
		organizationIndex[organizations.Items[i].Name] = &organizations.Items[i]
	}

	organizationUsers := &unikornv1.OrganizationUserList{}

	if err := cli.List(ctx, organizationUsers, &client.ListOptions{}); err != nil {
		return err
	}

	table := &metav1.Table{
		ColumnDefinitions: []metav1.TableColumnDefinition{
			{
				Name: "namespace",
			},
			{
				Name: "id",
			},
			{
				Name: "email",
			},
			{
				Name: "organization",
			},
		},
		Rows: make([]metav1.TableRow, 0, len(organizationUsers.Items)),
	}

	for i := range organizationUsers.Items {
		ou := &organizationUsers.Items[i]

		user, ok := userIndex[ou.Labels[constants.UserLabel]]
		if !ok {
			return fmt.Errorf("%w: organization user %s in namespace %s doesn't have corresponding user resource", ErrConsistency, ou.Name, ou.Namespace)
		}

		if o.email != "" && user.Spec.Subject != o.email {
			continue
		}

		organization, ok := organizationIndex[ou.Labels[constants.OrganizationLabel]]
		if !ok {
			return fmt.Errorf("%w: organization user %s in namespace %s doesn't have corresponding organization resource", ErrConsistency, ou.Name, ou.Namespace)
		}

		if o.organizationID != "" && organization.Name != o.organizationID {
			continue
		}

		table.Rows = append(table.Rows, metav1.TableRow{
			Cells: []interface{}{
				ou.Namespace,
				ou.Name,
				user.Spec.Subject,
				organization.Labels[constants.NameLabel],
			},
		})
	}

	return printers.NewTablePrinter(printers.PrintOptions{}).PrintObj(table, os.Stdout)
}

func getUser(factory *factory.Factory) *cobra.Command {
	o := createUserOptions{
		ConfigFlags: factory.ConfigFlags,
	}

	cmd := &cobra.Command{
		Use:   "user",
		Short: "List users",
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
