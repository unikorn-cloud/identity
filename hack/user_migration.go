/*
Copyright 2025 the Unikorn Authors.

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
	"context"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/constants"
	"github.com/unikorn-cloud/core/pkg/util"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes/scheme"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

func createUsers(ctx context.Context, cli client.Client, group *unikornv1.Group, users map[string]*unikornv1.User) error {
	if len(group.Spec.Users) == 0 {
		return nil
	}

	organizationID := group.Labels[constants.OrganizationLabel]

	for _, user := range group.Spec.Users {
		key := organizationID + ":" + user

		if resource, ok := users[key]; ok {
			group.Spec.UserIDs = append(group.Spec.UserIDs, resource.Name)

			continue
		}

		resource := &unikornv1.User{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: group.Namespace,
				Name:      util.GenerateResourceID(),
				Labels: map[string]string{
					constants.OrganizationLabel: organizationID,
					constants.NameLabel:         "unused",
				},
			},
			Spec: unikornv1.UserSpec{
				Subject: user,
				State:   unikornv1.UserStateActive,
			},
		}

		group.Spec.UserIDs = append(group.Spec.UserIDs, resource.Name)

		users[key] = resource

		if err := cli.Create(ctx, resource); err != nil {
			return err
		}

		fmt.Println("Creating", user)
	}

	// Out with the old...
	group.Spec.Users = nil

	fmt.Println("Updating", group)

	// In with the new...
	if err := cli.Update(ctx, group); err != nil {
		return err
	}

	return nil
}

func main() {
	ctx := context.Background()

	if err := unikornv1.AddToScheme(scheme.Scheme); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	configFlags := genericclioptions.NewConfigFlags(true)

	configFlags.AddFlags(pflag.CommandLine)

	pflag.Parse()

	config, err := cmdutil.NewFactory(configFlags).ToRESTConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	cli, err := client.New(config, client.Options{})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	groups := &unikornv1.GroupList{}

	if err := cli.List(ctx, groups, &client.ListOptions{}); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	users := map[string]*unikornv1.User{}

	for i := range groups.Items {
		if err := createUsers(ctx, cli, &groups.Items[i], users); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}
