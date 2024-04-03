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

package handler

import (
	"context"

	coreRBAC "github.com/unikorn-cloud/core/pkg/authorization/rbac"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// aclGetter gets an ACL from resourced owned by the identity service.
type aclGetter struct {
	client       client.Client
	namespace    string
	organization string
}

func newACLGetter(client client.Client, namespace, organization string) *aclGetter {
	return &aclGetter{
		client:       client,
		namespace:    namespace,
		organization: organization,
	}
}

func (a *aclGetter) Get(ctx context.Context) (*coreRBAC.ACL, error) {
	userinfo := userinfo.FromContext(ctx)

	return rbac.New(a.client, a.namespace).GetACL(ctx, userinfo.RBAC, a.organization)
}
