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

package authorization

import (
	"context"

	"github.com/unikorn-cloud/core/pkg/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
)

type keyType int

//nolint:gochecknoglobals
var key keyType

func NewContextWithUserinfo(ctx context.Context, userinfo *identityapi.Userinfo) context.Context {
	return context.WithValue(ctx, key, userinfo)
}

func UserinfoFromContext(ctx context.Context) (*identityapi.Userinfo, error) {
	if value := ctx.Value(key); value != nil {
		if userinfo, ok := value.(*identityapi.Userinfo); ok {
			return userinfo, nil
		}
	}

	return nil, errors.ErrInvalidContext
}
