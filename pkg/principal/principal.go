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

package principal

import (
	"context"

	"github.com/unikorn-cloud/core/pkg/errors"
)

const (
	Header = "X-Principal"
)

// Principal records information about what user insigated a request.
type Principal struct {
	OrganizationID string `json:"organizationId,omitempty"`
	ProjectID      string `json:"projectId,omitempty"`
	Email          string `json:"email,omitempty"`
}

type principalKeyType int

const (
	principalKey principalKeyType = iota
)

func NewContext(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey, principal)
}

func FromContext(ctx context.Context) (*Principal, error) {
	if value := ctx.Value(principalKey); value != nil {
		if principal, ok := value.(*Principal); ok {
			return principal, nil
		}
	}

	return nil, errors.ErrInvalidContext
}
