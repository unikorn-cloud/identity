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

package flags

import (
	"fmt"
	"net/url"

	"github.com/unikorn-cloud/identity/pkg/cmd/errors"
)

type HostnameVar string

func (v *HostnameVar) Set(s string) error {
	u, err := url.ParseRequestURI("scheme://" + s)
	if err != nil {
		return err
	}

	if u.Host != s {
		return fmt.Errorf("%w: %s is not a valid domain name", errors.ErrValidation, s)
	}

	*v = HostnameVar(s)

	return nil
}

func (v HostnameVar) String() string {
	return string(v)
}

func (v HostnameVar) Type() string {
	return "domainname"
}
