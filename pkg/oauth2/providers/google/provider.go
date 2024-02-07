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

package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
)

var (
	ErrUnexpectedStatusCode = errors.New("unexpected status code")
)

type Provider struct {
	organization *unikornv1.Organization
}

func New(organization *unikornv1.Organization) *Provider {
	return &Provider{
		organization: organization,
	}
}

func (*Provider) Scopes() []string {
	return []string{
		// This provides read-only access to a user's groups.
		"https://www.googleapis.com/auth/cloud-identity.groups.readonly",
	}
}

type Group struct {
	Name string `json:"name"`
}

type Groups struct {
	Groups []Group `json:"groups"`
}

func (p *Provider) Groups(ctx context.Context, accessToken string) ([]string, error) {
	if p.organization.Spec.ProviderOptions == nil || p.organization.Spec.ProviderOptions.Google == nil {
		return nil, nil
	}

	query := url.Values{
		"parent": []string{
			"customers/" + p.organization.Spec.ProviderOptions.Google.CustomerID,
		},
	}

	url := url.URL{
		Scheme:   "https",
		Host:     "cloudidentity.googleapis.com",
		Path:     "/v1/groups/",
		RawQuery: query.Encode(),
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add("Authorization", "Bearer "+accessToken)

	client := &http.Client{}

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	expectedStatusCode := http.StatusOK

	if response.StatusCode != expectedStatusCode {
		return nil, fmt.Errorf("%w: wanted %d, got %d, body %s", ErrUnexpectedStatusCode, expectedStatusCode, response.StatusCode, string(body))
	}

	var groups Groups

	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(groups.Groups))

	for _, group := range groups.Groups {
		result = append(result, group.Name)
	}

	return result, nil
}
