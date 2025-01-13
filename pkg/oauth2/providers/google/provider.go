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

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers/errors"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers/types"

	"k8s.io/utils/ptr"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (*Provider) AuthorizationRequestParameters() map[string]string {
	// This grants us access to a refresh token.
	// See: https://developers.google.com/identity/openid-connect/openid-connect#access-type-param
	// And: https://stackoverflow.com/questions/10827920/not-receiving-google-oauth-refresh-token
	return map[string]string{
		"prompt":      "consent",
		"access_type": "offline",
	}
}

func (*Provider) Scopes() []string {
	return []string{
		// This provides read-only access to a user's groups.
		"https://www.googleapis.com/auth/cloud-identity.groups.readonly",
	}
}

func (*Provider) RequiresAccessToken() bool {
	return true
}

type Group struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type Groups struct {
	Groups []Group `json:"groups"`
}

/*
SCOPES:

* https://www.googleapis.com/auth/cloud-identity.groups.readonly
* https://www.googleapis.com/auth/cloud-identity.groups
* https://www.googleapis.com/auth/cloud-identity
* https://www.googleapis.com/auth/cloud-platform

or...

GET https://admin.googleapis.com/admin/directory/v1/groups

https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups/list

{
  "kind": "admin#directory#groups",
  "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/5dl-BOsz4lBOImoI3lLrwvGKy1Q\"",
  "groups": [
    {
      "kind": "admin#directory#group",
      "id": "01rvwp1q1gini8q",
      "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/UQNupgFQfUCP_44mDaRNpM_vJqc\"",
      "email": "all@nscale.com",
      "name": "Everyone",
      "directMembersCount": "3",
      "description": "Everyone, use with extreme caution!",
      "adminCreated": true,
      "nonEditableAliases": [
        "all@nscale.com.test-google-a.com"
      ]
    }
  ],
  "nextPageToken": "Q2ljd0xDSmhiR3hBYm5OallXeGxMbU52YlNJc01pd2lNREF3TURBd09ETTRNV1F4TVRabFlTSklCR0MwanJqaUFXb2hjM1Z3Y0c5eWRDMW9hV1JsTFhObGRIUnBibWN0Y205emRHVnlMWEYxWlhKNQ=="
}
*/
//nolint:cyclop
func (p *Provider) Groups(ctx context.Context, organization *unikornv1.Organization, accessToken string) ([]types.Group, error) {
	if organization == nil || organization.Spec.ProviderOptions == nil || organization.Spec.ProviderOptions.Google == nil || organization.Spec.ProviderOptions.Google.CustomerID == nil {
		return nil, nil
	}

	query := url.Values{
		"parent": []string{
			"customers/" + *organization.Spec.ProviderOptions.Google.CustomerID,
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

	// On success:
	//
	// {
	//   "name": "groups/xzy", # This is the "group ID"
	//   "groupKey": {
	//     "id": "alias@org.com"
	//   },
	//   "displayName": "Human readable"
	//  }
	//
	// On error:
	//
	// {
	//   "error": {
	//     "code": 401,
	//     "message": "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.",
	//     "status": "UNAUTHENTICATED"
	//   }
	// }
	switch response.StatusCode {
	case http.StatusOK:
		break
	case http.StatusUnauthorized:
		return nil, errors.ErrUnauthorized
	default:
		return nil, fmt.Errorf("%w: got %d, body %s", errors.ErrUnexpectedStatusCode, response.StatusCode, string(body))
	}

	var groups Groups

	if err := json.Unmarshal(body, &groups); err != nil {
		return nil, err
	}

	result := make([]types.Group, 0, len(groups.Groups))

	for _, group := range groups.Groups {
		result = append(result, types.Group{
			Name:        group.Name,
			DisplayName: ptr.To(group.DisplayName),
		})
	}

	return result, nil
}

/*
SCOPES:

* https://www.googleapis.com/auth/cloud-identity.groups.readonly
* https://www.googleapis.com/auth/cloud-identity.groups
* https://www.googleapis.com/auth/cloud-identity
* https://www.googleapis.com/auth/cloud-platform

GET https://cloudidentity.googleapis.com/vi/{groupID=groups/xyz}/memberships?view=BASIC&pageSize=X&pageToken=Y

{
  "memberships": [
    {
      "name": "groups/03mzq4wv10ygnsx/memberships/102914945678377600674",
      "memberKey": {
        "id": "drew@nscale.com"
      },
      "roles": [
        {
          "name": "MEMBER"
        },
        {
          "name": "MANAGER"
        }
      ],
      "preferredMemberKey": {
        "id": "drew@nscale.com"
      }
    },
  ],
  "nextPageToken": "IhcKCQiHqemb0g4YARIHCInHkPzzFhjqBzANUAFYAQ=="
}

or:

GET https://admin.googleapis.com/admin/directory/v1/groups/{groupKey}/members

https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/list
o{
  "kind": "admin#directory#members",
  "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/fd_oBPHcqG8PHkO89QMmRe1FRrg\"",
  "members": [
    {
      "kind": "admin#directory#member",
      "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/4oZ4wB52slvqCl3BzI6_YMhHWZU\"",
      "id": "112999204022039996338",
      "email": "amin@nscale.com",
      "role": "MEMBER",
      "type": "USER",
      "status": "ACTIVE"
    }
  ],
  "nextPageToken": "CjBJaHdLR2dpbDJPbk1pQVFTRDJGdGFXNUFibk5qWVd4bExtTnZiUmdCWUx1TTNQY0QiHAoaCKXY6cyIBBIPYW1pbkBuc2NhbGUuY29tGAFgu4zc9wM="
}

{
  "kind": "admin#directory#members",
  "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/P0HWsUlPIjV7ernA3b4siONAxso\"",
  "members": [
    {
      "kind": "admin#directory#member",
      "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/m9JBs0_Rle6AWEKjmK2Ja-_fyPk\"",
      "id": "C02qjd6lx",
      "role": "MEMBER",
      "type": "CUSTOMER"
    }
  ],
  "nextPageToken": "CjhJaUlLSUFpdjhkUHI2d2dTRlM5b1pDOWtiMjFoYVc0dmJuTmpZV3hsTG1OdmJSZ0NZS0dIOExzRSIiCiAIr_HT6-sIEhUvaGQvZG9tYWluL25zY2FsZS5jb20YAmChh_C7BA=="
}

*/

/*
SCOPES:

* https://www.googleapis.com/auth/admin.directory.user
* https://www.googleapis.com/auth/admin.directory.user.readonly
* https://www.googleapis.com/auth/cloud-platform

GET https://admin.googleapis.com/admin/directory/v1/users&customer=C02qjd6lx&viewType=domain_public

{
  "kind": "admin#directory#users",
  "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/FC9DvLkkCkbIoe2XckEJ45RuCpo\"",
  "users": [
    {
      "kind": "admin#directory#user",
      "id": "101500039720350465469",
      "etag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/bELmHY5xsXf99Iq92-m4u-c6V_w\"",
      "primaryEmail": "adam.flanagan@nscale.com",
      "name": {
        "givenName": "Adam",
        "familyName": "Flanagan",
        "fullName": "Adam Flanagan"
      },
      "emails": [
        {
          "address": "amfwebsolutions@gmail.com",
          "type": "work"
        },
        {
          "address": "adam.flanagan@nscale.com",
          "primary": true
        }
      ],
      "languages": [
        {
          "languageCode": "en-GB",
          "preference": "preferred"
        }
      ],
      "thumbnailPhotoUrl": "https://lh3.googleusercontent.com/a-/ALV-UjVUGgb3u3bMDo4-ccDZNj3dcz-A9Mto9RqbTJKBCNi2xry8-Hg=s96-c",
      "thumbnailPhotoEtag": "\"g3-uukzdDYX7mcsQqDSmVT-0S6NlDP7HhGVb5s3jADM/Ye72DgwZGxjLkgOVJsG17bHB3Kc\""
    }
  ],
  "nextPageToken": "Ci2qASoKKDAsImFkYW0uZmxhbmFnYW4iLDMyMjE3Mjk5NTc0NCxOVUxMLDEsIiI="
}

*/
