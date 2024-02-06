/*
Copyright 2022-2024 EscherCloud.
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

//nolint:revive,stylecheck
package handler

import (
	"fmt"
	"net/http"

	"github.com/unikorn-cloud/identity/pkg/authorization"
	"github.com/unikorn-cloud/identity/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/generated"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// authenticator gives access to authentication and token handling functions.
	authenticator *authorization.Authenticator

	// options allows behaviour to be defined on the CLI.
	options *Options
}

func New(client client.Client, authenticator *authorization.Authenticator, options *Options) (*Handler, error) {
	h := &Handler{
		client:        client,
		authenticator: authenticator,
		options:       options,
	}

	return h, nil
}

/*
func (h *Handler) setCacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", fmt.Sprintf("max-age=%d", h.options.CacheMaxAge/time.Second))
	w.Header().Add("Cache-Control", "private")
}
*/

func (h *Handler) setUncacheable(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")
}

func (h *Handler) setCORS(w http.ResponseWriter) {
	w.Header().Add("Access-Control-Allow-Origin", "*")
}

func (h *Handler) GetWellKnownOpenidConfiguration(w http.ResponseWriter, r *http.Request) {
	result := &generated.OpenidConfiguration{
		Issuer:                h.options.Host,
		AuthorizationEndpoint: fmt.Sprintf("%s/oauth2/v2/authorization", h.options.Host),
		TokenEndpoint:         fmt.Sprintf("%s/oauth2/v2/token", h.options.Host),
		JwksUri:               fmt.Sprintf("%s/oauth2/v2/jwks", h.options.Host),
		ScopesSupported: []generated.Scope{
			generated.ScopeEmail,
			generated.ScopeOpenid,
			generated.ScopeProfile,
		},
		ClaimsSupported: []generated.Claim{
			generated.ClaimAud,
			generated.ClaimEmail,
			generated.ClaimEmailVerified,
			generated.ClaimExp,
			generated.ClaimFamilityName,
			generated.ClaimGivenName,
			generated.ClaimIat,
			generated.ClaimIss,
			generated.ClaimLocale,
			generated.ClaimName,
			generated.ClaimPicture,
			generated.ClaimSub,
		},
		ResponseTypesSupported: []generated.ResponseType{
			generated.ResponseTypeCode,
		},
		TokenEndpointAuthMethodsSupported: []generated.AuthMethod{
			generated.ClientSecretPost,
		},
		GrantTypesSupported: []generated.GrantType{
			generated.AuthorizationCode,
		},
		IdTokenSigningAlgValuesSupported: []generated.SigningAlgorithm{
			generated.ES512,
		},
		CodeChallengeMethodsSupported: []generated.CodeChallengeMethod{
			generated.S256,
		},
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.authenticator.OAuth2.Authorization(w, r)
}

func (h *Handler) PostOauth2V2Login(w http.ResponseWriter, r *http.Request) {
	h.authenticator.OAuth2.Login(w, r)
}

func (h *Handler) PostOauth2V2Token(w http.ResponseWriter, r *http.Request) {
	result, err := h.authenticator.OAuth2.Token(w, r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setCORS(w)
	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	result, err := h.authenticator.JWKS()
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setCORS(w)
	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	h.authenticator.OAuth2.OIDCCallback(w, r)
}

func (h *Handler) GetApiV1Organizations(w http.ResponseWriter, r *http.Request) {
}

func (h *Handler) PutApiV1OrganizationsOrganization(w http.ResponseWriter, r *http.Request, organization generated.OrganizationParameter) {
}

func (h *Handler) GetApiV1OrganizationsOrganizationGroups(w http.ResponseWriter, r *http.Request, organization generated.OrganizationParameter) {
}

func (h *Handler) PostApiV1OrganizationsOrganizationGroups(w http.ResponseWriter, r *http.Request, organization generated.OrganizationParameter) {
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationGroupsGroupid(w http.ResponseWriter, r *http.Request, organization generated.OrganizationParameter, groupid generated.GroupidParameter) {
}

func (h *Handler) PutApiV1OrganizationsOrganizationGroupsGroupid(w http.ResponseWriter, r *http.Request, organization generated.OrganizationParameter, groupid generated.GroupidParameter) {
}
