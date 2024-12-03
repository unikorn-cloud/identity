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
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/handler/oauth2providers"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
	"github.com/unikorn-cloud/identity/pkg/oauth2"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// namespace is the namespace we are running in.
	namespace string

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	// oauth2 is the oauth2 deletgating authenticator.
	oauth2 *oauth2.Authenticator

	// rbac gives access to low level rbac functionality.
	rbac *rbac.RBAC

	// options allows behaviour to be defined on the CLI.
	options *Options
}

func New(client client.Client, namespace string, issuer *jose.JWTIssuer, oauth2 *oauth2.Authenticator, rbac *rbac.RBAC, options *Options) (*Handler, error) {
	h := &Handler{
		client:    client,
		namespace: namespace,
		issuer:    issuer,
		oauth2:    oauth2,
		rbac:      rbac,
		options:   options,
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

func (h *Handler) GetWellKnownOpenidConfiguration(w http.ResponseWriter, r *http.Request) {
	result := &openapi.OpenidConfiguration{
		Issuer:                h.options.Host,
		AuthorizationEndpoint: fmt.Sprintf("%s/oauth2/v2/authorization", h.options.Host),
		TokenEndpoint:         fmt.Sprintf("%s/oauth2/v2/token", h.options.Host),
		UserinfoEndpoint:      fmt.Sprintf("%s/oauth2/v2/userinfo", h.options.Host),
		JwksUri:               fmt.Sprintf("%s/oauth2/v2/jwks", h.options.Host),
		ScopesSupported: []openapi.Scope{
			openapi.ScopeEmail,
			openapi.ScopeOpenid,
			openapi.ScopeProfile,
		},
		ClaimsSupported: []openapi.Claim{
			openapi.ClaimAud,
			openapi.ClaimEmail,
			openapi.ClaimEmailVerified,
			openapi.ClaimExp,
			openapi.ClaimFamilyName,
			openapi.ClaimGivenName,
			openapi.ClaimIat,
			openapi.ClaimIss,
			openapi.ClaimLocale,
			openapi.ClaimName,
			openapi.ClaimPicture,
			openapi.ClaimSub,
		},
		ResponseTypesSupported: []openapi.ResponseType{
			openapi.ResponseTypeCode,
		},
		TokenEndpointAuthMethodsSupported: []openapi.AuthMethod{
			openapi.ClientSecretPost,
			openapi.TlsClientAuth,
		},
		GrantTypesSupported: []openapi.GrantType{
			openapi.AuthorizationCode,
			openapi.ClientCredentials,
			openapi.RefreshToken,
		},
		IdTokenSigningAlgValuesSupported: []openapi.SigningAlgorithm{
			openapi.ES512,
		},
		CodeChallengeMethodsSupported: []openapi.CodeChallengeMethod{
			openapi.S256,
		},
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Authorization(w, r)
}

func (h *Handler) PostOauth2V2Login(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Login(w, r)
}

func (h *Handler) PostOauth2V2Token(w http.ResponseWriter, r *http.Request) {
	result, err := h.oauth2.Token(w, r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	userinfo, err := authorization.UserinfoFromContext(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("userinfo is not set").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo)
}

func (h *Handler) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	result, _, err := h.issuer.GetJSONWebKeySet(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("unable to generate json web key set").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	h.oauth2.OIDCCallback(w, r)
}

func (h *Handler) GetApiV1Oauth2providers(w http.ResponseWriter, r *http.Request) {
	result, err := oauth2providers.New(h.client, h.namespace).ListGlobal(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAcl(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result := rbac.FromContext(r.Context())

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRoles(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:roles", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := roles.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := oauth2providers.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := oauth2providers.New(h.client, h.namespace).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := oauth2providers.New(h.client, h.namespace).Update(r.Context(), organizationID, providerID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:oauth2providers", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := oauth2providers.New(h.client, h.namespace).Delete(r.Context(), organizationID, providerID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GetApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	result, err := organizations.New(h.client, h.namespace).List(r.Context(), h.rbac)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	if err := rbac.AllowGlobalScope(r.Context(), "identity:organizations", openapi.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.OrganizationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := organizations.New(h.client, h.namespace).Create(r.Context(), request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:organizations", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := organizations.New(h.client, h.namespace).Get(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:organizations", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.OrganizationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := organizations.New(h.client, h.namespace).Update(r.Context(), organizationID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAvailableGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.oauth2.Groups(w, r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := groups.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := groups.New(h.client, h.namespace).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := groups.New(h.client, h.namespace).Get(r.Context(), organizationID, groupID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := groups.New(h.client, h.namespace).Delete(r.Context(), organizationID, groupID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:groups", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := groups.New(h.client, h.namespace).Update(r.Context(), organizationID, groupID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := projects.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	// Apply RBAC after listing as a filter.
	result = slices.DeleteFunc(result, func(resource openapi.ProjectRead) bool {
		return rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Read, organizationID, resource.Metadata.Id) != nil
	})

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:projects", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := projects.New(h.client, h.namespace).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := projects.New(h.client, h.namespace).Get(r.Context(), organizationID, projectID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).Update(r.Context(), organizationID, projectID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:projects", openapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).Delete(r.Context(), organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1Acl(w http.ResponseWriter, r *http.Request) {
	result, err := h.rbac.GetACL(r.Context(), "", "")
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
