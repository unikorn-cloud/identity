/*
Copyright 2022-2024 EscherCloud.
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

//nolint:revive,stylecheck
package handler

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/server/util"
	"github.com/unikorn-cloud/identity/pkg/handler/allocations"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/handler/oauth2providers"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/handler/quotas"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/handler/serviceaccounts"
	"github.com/unikorn-cloud/identity/pkg/handler/users"
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

func (h *Handler) setUncacheableNoStore(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-store")
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
			openapi.ClientSecretBasic,
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
			openapi.Plain,
			openapi.S256,
		},
	}

	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	h.oauth2.Authorization(w, r)
}

func (h *Handler) PostOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
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

	// See OIDC 1.0 Section 3.1.3.3.
	h.setUncacheableNoStore(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	info, err := authorization.FromContext(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("userinfo is not set").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, info.Userinfo)
}

func (h *Handler) PostOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	info, err := authorization.FromContext(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("userinfo is not set").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, info.Userinfo)
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
	h.oauth2.Callback(w, r)
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

func (h *Handler) GetApiV1Acl(w http.ResponseWriter, r *http.Request) {
	// The middleware will populate this from the URL, and thus not have access to any
	// scoping information, so just return anything at the global scope.
	// TODO: we may want to consider just returning everything across all organizations.
	result := rbac.FromContext(r.Context())

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
	util.WriteJSONResponse(w, r, http.StatusAccepted, result)
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

func (h *Handler) serviceAccountsClient(r *http.Request) *serviceaccounts.Client {
	return serviceaccounts.New(h.client, h.namespace, r.Host, h.oauth2, &h.options.ServiceAccounts)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDServiceaccounts(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := h.serviceAccountsClient(r).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDServiceaccounts(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServiceAccountWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient(r).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ServiceAccountWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient(r).Update(r.Context(), organizationID, serviceAccountID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.serviceAccountsClient(r).Delete(r.Context(), organizationID, serviceAccountID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountIDRotate(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, serviceAccountID openapi.ServiceAccountIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:serviceaccounts", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.serviceAccountsClient(r).Rotate(r.Context(), organizationID, serviceAccountID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) usersClient(r *http.Request) *users.Client {
	return users.New(r.Host, h.client, h.namespace, h.issuer, &h.options.Users)
}

func (h *Handler) GetApiV1Signup(w http.ResponseWriter, r *http.Request) {
	h.usersClient(r).Signup(w, r)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDUsers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient(r).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDUsers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Create, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.UserWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient(r).Create(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDUsersUserID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, userID openapi.UserIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Delete, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.usersClient(r).Delete(r.Context(), organizationID, userID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDUsersUserID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, userID openapi.UserIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:users", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.UserWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.usersClient(r).Update(r.Context(), organizationID, userID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) quotasClient() *quotas.Client {
	return quotas.New(h.client, h.namespace)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:quotas", openapi.Read, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.quotasClient().Get(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDQuotas(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := rbac.AllowOrganizationScope(r.Context(), "identity:quotas", openapi.Update, organizationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.QuotasWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.quotasClient().Update(r.Context(), organizationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) allocationsClient() *allocations.Client {
	return allocations.New(h.client, h.namespace)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	ctx := r.Context()

	result, err := h.allocationsClient().List(ctx, organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result = slices.DeleteFunc(result, func(resource openapi.AllocationRead) bool {
		return rbac.AllowProjectScope(ctx, "identity:allocations", openapi.Read, organizationID, resource.Metadata.ProjectId) != nil
	})

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocations(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:allocations", openapi.Create, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.AllocationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Create(r.Context(), organizationID, projectID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusCreated, result)
}

func (h *Handler) DeleteApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:allocations", openapi.Delete, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := h.allocationsClient().Delete(r.Context(), organizationID, projectID, allocationID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:allocations", openapi.Read, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Get(r.Context(), organizationID, projectID, allocationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter, allocationID openapi.AllocationIDParameter) {
	if err := rbac.AllowProjectScope(r.Context(), "identity:allocations", openapi.Update, organizationID, projectID); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.AllocationWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.allocationsClient().Update(r.Context(), organizationID, projectID, allocationID, request)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}
