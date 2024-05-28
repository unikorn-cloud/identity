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
	"context"
	"fmt"
	"net/http"

	"github.com/unikorn-cloud/core/pkg/authorization/constants"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/authorization"
	"github.com/unikorn-cloud/identity/pkg/handler/groups"
	"github.com/unikorn-cloud/identity/pkg/handler/oauth2providers"
	"github.com/unikorn-cloud/identity/pkg/handler/organizations"
	"github.com/unikorn-cloud/identity/pkg/handler/projects"
	"github.com/unikorn-cloud/identity/pkg/handler/roles"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/util"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Handler struct {
	// client gives cached access to Kubernetes.
	client client.Client

	// namespace is the namespace we are running in.
	namespace string

	// authenticator gives access to authentication and token handling functions.
	authenticator *authorization.Authenticator

	// options allows behaviour to be defined on the CLI.
	options *Options
}

func (h *Handler) checkRBAC(ctx context.Context, organizationID, scope string, permission constants.Permission) error {
	authorizer, err := userinfo.NewAuthorizer(ctx, newACLGetter(h.client, h.namespace, organizationID))
	if err != nil {
		return errors.HTTPForbidden("operation is not allowed by rbac").WithError(err)
	}

	if err := authorizer.Allow(ctx, scope, permission); err != nil {
		return errors.HTTPForbidden("operation is not allowed by rbac").WithError(err)
	}

	return nil
}

func New(client client.Client, namespace string, authenticator *authorization.Authenticator, options *Options) (*Handler, error) {
	h := &Handler{
		client:        client,
		namespace:     namespace,
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
		},
		GrantTypesSupported: []openapi.GrantType{
			openapi.AuthorizationCode,
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

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOauth2V2Userinfo(w http.ResponseWriter, r *http.Request) {
	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, userinfo.FromContext(r.Context()))
}

func (h *Handler) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	result, err := h.authenticator.JWKS(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	h.authenticator.OAuth2.OIDCCallback(w, r)
}

func (h *Handler) GetApiV1Oauth2providers(w http.ResponseWriter, r *http.Request) {
	if err := h.checkRBAC(r.Context(), "", "oauth2providers", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := oauth2providers.New(h.client, h.namespace).ListGlobal(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDAcl(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	result, err := newACLGetter(h.client, h.namespace, organizationID).Get(r.Context())
	if err != nil {
		errors.HandleError(w, r, errors.HTTPForbidden("operation is not allowed by rbac").WithError(err))
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDRoles(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "roles", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := roles.New(h.client, h.namespace).List(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDOauth2providers(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "oauth2providers", constants.Read); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "oauth2providers", constants.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.Oauth2ProviderWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := oauth2providers.New(h.client, h.namespace).Create(r.Context(), organizationID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) PutApiV1OrganizationsOrganizationIDOauth2providersProviderID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, providerID openapi.Oauth2ProvderIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "oauth2providers", constants.Update); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "oauth2providers", constants.Delete); err != nil {
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
	if err := h.checkRBAC(r.Context(), "", "organizations", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := organizations.New(h.client, h.namespace).List(r.Context())
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	if err := h.checkRBAC(r.Context(), "", "organizations", constants.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}
}

func (h *Handler) GetApiV1OrganizationsOrganizationID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := h.checkRBAC(r.Context(), "", "organizations", constants.Update); err != nil {
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
	if err := h.checkRBAC(r.Context(), "", "organizations", constants.Update); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "groups", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := h.authenticator.OAuth2.Groups(w, r)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroups(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "groups", constants.Read); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "groups", constants.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.GroupWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := groups.New(h.client, h.namespace).Create(r.Context(), organizationID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDGroupsGroupid(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, groupID openapi.GroupidParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "groups", constants.Delete); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "groups", constants.Delete); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "groups", constants.Update); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "projects", constants.Read); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	result, err := projects.New(h.client, h.namespace).List(r.Context(), organizationID)
	if err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	util.WriteJSONResponse(w, r, http.StatusOK, result)
}

func (h *Handler) PostApiV1OrganizationsOrganizationIDProjects(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "projects", constants.Create); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	request := &openapi.ProjectWrite{}

	if err := util.ReadJSONBody(r, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	if err := projects.New(h.client, h.namespace).Create(r.Context(), organizationID, request); err != nil {
		errors.HandleError(w, r, err)
		return
	}

	h.setUncacheable(w)
	w.WriteHeader(http.StatusAccepted)
}

func (h *Handler) GetApiV1OrganizationsOrganizationIDProjectsProjectID(w http.ResponseWriter, r *http.Request, organizationID openapi.OrganizationIDParameter, projectID openapi.ProjectIDParameter) {
	if err := h.checkRBAC(r.Context(), organizationID, "projects", constants.Read); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "projects", constants.Update); err != nil {
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
	if err := h.checkRBAC(r.Context(), organizationID, "projects", constants.Delete); err != nil {
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
