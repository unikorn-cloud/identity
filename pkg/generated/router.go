// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package generated

import (
	"fmt"
	"net/http"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/go-chi/chi/v5"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {

	// (GET /.well-known/openid-configuration)
	GetWellKnownOpenidConfiguration(w http.ResponseWriter, r *http.Request)

	// (GET /api/v1/oauth2/providers)
	GetApiV1Oauth2Providers(w http.ResponseWriter, r *http.Request)

	// (GET /api/v1/organizations)
	GetApiV1Organizations(w http.ResponseWriter, r *http.Request)

	// (POST /api/v1/organizations)
	PostApiV1Organizations(w http.ResponseWriter, r *http.Request)

	// (PUT /api/v1/organizations/{organization})
	PutApiV1OrganizationsOrganization(w http.ResponseWriter, r *http.Request, organization OrganizationParameter)

	// (GET /api/v1/organizations/{organization}/groups)
	GetApiV1OrganizationsOrganizationGroups(w http.ResponseWriter, r *http.Request, organization OrganizationParameter)

	// (POST /api/v1/organizations/{organization}/groups)
	PostApiV1OrganizationsOrganizationGroups(w http.ResponseWriter, r *http.Request, organization OrganizationParameter)

	// (DELETE /api/v1/organizations/{organization}/groups/{groupid})
	DeleteApiV1OrganizationsOrganizationGroupsGroupid(w http.ResponseWriter, r *http.Request, organization OrganizationParameter, groupid GroupidParameter)

	// (PUT /api/v1/organizations/{organization}/groups/{groupid})
	PutApiV1OrganizationsOrganizationGroupsGroupid(w http.ResponseWriter, r *http.Request, organization OrganizationParameter, groupid GroupidParameter)

	// (GET /oauth2/v2/authorization)
	GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request)

	// (GET /oauth2/v2/jwks)
	GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request)

	// (POST /oauth2/v2/login)
	PostOauth2V2Login(w http.ResponseWriter, r *http.Request)

	// (POST /oauth2/v2/token)
	PostOauth2V2Token(w http.ResponseWriter, r *http.Request)

	// (GET /oidc/callback)
	GetOidcCallback(w http.ResponseWriter, r *http.Request)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// GetWellKnownOpenidConfiguration operation middleware
func (siw *ServerInterfaceWrapper) GetWellKnownOpenidConfiguration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetWellKnownOpenidConfiguration(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetApiV1Oauth2Providers operation middleware
func (siw *ServerInterfaceWrapper) GetApiV1Oauth2Providers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetApiV1Oauth2Providers(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetApiV1Organizations operation middleware
func (siw *ServerInterfaceWrapper) GetApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetApiV1Organizations(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PostApiV1Organizations operation middleware
func (siw *ServerInterfaceWrapper) PostApiV1Organizations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PostApiV1Organizations(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PutApiV1OrganizationsOrganization operation middleware
func (siw *ServerInterfaceWrapper) PutApiV1OrganizationsOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "organization" -------------
	var organization OrganizationParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "organization", runtime.ParamLocationPath, chi.URLParam(r, "organization"), &organization)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "organization", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PutApiV1OrganizationsOrganization(w, r, organization)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetApiV1OrganizationsOrganizationGroups operation middleware
func (siw *ServerInterfaceWrapper) GetApiV1OrganizationsOrganizationGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "organization" -------------
	var organization OrganizationParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "organization", runtime.ParamLocationPath, chi.URLParam(r, "organization"), &organization)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "organization", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetApiV1OrganizationsOrganizationGroups(w, r, organization)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PostApiV1OrganizationsOrganizationGroups operation middleware
func (siw *ServerInterfaceWrapper) PostApiV1OrganizationsOrganizationGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "organization" -------------
	var organization OrganizationParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "organization", runtime.ParamLocationPath, chi.URLParam(r, "organization"), &organization)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "organization", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PostApiV1OrganizationsOrganizationGroups(w, r, organization)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// DeleteApiV1OrganizationsOrganizationGroupsGroupid operation middleware
func (siw *ServerInterfaceWrapper) DeleteApiV1OrganizationsOrganizationGroupsGroupid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "organization" -------------
	var organization OrganizationParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "organization", runtime.ParamLocationPath, chi.URLParam(r, "organization"), &organization)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "organization", Err: err})
		return
	}

	// ------------- Path parameter "groupid" -------------
	var groupid GroupidParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "groupid", runtime.ParamLocationPath, chi.URLParam(r, "groupid"), &groupid)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "groupid", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.DeleteApiV1OrganizationsOrganizationGroupsGroupid(w, r, organization, groupid)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PutApiV1OrganizationsOrganizationGroupsGroupid operation middleware
func (siw *ServerInterfaceWrapper) PutApiV1OrganizationsOrganizationGroupsGroupid(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var err error

	// ------------- Path parameter "organization" -------------
	var organization OrganizationParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "organization", runtime.ParamLocationPath, chi.URLParam(r, "organization"), &organization)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "organization", Err: err})
		return
	}

	// ------------- Path parameter "groupid" -------------
	var groupid GroupidParameter

	err = runtime.BindStyledParameterWithLocation("simple", false, "groupid", runtime.ParamLocationPath, chi.URLParam(r, "groupid"), &groupid)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "groupid", Err: err})
		return
	}

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PutApiV1OrganizationsOrganizationGroupsGroupid(w, r, organization, groupid)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetOauth2V2Authorization operation middleware
func (siw *ServerInterfaceWrapper) GetOauth2V2Authorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetOauth2V2Authorization(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetOauth2V2Jwks operation middleware
func (siw *ServerInterfaceWrapper) GetOauth2V2Jwks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetOauth2V2Jwks(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PostOauth2V2Login operation middleware
func (siw *ServerInterfaceWrapper) PostOauth2V2Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PostOauth2V2Login(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// PostOauth2V2Token operation middleware
func (siw *ServerInterfaceWrapper) PostOauth2V2Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.PostOauth2V2Token(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

// GetOidcCallback operation middleware
func (siw *ServerInterfaceWrapper) GetOidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetOidcCallback(w, r)
	})

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r.WithContext(ctx))
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshallingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshallingParamError) Error() string {
	return fmt.Sprintf("Error unmarshalling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshallingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/.well-known/openid-configuration", wrapper.GetWellKnownOpenidConfiguration)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/oauth2/providers", wrapper.GetApiV1Oauth2Providers)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/organizations", wrapper.GetApiV1Organizations)
	})
	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/api/v1/organizations", wrapper.PostApiV1Organizations)
	})
	r.Group(func(r chi.Router) {
		r.Put(options.BaseURL+"/api/v1/organizations/{organization}", wrapper.PutApiV1OrganizationsOrganization)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/api/v1/organizations/{organization}/groups", wrapper.GetApiV1OrganizationsOrganizationGroups)
	})
	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/api/v1/organizations/{organization}/groups", wrapper.PostApiV1OrganizationsOrganizationGroups)
	})
	r.Group(func(r chi.Router) {
		r.Delete(options.BaseURL+"/api/v1/organizations/{organization}/groups/{groupid}", wrapper.DeleteApiV1OrganizationsOrganizationGroupsGroupid)
	})
	r.Group(func(r chi.Router) {
		r.Put(options.BaseURL+"/api/v1/organizations/{organization}/groups/{groupid}", wrapper.PutApiV1OrganizationsOrganizationGroupsGroupid)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/oauth2/v2/authorization", wrapper.GetOauth2V2Authorization)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/oauth2/v2/jwks", wrapper.GetOauth2V2Jwks)
	})
	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/oauth2/v2/login", wrapper.PostOauth2V2Login)
	})
	r.Group(func(r chi.Router) {
		r.Post(options.BaseURL+"/oauth2/v2/token", wrapper.PostOauth2V2Token)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/oidc/callback", wrapper.GetOidcCallback)
	})

	return r
}
