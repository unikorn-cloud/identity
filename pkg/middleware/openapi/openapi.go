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

package openapi

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/unikorn-cloud/core/pkg/authorization/accesstoken"
	"github.com/unikorn-cloud/core/pkg/authorization/userinfo"
	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	identityapi "github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Validator provides Schema validation of request and response codes,
// media, and schema validation of payloads to ensure we are meeting the
// specification.
type Validator struct {
	// next defines the next HTTP handler in the chain.
	next http.Handler

	// authorizer provides security policy enforcement.
	authorizer Authorizer

	// openapi caches the Schema schema.
	openapi *openapi.Schema

	// accessToken is used to propagate to descendant services.
	accessToken string

	// userinfo is used for identity and RBAC.
	userinfo *userinfo.UserInfo

	// err is used to indicate the actual openapi error.
	err error
}

// Ensure this implements the required interfaces.
var _ http.Handler = &Validator{}

// NewValidator returns an initialized validator middleware.
func NewValidator(authorizer Authorizer, next http.Handler, openapi *openapi.Schema) *Validator {
	return &Validator{
		authorizer: authorizer,
		next:       next,
		openapi:    openapi,
	}
}

// bufferingResponseWriter saves the response code and body so that we can
// validate them.
type bufferingResponseWriter struct {
	// next is the parent handler.
	next http.ResponseWriter

	// code is the HTTP status code.
	code int

	// body is a copy of the HTTP response body.
	// This valus will be nil if no body was written.
	body io.ReadCloser
}

// Ensure the correct interfaces are implmeneted.
var _ http.ResponseWriter = &bufferingResponseWriter{}

// Header returns the HTTP headers.
func (w *bufferingResponseWriter) Header() http.Header {
	return w.next.Header()
}

// Write writes out a body, if WriteHeader has not been called this will
// be done with a 200 status code.
func (w *bufferingResponseWriter) Write(body []byte) (int, error) {
	buf := &bytes.Buffer{}
	buf.Write(body)

	w.body = io.NopCloser(buf)

	return w.next.Write(body)
}

// WriteHeader writes out the HTTP headers with the provided status code.
func (w *bufferingResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode

	w.next.WriteHeader(statusCode)
}

// StatusCode calculates the status code returned to the client.
func (w *bufferingResponseWriter) StatusCode() int {
	if w.code == 0 {
		return http.StatusOK
	}

	return w.code
}

func (v *Validator) validateRequest(r *http.Request, route *routers.Route, params map[string]string) (*openapi3filter.ResponseValidationInput, error) {
	authorizationFunc := func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		v.accessToken, v.userinfo, v.err = v.authorizer.Authorize(input)

		return v.err
	}

	options := &openapi3filter.Options{
		IncludeResponseStatus: true,
		AuthenticationFunc:    authorizationFunc,
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: params,
		Route:      route,
		Options:    options,
	}

	if err := openapi3filter.ValidateRequest(r.Context(), requestValidationInput); err != nil {
		return nil, errors.OAuth2InvalidRequest("request body invalid").WithError(err)
	}

	responseValidationInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestValidationInput,
		Options:                options,
	}

	return responseValidationInput, nil
}

func (v *Validator) validateResponse(w *bufferingResponseWriter, r *http.Request, responseValidationInput *openapi3filter.ResponseValidationInput) {
	responseValidationInput.Status = w.StatusCode()
	responseValidationInput.Header = w.Header()
	responseValidationInput.Body = w.body

	if err := openapi3filter.ValidateResponse(r.Context(), responseValidationInput); err != nil {
		log.FromContext(r.Context()).Error(err, "response openapi schema validation failure")
	}
}

// ServeHTTP implements the http.Handler interface.
func (v *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, params, err := v.openapi.FindRoute(r)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2ServerError("route lookup failure").WithError(err))

		return
	}

	responseValidationInput, err := v.validateRequest(r, route, params)
	if err != nil {
		// If the authenticator errored, override whatever openapi spits out.
		if v.err != nil {
			err = v.err
		}

		errors.HandleError(w, r, err)

		return
	}

	// Propagate authentication/authorization info to the handlers
	// and the ACL layer to use.
	ctx := r.Context()
	ctx = accesstoken.NewContext(ctx, v.accessToken)
	ctx = userinfo.NewContext(ctx, v.userinfo)

	// This parameter is standardized across all services.
	organizationID := params["organizationID"]

	var acl *identityapi.Acl

	if v.userinfo != nil {
		acl, err = v.authorizer.GetACL(ctx, organizationID, v.userinfo.Subject)
		if err != nil {
			errors.HandleError(w, r, err)

			return
		}

		ctx = rbac.NewContext(ctx, acl)
	}

	req := r.WithContext(ctx)

	// Override the writer so we can inspect the contents and status.
	writer := &bufferingResponseWriter{
		next: w,
	}

	v.next.ServeHTTP(writer, req)

	v.validateResponse(writer, req, responseValidationInput)
}

// Middleware returns a function that generates per-request
// middleware functions.
func Middleware(authorizer Authorizer, openapi *openapi.Schema) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return NewValidator(authorizer, next, openapi)
	}
}
