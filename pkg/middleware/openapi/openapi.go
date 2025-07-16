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

package openapi

import (
	"bytes"
	"context"
	"io"
	"net/http"

	"github.com/felixge/httpsnoop"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/identity/pkg/middleware/authorization"
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

	// info is the authorization info containing the token, any claims
	// and other available metadata.
	info *authorization.Info

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

func (v *Validator) validateRequest(r *http.Request, route *routers.Route, params map[string]string) (*openapi3filter.ResponseValidationInput, error) {
	authorizationFunc := func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
		v.info, v.err = v.authorizer.Authorize(input)

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

type responseForValidation struct {
	body   io.ReadCloser
	code   int
	header http.Header
}

func captureResponseForValidation(w http.ResponseWriter, r *http.Request, next http.Handler) *responseForValidation {
	body := &bytes.Buffer{}
	code := 200

	wrapper := httpsnoop.Wrap(w, httpsnoop.Hooks{
		Write: func(next httpsnoop.WriteFunc) httpsnoop.WriteFunc {
			return func(p []byte) (int, error) {
				n, err := next(p)
				body.Write(p[:n]) // this always succeeds, for bytes.Buffer (unless it panics!)

				return n, err
			}
		},
		WriteHeader: func(next httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
			return func(statuscode int) {
				code = statuscode
				next(statuscode)
			}
		},
		ReadFrom: func(next httpsnoop.ReadFromFunc) httpsnoop.ReadFromFunc {
			return func(src io.Reader) (int64, error) {
				tee := io.TeeReader(src, body)
				return next(tee)
			}
		},
	})

	next.ServeHTTP(wrapper, r)

	return &responseForValidation{
		code:   code,
		body:   io.NopCloser(body),
		header: w.Header(),
	}
}

func (v *Validator) validateResponse(res *responseForValidation, r *http.Request, responseValidationInput *openapi3filter.ResponseValidationInput) {
	responseValidationInput.Status = res.code
	responseValidationInput.Header = res.header
	responseValidationInput.Body = res.body

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

	// Propagate the client certificate now so it's available in the request validation
	// in case its required for a bound access token.
	ctx, err := authorization.ExtractClientCert(r.Context(), r.Header)
	if err != nil {
		errors.HandleError(w, r, errors.OAuth2InvalidRequest("certificate propagation failure").WithError(err))

		return
	}

	// Make a shallow copy of the request with the new context.  OpenAPI validation
	// will read the body, and replace it with a new buffer, so be sure to use this
	// version from here on.
	r = r.WithContext(ctx)

	responseValidationInput, err := v.validateRequest(r, route, params)
	if err != nil {
		// If the authenticator errored, override whatever openapi spits out.
		if v.err != nil {
			err = v.err
		}

		errors.HandleError(w, r, err)

		return
	}

	// If any authentication was requested as part of the route, then update anything
	// that needs doing.
	if v.info != nil {
		// Propagate authentication/authorization info to the handlers
		// and the ACL layer to use.
		ctx = authorization.NewContext(ctx, v.info)

		// The organizationID parameter is standardized across all services.
		// NOTE: this can legitimately be undefined, but the ACL code will handle
		// that and only look for globally scoped roles.
		acl, err := v.authorizer.GetACL(ctx, params["organizationID"])
		if err != nil {
			errors.HandleError(w, r, err)
			return
		}

		ctx = rbac.NewContext(ctx, acl)
	}

	r = r.WithContext(ctx)

	response := captureResponseForValidation(w, r, v.next)
	v.validateResponse(response, r, responseValidationInput)
}

// Middleware returns a function that generates per-request
// middleware functions.
func Middleware(authorizer Authorizer, openapi *openapi.Schema) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return NewValidator(authorizer, next, openapi)
	}
}
