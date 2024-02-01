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

package oauth2

import (
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/oauth2"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/errors"
	"github.com/unikorn-cloud/identity/pkg/generated"
	"github.com/unikorn-cloud/identity/pkg/jose"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Options struct {
}

// Authenticator provides Keystone authentication functionality.
type Authenticator struct {
	options *Options

	namespace string

	client client.Client

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer
}

// New returns a new authenticator with required fields populated.
// You must call AddFlags after this.
func New(options *Options, namespace string, client client.Client, issuer *jose.JWTIssuer) *Authenticator {
	return &Authenticator{
		options:   options,
		namespace: namespace,
		client:    client,
		issuer:    issuer,
	}
}

type Error string

const (
	ErrorInvalidRequest          Error = "invalid_request"
	ErrorUnauthorizedClient      Error = "unauthorized_client"
	ErrorAccessDenied            Error = "access_denied"
	ErrorUnsupportedResponseType Error = "unsupported_response_type"
	ErrorInvalidScope            Error = "invalid_scope"
	ErrorServerError             Error = "server_error"
)

// State records state across the call to the authorization server.
// This must be encrypted with JWE.
type State struct {
	// Nonce is the one time nonce used to create the token.
	Nonce string `json:"n"`
	// Code verfier is required to prove our identity when
	// exchanging the code with the token endpoint.
	CodeVerfier string `json:"cv"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// ClientID is the client identifier.
	ClientID string `json:"cid"`
	// ClientRedirectURI is the redirect URL requested by the client.
	ClientRedirectURI string `json:"cri"`
	// Client state records the client's OAuth state while we interact
	// with the OIDC authorization server.
	ClientState string `json:"cst,omitempty"`
	// ClientCodeChallenge records the client code challenge so we can
	// authenticate we are handing the authorization token back to the
	// correct client.
	ClientCodeChallenge string `json:"ccc"`
	// ClientScope records the requested client scope.
	ClientScope Scope `json:"csc,omitempty"`
	// ClientNonce is injected into a OIDC id_token.
	ClientNonce string `json:"cno,omitempty"`
}

// Code is an authorization code to return to the client that can be
// exchanged for an access token.  Much like how we client things in the oauth2
// state during the OIDC exchange, to mitigate problems with horizonal scaling
// and sharing stuff, we do the same here.
// WARNING: Don't make this too big, the ingress controller will barf if the
// headers are too hefty.
type Code struct {
	// ClientID is the client identifier.
	ClientID string `json:"cid"`
	// ClientRedirectURI is the redirect URL requested by the client.
	ClientRedirectURI string `json:"cri"`
	// ClientCodeChallenge records the client code challenge so we can
	// authenticate we are handing the authorization token back to the
	// correct client.
	ClientCodeChallenge string `json:"ccc"`
	// ClientScope records the requested client scope.
	ClientScope Scope `json:"csc,omitempty"`
	// ClientNonce is injected into a OIDC id_token.
	ClientNonce string `json:"cno,omitempty"`
	// TODO: we would be a lot more flexible by passing all the claims over...
	// Email is exactly that.
	Email string `json:"email"`
}

var (
	// errorTemplate defines the HTML used to raise an error to the client.
	//go:embed error.tmpl
	errorTemplate string

	// loginTemplate defines the HTML used to acquire an email address from
	// the end user.
	//go:embed login.tmpl
	loginTemplate string
)

// htmlError is used in dire situations when we cannot return an error via
// the usual oauth2 flow.
func htmlError(w http.ResponseWriter, r *http.Request, status int, description string) {
	log := log.FromContext(r.Context())

	w.WriteHeader(status)

	tmpl, err := template.New("error").Parse(errorTemplate)
	if err != nil {
		log.Info("oauth2: failed to parse template", "error", err)
		return
	}

	templateContext := map[string]interface{}{
		"description": description,
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		log.Info("oauth2: failed to render template", "error", err)
		return
	}

	if _, err := w.Write(buffer.Bytes()); err != nil {
		log.Info("oauth2: failed to write HTML response")
	}
}

// authorizationError redirects to the client's callback URI with an error
// code in the query.
func authorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, kind Error, description string) {
	values := &url.Values{}
	values.Set("error", string(kind))
	values.Set("description", description)

	http.Redirect(w, r, redirectURI+"?"+values.Encode(), http.StatusFound)
}

func (a *Authenticator) lookupClient(w http.ResponseWriter, r *http.Request, clientID string) (*unikornv1.OAuth2Client, bool) {
	var clients unikornv1.OAuth2ClientList

	if err := a.client.List(r.Context(), &clients, &client.ListOptions{Namespace: a.namespace}); err != nil {
		htmlError(w, r, http.StatusInternalServerError, err.Error())

		return nil, false
	}

	for i := range clients.Items {
		if clients.Items[i].Spec.ID == clientID {
			return &clients.Items[i], true
		}
	}

	htmlError(w, r, http.StatusBadRequest, "client_id is invalid")

	return nil, false
}

// OAuth2AuthorizationValidateNonRedirecting checks authorization request parameters
// are valid that directly control the ability to redirect, and returns some helpful
// debug in HTML.
func (a *Authenticator) authorizationValidateNonRedirecting(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()

	if !query.Has("client_id") {
		htmlError(w, r, http.StatusBadRequest, "client_id is not specified")

		return false
	}

	if !query.Has("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is not specified")

		return false
	}

	client, ok := a.lookupClient(w, r, query.Get("client_id"))
	if !ok {
		return false
	}

	if client.Spec.RedirectURI != query.Get("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is invalid")

		return false
	}

	return true
}

// OAuth2AuthorizationValidateRedirecting checks autohorization request parameters after
// the redirect URI has been validated.  If any of these fail, we redirect but with an
// error query rather than a code for the client to pick up and run with.
func (a *Authenticator) authorizationValidateRedirecting(w http.ResponseWriter, r *http.Request) bool {
	query := r.URL.Query()

	var kind Error

	var description string

	switch {
	case query.Get("response_type") != "code":
		kind = ErrorUnsupportedResponseType
		description = "response_type must be 'code'"
	case query.Get("code_challenge_method") != "S256":
		kind = ErrorInvalidRequest
		description = "code_challenge_method must be 'S256'"
	case query.Get("code_challenge") == "":
		kind = ErrorInvalidRequest
		description = "code_challenge must be specified"
	default:
		return true
	}

	authorizationError(w, r, query.Get("redirect_uri"), kind, description)

	return false
}

// oidcConfig returns a oauth2 configuration for the OIDC backend.
func (a *Authenticator) oidcConfig(r *http.Request, provider *unikornv1.OAuth2Provider, endpoint oauth2.Endpoint) *oauth2.Config {
	return &oauth2.Config{
		ClientID: provider.Spec.ClientID,
		Endpoint: endpoint,
		// TODO: the ingress converts this all into a relative URL
		// and adds an X-Forwardered-Host, X-Forwarded-Proto.  You should
		// never use HTTP anyway to be fair...
		RedirectURL: "https://" + r.Host + "/oidc/callback",
		Scopes: []string{
			oidc.ScopeOpenID,
			"profile",
			"email",
		},
	}
}

// encodeCodeChallengeS256 performs code verifier to code challenge translation
// for the SHA256 method.
func encodeCodeChallengeS256(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// randomString creates size bytes of high entropy randomness and base64 URL
// encodes it into a string.  Bear in mind base64 expands the size by 33%, so for example
// an oauth2 code verifier needs to be at least 43 bytes, so youd nee'd a size of 32,
// 32 * 1.33 = 42.66.
func randomString(size int) (string, error) {
	buf := make([]byte, size)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Authorization redirects the client to the OIDC autorization endpoint
// to get an authorization code.  Note that this function is responsible for
// either returning an authorization grant or error via a HTTP 302 redirect,
// or returning a HTML fragment for errors that cannot follow the provided
// redirect URI.
func (a *Authenticator) Authorization(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	query := r.URL.Query()

	if !a.authorizationValidateNonRedirecting(w, r) {
		return
	}

	if !a.authorizationValidateRedirecting(w, r) {
		return
	}

	tmpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		log.Info("oauth2: failed to parse template", "error", err)
		return
	}

	templateContext := map[string]interface{}{
		"query": query.Encode(),
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer, templateContext); err != nil {
		log.Info("oauth2: failed to render template", "error", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(buffer.Bytes()); err != nil {
		log.Info("oauth2: failed to write HTML response")
	}
}

func (a *Authenticator) lookupMapping(_ http.ResponseWriter, r *http.Request, email string) (*unikornv1.OAuth2Mapping, error) {
	// TODO: error checking.
	parts := strings.Split(email, "@")

	// TODO: error checking.
	domain := parts[1]

	var mappings unikornv1.OAuth2MappingList

	if err := a.client.List(r.Context(), &mappings, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, err
	}

	for i := range mappings.Items {
		if mappings.Items[i].Spec.Domain == domain {
			return &mappings.Items[i], nil
		}
	}

	// TODO: error type!
	//nolint:goerr113
	return nil, fmt.Errorf("unsupported domain")
}

//nolint:cyclop
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		log.Error(err, "form parse failed")
		return
	}

	if !r.Form.Has("email") {
		log.Info("email doesn't exist in form")
		return
	}

	email := r.Form.Get("email")

	if !r.Form.Has("query") {
		log.Info("query doesn't exist in form")
		return
	}

	query, err := url.ParseQuery(r.Form.Get("query"))
	if err != nil {
		log.Error(err, "failed to parse query")
		return
	}

	mapping, err := a.lookupMapping(w, r, email)
	if err != nil {
		log.Error(err, "failed to list mappings")
		return
	}

	var providerResource unikornv1.OAuth2Provider

	if err := a.client.Get(r.Context(), client.ObjectKey{Namespace: a.namespace, Name: mapping.Spec.ProviderName}, &providerResource); err != nil {
		log.Error(err, "failed to get provider")
		return
	}

	provider, err := oidc.NewProvider(r.Context(), providerResource.Spec.Issuer)
	if err != nil {
		log.Error(err, "failed to do OIDC discovery")
		return
	}

	endpoint := provider.Endpoint()

	clientRedirectURI := query.Get("redirect_uri")

	// OIDC requires a nonce, just some random data base64 URL encoded will suffice.
	nonce, err := randomString(16)
	if err != nil {
		authorizationError(w, r, clientRedirectURI, ErrorServerError, "unable to create oidc nonce: "+err.Error())
		return
	}

	// We pass a hashed code challenge to the OIDC authorization endpoint when
	// requesting an authentication code.  When we exchange that for a token we
	// send the initial code challenge verifier so the token endpoint can validate
	// it's talking to the same client.
	codeVerifier, err := randomString(32)
	if err != nil {
		authorizationError(w, r, clientRedirectURI, ErrorServerError, "unable to create oauth2 code verifier: "+err.Error())
		return
	}

	codeChallenge := encodeCodeChallengeS256(codeVerifier)

	// Rather than cache any state we require after the oauth rediretion dance, which
	// requires persistent state at the minimum, and a database in the case of multi-head
	// deployments, just encrypt it and send with the authoriation request.
	oidcState := &State{
		OAuth2Provider:      providerResource.Name,
		Nonce:               nonce,
		CodeVerfier:         codeVerifier,
		ClientID:            query.Get("client_id"),
		ClientRedirectURI:   query.Get("redirect_uri"),
		ClientState:         query.Get("state"),
		ClientCodeChallenge: query.Get("code_challenge"),
	}

	// To implement OIDC we need a copy of the scopes.
	if query.Has("scope") {
		oidcState.ClientScope = NewScope(query.Get("scope"))
	}

	if query.Has("nonce") {
		oidcState.ClientNonce = query.Get("nonce")
	}

	state, err := a.issuer.EncodeJWEToken(oidcState)
	if err != nil {
		authorizationError(w, r, clientRedirectURI, ErrorServerError, "failed to encode oidc state: "+err.Error())
		return
	}

	// Finally generate the redirection URL and send back to the client.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oidc.Nonce(nonce),
	}

	http.Redirect(w, r, a.oidcConfig(r, &providerResource, endpoint).AuthCodeURL(state, authURLParams...), http.StatusFound)
}

// oidcExtractIDToken wraps up token verification against the JWKS service and conversion
// to a concrete type.
func (a *Authenticator) oidcExtractIDToken(ctx context.Context, provider *oidc.Provider, providerResource *unikornv1.OAuth2Provider, token string) (*oidc.IDToken, error) {
	config := &oidc.Config{
		ClientID: providerResource.Spec.ClientID,
	}

	idTokenVerifier := provider.Verifier(config)

	idToken, err := idTokenVerifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	return idToken, nil
}

// OIDCCallback is called by the authorization endpoint in order to return an
// authorization back to us.  We then exchange the code for an ID token, and
// refresh token.  Remember, as far as the client is concerned we're still doing
// the code grant, so return errors in the redirect query.
//
//nolint:cyclop
func (a *Authenticator) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	query := r.URL.Query()

	// This should always be present, if not then we are boned and cannot
	// send an error back to the redirectURI, cos that's in the state!
	if !query.Has("state") {
		htmlError(w, r, http.StatusBadRequest, "oidc state is required")
		return
	}

	// Extract our state for the next part...
	state := &State{}

	if err := a.issuer.DecodeJWEToken(query.Get("state"), state); err != nil {
		htmlError(w, r, http.StatusBadRequest, "oidc state failed to decode")
		return
	}

	if query.Has("error") {
		authorizationError(w, r, state.ClientRedirectURI, Error(query.Get("error")), query.Get("description"))
		return
	}

	if !query.Has("code") {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc callback does not contain an authorization code")
		return
	}

	var providerResource unikornv1.OAuth2Provider

	if err := a.client.Get(r.Context(), client.ObjectKey{Namespace: a.namespace, Name: state.OAuth2Provider}, &providerResource); err != nil {
		log.Error(err, "failed to get provider")
		return
	}

	provider, err := oidc.NewProvider(r.Context(), providerResource.Spec.Issuer)
	if err != nil {
		log.Error(err, "failed to do OIDC discovery")
		return
	}

	endpoint := provider.Endpoint()

	// Exchange the code for an id_token, access_token and refresh_token with
	// the extracted code verifier.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", state.ClientID),
		oauth2.SetAuthURLParam("client_secret", providerResource.Spec.ClientSecret),
		oauth2.SetAuthURLParam("code_verifier", state.CodeVerfier),
	}

	tokens, err := a.oidcConfig(r, &providerResource, endpoint).Exchange(r.Context(), query.Get("code"), authURLParams...)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc code exchange failed: "+err.Error())
		return
	}

	idTokenRaw, ok := tokens.Extra("id_token").(string)
	if !ok {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc response missing id_token")
		return
	}

	idToken, err := a.oidcExtractIDToken(r.Context(), provider, &providerResource, idTokenRaw)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "id_token verification failed: "+err.Error())
		return
	}

	var claims OIDCClaimsEmail

	if err := idToken.Claims(&claims); err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to extract id_token email claims: "+err.Error())
		return
	}

	// TODO: poll groups here!

	oauth2Code := &Code{
		ClientID:            state.ClientID,
		ClientRedirectURI:   state.ClientRedirectURI,
		ClientCodeChallenge: state.ClientCodeChallenge,
		ClientScope:         state.ClientScope,
		ClientNonce:         state.ClientNonce,
		Email:               claims.Email,
	}

	code, err := a.issuer.EncodeJWEToken(oauth2Code)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to encode authorization code: "+err.Error())
		return
	}

	q := &url.Values{}
	q.Set("code", code)

	if state.ClientState != "" {
		q.Set("state", state.ClientState)
	}

	http.Redirect(w, r, state.ClientRedirectURI+"?"+q.Encode(), http.StatusFound)
}

// tokenValidate does any request validation when issuing a token.
func tokenValidate(r *http.Request) error {
	if r.Form.Get("grant_type") != "authorization_code" {
		return errors.OAuth2UnsupportedGrantType("grant_type must be 'authorization_code'")
	}

	required := []string{
		"client_id",
		"redirect_uri",
		"code",
		"code_verifier",
	}

	for _, parameter := range required {
		if !r.Form.Has(parameter) {
			return errors.OAuth2InvalidRequest(parameter + " must be specified")
		}
	}

	return nil
}

// tokenValidateCode validates the request against the parsed code.
func tokenValidateCode(code *Code, r *http.Request) error {
	if code.ClientID != r.Form.Get("client_id") {
		return errors.OAuth2InvalidGrant("client_id mismatch")
	}

	if code.ClientRedirectURI != r.Form.Get("redirect_uri") {
		return errors.OAuth2InvalidGrant("redirect_uri mismatch")
	}

	if code.ClientCodeChallenge != encodeCodeChallengeS256(r.Form.Get("code_verifier")) {
		return errors.OAuth2InvalidClient("code_verfier invalid")
	}

	return nil
}

// oidcHash is used to create at_hash and c_hash values.
// TODO: this is very much tied to the algorithm defined (hard coded) in
// the JOSE package.
func oidcHash(value string) string {
	sum := sha512.Sum512([]byte(value))

	return base64.RawURLEncoding.EncodeToString(sum[:sha512.Size>>1])
}

// oidcPicture returns a URL to a picture for the user.
func oidcPicture(email string) string {
	//nolint:gosec
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x", md5.Sum([]byte(email)))
}

// oidcIDToken builds an OIDC ID token.
func (a *Authenticator) oidcIDToken(r *http.Request, scope Scope, expiry time.Time, atHash, clientID, email string) (*string, error) {
	//nolint:nilnil
	if !slices.Contains(scope, "openid") {
		return nil, nil
	}

	claims := &IDToken{
		Claims: jwt.Claims{
			Issuer:  "https://" + r.Host,
			Subject: email,
			Audience: []string{
				clientID,
			},
			Expiry:   jwt.NewNumericDate(expiry),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		OIDCClaims: OIDCClaims{
			ATHash: atHash,
		},
	}

	// TODO: we should just pass through the federated id_token in the code...
	if slices.Contains(scope, "email") {
		claims.OIDCClaimsEmail.Email = email
	}

	if slices.Contains(scope, "profile") {
		claims.OIDCClaimsProfile.Picture = oidcPicture(email)
	}

	idToken, err := a.issuer.EncodeJWT(claims)
	if err != nil {
		return nil, err
	}

	return &idToken, nil
}

// Token issues an OAuth2 access token from the provided autorization code.
func (a *Authenticator) Token(w http.ResponseWriter, r *http.Request) (*generated.Token, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse form data: " + err.Error())
	}

	if err := tokenValidate(r); err != nil {
		return nil, err
	}

	code := &Code{}

	if err := a.issuer.DecodeJWEToken(r.Form.Get("code"), code); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse code: " + err.Error())
	}

	if err := tokenValidateCode(code, r); err != nil {
		return nil, err
	}

	expiry := time.Now().Add(24 * time.Hour)

	// TODO: add some scopes, these hould probably be derived from the OIDC mapping.
	accessToken, err := Issue(a.issuer, r, code.ClientID, code.Email, nil, expiry)
	if err != nil {
		return nil, err
	}

	// Handle OIDC.
	idToken, err := a.oidcIDToken(r, code.ClientScope, expiry, oidcHash(accessToken), r.Form.Get("client_id"), code.Email)
	if err != nil {
		return nil, err
	}

	result := &generated.Token{
		TokenType:   "Bearer",
		AccessToken: accessToken,
		IdToken:     idToken,
		ExpiresIn:   int(time.Until(expiry).Seconds()),
	}

	return result, nil
}
