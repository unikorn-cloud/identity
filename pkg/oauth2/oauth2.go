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

package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	goerrors "errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/spf13/pflag"

	"github.com/unikorn-cloud/core/pkg/server/errors"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/html"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2/oidc"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers"
	"github.com/unikorn-cloud/identity/pkg/oauth2/types"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"

	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/utils/ptr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	SessionCookie = "unikorn-identity-session"
)

var (
	ErrUnsupportedProviderType = goerrors.New("unhandled provider type")
	ErrReference               = goerrors.New("resource reference error")
	ErrUserNotDomainMapped     = goerrors.New("user is not domain mapped to an organization")
)

type Options struct {
	// AccessTokenDuration should be short to prevent long term use.
	AccessTokenDuration time.Duration

	// RefreshTokenDuration should be driven by the signing key rotation
	// period.
	RefreshTokenDuration time.Duration

	// TokenVerificationLeeway tells us how permissive we should or shouldn't
	// be of timing.
	TokenVerificationLeeway time.Duration

	// TokenLeewayDuration allows us to remove a period from the IdP access token
	// lifetime so we can "guarantee" ours will expire before theirs and force
	// a refresh before any errors can come from the IdP.
	TokenLeewayDuration time.Duration

	// TokenCacheSize is used to control the size of the LRU cache for token validation
	// checks.  This bounds the memory use to prevent DoS attacks.
	TokenCacheSize int

	// CodeCacheSize is used to set the number of authorization code in flight.
	CodeCacheSize int

	// Bool to indicate whether sign up is allowed.
	AuthenticateUnknownUsers bool
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.AccessTokenDuration, "access-token-duration", time.Hour, "Maximum time an access token can be active for.")
	f.DurationVar(&o.RefreshTokenDuration, "refresh-token-duration", 0, "Maximum time a refresh token can be active for.")
	f.DurationVar(&o.TokenVerificationLeeway, "token-verification-leeway", 0, "How mush leeway to permit for verification of token validity.")
	f.DurationVar(&o.TokenLeewayDuration, "token-leeway", time.Minute, "How long to remove from the provider token expiry to account for network and processing latency.")
	f.IntVar(&o.TokenCacheSize, "token-cache-size", 8192, "How many token cache entries to allow.")
	f.IntVar(&o.CodeCacheSize, "code-cache-size", 8192, "How many code cache entries to allow.")
	f.BoolVar(&o.AuthenticateUnknownUsers, "authenticate-unknown-users", false, "Authenticate unknown users, allow new user organizations to be created.")
}

// Authenticator provides Keystone authentication functionality.
type Authenticator struct {
	options *Options

	namespace string

	client client.Client

	// issuer allows creation and validation of JWT bearer tokens.
	issuer *jose.JWTIssuer

	rbac *rbac.RBAC

	// tokenCache is used to enhance interaction as the validation is a
	// very expensive operation.
	tokenCache *cache.LRUExpireCache

	// codeCache is used to protect against authorization code reuse.
	codeCache *cache.LRUExpireCache
}

// New returns a new authenticator with required fields populated.
// You must call AddFlags after this.
func New(options *Options, namespace string, client client.Client, issuer *jose.JWTIssuer, rbac *rbac.RBAC) *Authenticator {
	return &Authenticator{
		options:    options,
		namespace:  namespace,
		client:     client,
		issuer:     issuer,
		rbac:       rbac,
		tokenCache: cache.NewLRUExpireCache(options.TokenCacheSize),
		codeCache:  cache.NewLRUExpireCache(options.CodeCacheSize),
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
	ErrorLoginRequired           Error = "login_required"
	ErrorRequestNotSupported     Error = "request_not_supported"
	ErrorInteractionRequired     Error = "interaction_required"
)

// State records state across the call to the authorization server.
// This must be encrypted with JWE.
type State struct {
	// Nonce is the one time nonce used to create the token.
	Nonce string `json:"n"`
	// Code verfier is required to prove our identity when
	// exchanging the code with the token endpoint.
	CodeVerifier string `json:"cv"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// ClientQuery stores the full client query string.
	ClientQuery string `json:"cq"`
}

// Code is an authorization code to return to the client that can be
// exchanged for an access token.  Much like how we client things in the oauth2
// state during the OIDC exchange, to mitigate problems with horizonal scaling
// and sharing stuff, we do the same here.
type Code struct {
	// ID is a unique identifier for the code.
	ID string `json:"id"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
	// UserID is the user that issued the code.
	UserID string `json:"uid"`
	// ClientQuery stores the full client query string.
	ClientQuery string `json:"cq"`
	// IDToken is the full set of claims returned by the provider.
	IDToken *oidc.IDToken `json:"idt"`
	// Interactive declares whether this is an interactive login
	// or not (e.g. cookie based).
	Interactive bool `json:"int"`
}

// htmlError is used in dire situations when we cannot return an error via
// the usual oauth2 flow.
//
//nolint:unparam
func htmlError(w http.ResponseWriter, r *http.Request, status int, description string) {
	log := log.FromContext(r.Context())

	body, err := html.Error("oauth2 error", description)
	if err != nil {
		log.Info("oauth2: failed to generate error page", "error", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)

	if _, err := w.Write(body); err != nil {
		log.Info("oauth2: failed to write HTML response")
	}
}

// redirector wraps up error redirects.
type redirector struct {
	w           http.ResponseWriter
	r           *http.Request
	redirectURI string
	state       string
}

func newRedirector(w http.ResponseWriter, r *http.Request, redirectURI, state string) *redirector {
	return &redirector{
		w:           w,
		r:           r,
		redirectURI: redirectURI,
		state:       state,
	}
}

func (e *redirector) redirect(values url.Values) {
	http.Redirect(e.w, e.r, e.redirectURI+"?"+values.Encode(), http.StatusFound)
}

// raise redirects to the client's callback URI with an error
// code in the query.
func (e *redirector) raise(kind Error, description string) {
	values := url.Values{}
	values.Set("error", string(kind))
	values.Set("error_description", description)

	if e.state != "" {
		values.Set("state", e.state)
	}

	e.redirect(values)
}

// lookupClient returns the oauth2 client given its ID.
func (a *Authenticator) lookupClient(ctx context.Context, id string) (*unikornv1.OAuth2Client, error) {
	cli := &unikornv1.OAuth2Client{}

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: id}, cli); err != nil {
		return nil, err
	}

	return cli, nil
}

// lookupOrganization maps from an email address to an organization, this handles
// corporate mandates that say your entire domain have to use a single sign on
// provider across the entire enterprise.
func (a *Authenticator) lookupOrganization(ctx context.Context, email string) (*unikornv1.Organization, error) {
	// TODO: error checking.
	parts := strings.Split(email, "@")

	// TODO: error checking.
	domain := parts[1]

	var organizations unikornv1.OrganizationList

	if err := a.client.List(ctx, &organizations, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, err
	}

	for i := range organizations.Items {
		if organizations.Items[i].Spec.Domain == nil {
			continue
		}

		if *organizations.Items[i].Spec.Domain == domain {
			return &organizations.Items[i], nil
		}
	}

	return nil, ErrUserNotDomainMapped
}

// getProviders lists all identity providers.
func (a *Authenticator) getProviders(ctx context.Context) (*unikornv1.OAuth2ProviderList, error) {
	resources := &unikornv1.OAuth2ProviderList{}

	if err := a.client.List(ctx, resources, &client.ListOptions{Namespace: a.namespace}); err != nil {
		return nil, err
	}

	return resources, nil
}

func (a *Authenticator) getProviderTypes(ctx context.Context) ([]string, error) {
	resources, err := a.getProviders(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(resources.Items))

	for _, resource := range resources.Items {
		if resource.Spec.Type != nil && *resource.Spec.Type != "" {
			result = append(result, string(*resource.Spec.Type))
		}
	}

	return result, nil
}

// lookupProviderByType finds the provider configuration by the type chosen by the user.
func (a *Authenticator) lookupProviderByType(ctx context.Context, t unikornv1.IdentityProviderType) (*unikornv1.OAuth2Provider, error) {
	resources, err := a.getProviders(ctx)
	if err != nil {
		return nil, err
	}

	for i := range resources.Items {
		if resources.Items[i].Spec.Type != nil && *resources.Items[i].Spec.Type == t {
			return &resources.Items[i], nil
		}
	}

	return nil, ErrUnsupportedProviderType
}

// lookupProviderByID finds the provider based on ID.
func (a *Authenticator) lookupProviderByID(ctx context.Context, id string, organization *unikornv1.Organization) (*unikornv1.OAuth2Provider, error) {
	providers := &unikornv1.OAuth2ProviderList{}

	if err := a.client.List(ctx, providers); err != nil {
		return nil, err
	}

	find := func(provider unikornv1.OAuth2Provider) bool {
		return provider.Name == id
	}

	index := slices.IndexFunc(providers.Items, find)
	if index < 0 {
		return nil, fmt.Errorf("%w: requested provider does not exist", ErrReference)
	}

	provider := &providers.Items[index]

	// If the provider is neither global, nor scoped to the provided organization, reject.
	// NOTE: when called by the authorization endpoint and an email is provided, that email
	// maps to an organization, and the provider must be in that organization to avoid
	// jailbreaking.  In later provider authorization and token exchanges we can trust the
	// ID as it's already been checked and it has been cryptographically protected against
	// tamering.
	if provider.Namespace != a.namespace && (organization == nil || provider.Namespace != organization.Status.Namespace) {
		return nil, fmt.Errorf("%w: requested provider not allowed", ErrReference)
	}

	return provider, nil
}

// OAuth2AuthorizationValidateNonRedirecting checks authorization request parameters
// are valid that directly control the ability to redirect, and returns some helpful
// debug in HTML.
func (a *Authenticator) authorizationValidateNonRedirecting(w http.ResponseWriter, r *http.Request, query url.Values) (*unikornv1.OAuth2Client, bool) {
	if !query.Has("client_id") {
		htmlError(w, r, http.StatusBadRequest, "client_id is not specified")

		return nil, false
	}

	if !query.Has("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is not specified")

		return nil, false
	}

	client, err := a.lookupClient(r.Context(), query.Get("client_id"))
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "client_id does not exist")

		return nil, false
	}

	if client.Spec.RedirectURI != query.Get("redirect_uri") {
		htmlError(w, r, http.StatusBadRequest, "redirect_uri is invalid")

		return nil, false
	}

	return client, true
}

// getCodeChallengeMethod handles defaulting when a code challenge is provided.
func getCodeChallengeMethod(query url.Values) openapi.CodeChallengeMethod {
	if query.Has("code_challenge_method") {
		return openapi.CodeChallengeMethod(query.Get("code_challenge_method"))
	}

	return openapi.Plain
}

var (
	//nolint:gochecknoglobals
	allowedResponseTypes = []string{
		string(openapi.ResponseTypeCode),
	}

	//nolint:gochecknoglobals
	allowedResponseModes = []string{
		string(openapi.Query),
	}

	//nolint:gochecknoglobals
	allowedCodeChallengeMethods = []string{
		string(openapi.Plain),
		string(openapi.S256),
	}
)

// authorizationValidateRedirecting checks autohorization request parameters after
// the redirect URI has been validated.  If any of these fail, we redirect but with an
// error query rather than a code for the client to pick up and run with.
func authorizationValidateRedirecting(redirector *redirector, query url.Values) bool {
	if query.Has("request") {
		redirector.raise(ErrorRequestNotSupported, "request object by value not supported")
		return false
	}

	if !slices.Contains(allowedResponseTypes, query.Get("response_type")) {
		redirector.raise(ErrorUnsupportedResponseType, "response_type must be one of "+strings.Join(allowedResponseTypes, ", "))
		return false
	}

	if query.Has("response_mode") && !slices.Contains(allowedResponseModes, query.Get("response_mode")) {
		redirector.raise(ErrorRequestNotSupported, "response_mode must be one of "+strings.Join(allowedResponseModes, ", "))
		return false
	}

	if !slices.Contains(allowedCodeChallengeMethods, string(getCodeChallengeMethod(query))) {
		redirector.raise(ErrorInvalidRequest, "code_challenge_method must be one of "+strings.Join(allowedCodeChallengeMethods, ", "))
		return false
	}

	return true
}

// encodeCodeChallengeS256 performs code verifier to code challenge translation
// for the SHA256 method.
func encodeCodeChallengeS256(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// randomString creates size bytes of high entropy randomness and base64 URL
// encodes it into a string.  Bear in mind base64 expands the size by 33%, so for example
// an oauth2 code verifier needs to be at least 43 bytes, so you'd need a size of 32,
// 32 * 1.33 = 42.66.
func randomString(size int) (string, error) {
	buf := make([]byte, size)

	if _, err := rand.Read(buf); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// LoginStateClaims are used to encrypt information across the login dialog.
type LoginStateClaims struct {
	Query string `json:"query"`
}

func (a *Authenticator) getUser(ctx context.Context, id string) (*unikornv1.User, error) {
	user := &unikornv1.User{}

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: id}, user); err != nil {
		return nil, err
	}

	return user, nil
}

//nolint:cyclop
func (a *Authenticator) authorizationSilent(r *http.Request, redirector *redirector, query url.Values) bool {
	if !query.Has("max_age") && query.Get("prompt") != "none" {
		return false
	}

	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		return false
	}

	code := &Code{}

	if err := a.issuer.DecodeJWEToken(r.Context(), cookie.Value, code, jose.TokenTypeAuthorizationCode); err != nil {
		return false
	}

	clientQuery, err := url.ParseQuery(code.ClientQuery)
	if err != nil {
		return false
	}

	if clientQuery.Get("client_id") != query.Get("client_id") {
		return false
	}

	if clientQuery.Get("redirect_uri") != query.Get("redirect_uri") {
		return false
	}

	user, err := a.getUser(r.Context(), code.UserID)
	if err != nil {
		return false
	}

	session, err := user.Session(query.Get("client_id"))
	if err != nil {
		return false
	}

	if query.Has("max_age") {
		maxAge, err := strconv.Atoi(query.Get("max_age"))
		if err != nil {
			return false
		}

		if maxAge == 0 {
			return false
		}

		if session.LastAuthentication == nil {
			return false
		}

		if session.LastAuthentication.Add(time.Duration(maxAge) * time.Second).Before(time.Now()) {
			return false
		}
	}

	// Skip the nonsense!
	oauth2Code := &Code{
		ID:             uuid.New().String(),
		UserID:         user.Name,
		ClientQuery:    query.Encode(),
		OAuth2Provider: code.OAuth2Provider,
		IDToken:        code.IDToken,
	}

	newCode, err := a.issuer.EncodeJWEToken(r.Context(), oauth2Code, jose.TokenTypeAuthorizationCode)
	if err != nil {
		return false
	}

	q := url.Values{}
	q.Set("code", newCode)

	if query.Has("state") {
		q.Set("state", query.Get("state"))
	}

	a.codeCache.Add(newCode, nil, time.Minute)

	redirector.redirect(q)

	return true
}

func getAuthorizationQuery(r *http.Request) (url.Values, error) {
	if r.Method == http.MethodGet {
		return r.URL.Query(), nil
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return r.Form, nil
}

// Authorization redirects the client to the OIDC autorization endpoint
// to get an authorization code.  Note that this function is responsible for
// either returning an authorization grant or error via a HTTP 302 redirect,
// or returning a HTML fragment for errors that cannot follow the provided
// redirect URI.
//
//nolint:cyclop
func (a *Authenticator) Authorization(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	// Extract the client supplied parameters.
	query, err := getAuthorizationQuery(r)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "failed to get authorization query")
	}

	// Get the client corresponding to the request, if this errors then we cannot
	// trust the redirect URI and must render an error page.
	client, ok := a.authorizationValidateNonRedirecting(w, r, query)
	if !ok {
		return
	}

	redirector := newRedirector(w, r, client.Spec.RedirectURI, query.Get("state"))

	// Validate the other request parameters based on what we support, on error this
	// returns control back to the client via the redirect.
	if !authorizationValidateRedirecting(redirector, query) {
		return
	}

	// If 'max_age' is set and not zero, or 'prompt=none', then we may be able to silently
	// authenticate the user with a browser cookie, instantly returning an authorization
	// code to the client.
	if a.authorizationSilent(r, redirector, query) {
		return
	}

	// If that wasn't able to be handled and prompt=none, then we need to return an
	// interaction_required error.
	if query.Get("prompt") == "none" {
		redirector.raise(ErrorInteractionRequired, "login required but no prompt requested")
		return
	}

	// Encrypt the query across the login dialog to prevent tampering.
	stateClaims := &LoginStateClaims{
		Query: query.Encode(),
	}

	state, err := a.issuer.EncodeJWEToken(r.Context(), stateClaims, jose.TokenTypeLoginDialogState)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to encode request state")
		return
	}

	supportedTypes, err := a.getProviderTypes(r.Context())
	if err != nil {
		redirector.raise(ErrorServerError, "failed to get oauth2 providers")
		return
	}

	loginQuery := url.Values{}

	loginQuery.Set("state", state)
	loginQuery.Set("callback", "https://"+r.Host+"/oauth2/v2/login")
	loginQuery.Set("providers", strings.Join(supportedTypes, " "))

	// Redirect to an external login handler, if you have chosen to.
	if client.Spec.LoginURI != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?%s", *client.Spec.LoginURI, loginQuery.Encode()), http.StatusFound)
		return
	}

	// Otherwise use the internal version.
	body, err := html.Login(loginQuery.Encode())
	if err != nil {
		redirector.raise(ErrorServerError, "failed to render login template")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body); err != nil {
		log.Info("oauth2: failed to write HTML response")
		return
	}
}

// Login handles the response from the user login prompt.
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		htmlError(w, r, http.StatusBadRequest, "form parse failure")
		return
	}

	if !r.Form.Has("state") {
		htmlError(w, r, http.StatusBadRequest, "state field missing")
		return
	}

	state := &LoginStateClaims{}

	if err := a.issuer.DecodeJWEToken(r.Context(), r.Form.Get("state"), state, jose.TokenTypeLoginDialogState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "login state failed to decode")
		return
	}

	query, err := url.ParseQuery(state.Query)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "failed to parse query")
		return
	}

	redirector := newRedirector(w, r, query.Get("redirect_uri"), query.Get("state"))

	// Handle the case where the provider is explicitly specified.
	if providerType := r.Form.Get("provider"); providerType != "" {
		provider, err := a.lookupProviderByType(r.Context(), unikornv1.IdentityProviderType(providerType))
		if err != nil {
			redirector.raise(ErrorServerError, err.Error())
			return
		}

		a.providerAuthenticationRequest(w, r, redirector, provider, query, "")

		return
	}

	// Otherwise we need to infer the provider.
	email := r.Form.Get("email")
	if email == "" {
		redirector.raise(ErrorServerError, "email query parameter not specified")
		return
	}

	organization, err := a.lookupOrganization(r.Context(), email)
	if err != nil {
		redirector.raise(ErrorServerError, err.Error())
		return
	}

	provider, err := a.lookupProviderByID(r.Context(), *organization.Spec.ProviderID, organization)
	if err != nil {
		redirector.raise(ErrorServerError, err.Error())
		return
	}

	a.providerAuthenticationRequest(w, r, redirector, provider, query, email)
}

// providerAuthenticationRequest kicks off the authorization flow with the backend
// provider.
func (a *Authenticator) providerAuthenticationRequest(w http.ResponseWriter, r *http.Request, redirector *redirector, provider *unikornv1.OAuth2Provider, query url.Values, email string) {
	// Try infer the email address if one was not specified.
	if email == "" && query.Has("login_hint") {
		email = query.Get("login_hint")
	}

	// OIDC requires a nonce, just some random data base64 URL encoded will suffice.
	nonce, err := randomString(16)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oidc nonce: "+err.Error())
		return
	}

	// We pass a hashed code challenge to the OIDC authorization endpoint when
	// requesting an authentication code.  When we exchange that for a token we
	// send the initial code challenge verifier so the token endpoint can validate
	// it's talking to the same client.
	codeVerifier, err := randomString(32)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oauth2 code verifier: "+err.Error())
		return
	}

	// Rather than cache any state we require after the oauth rediretion dance, which
	// requires persistent state at the minimum, and a database in the case of multi-head
	// deployments, just encrypt it and send with the authoriation request.
	oidcState := &State{
		OAuth2Provider: provider.Name,
		Nonce:          nonce,
		CodeVerifier:   codeVerifier,
		ClientQuery:    query.Encode(),
	}

	state, err := a.issuer.EncodeJWEToken(r.Context(), oidcState, jose.TokenTypeLoginState)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to encode oidc state: "+err.Error())
		return
	}

	driver := providers.New(provider.Spec.Type)

	configParameters := &types.ConfigParameters{
		Host:     r.Host,
		Provider: provider,
	}

	config, err := driver.Config(r.Context(), configParameters)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oauth2 config: "+err.Error())
		return
	}

	parameters := &types.AuthorizationParamters{
		Nonce:         nonce,
		State:         state,
		CodeChallenge: encodeCodeChallengeS256(codeVerifier),
		Email:         email,
		Query:         query,
	}

	url, err := driver.AuthorizationURL(config, parameters)
	if err != nil {
		redirector.raise(ErrorServerError, "unable to create oauth2 redirect: "+err.Error())
		return
	}

	http.Redirect(w, r, url, http.StatusFound)
}

// OIDCCallback is called by the authorization endpoint in order to return an
// authorization back to us.  We then exchange the code for an ID token, and
// refresh token.  Remember, as far as the client is concerned we're still doing
// the code grant, so return errors in the redirect query.
//
//nolint:cyclop
func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// This should always be present, if not then we are boned and cannot
	// send an error back to the redirectURI, cos that's in the state!
	if !query.Has("state") {
		htmlError(w, r, http.StatusBadRequest, "oidc state is required")
		return
	}

	// Extract our state for the next part...
	state := &State{}

	if err := a.issuer.DecodeJWEToken(r.Context(), query.Get("state"), state, jose.TokenTypeLoginState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "oidc state failed to decode")
		return
	}

	clientQuery, err := url.ParseQuery(state.ClientQuery)
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "client query failed to decode")
		return
	}

	redirector := newRedirector(w, r, clientQuery.Get("redirect_uri"), clientQuery.Get("state"))

	if query.Has("error") {
		redirector.raise(Error(query.Get("error")), query.Get("error_description"))
		return
	}

	if !query.Has("code") {
		redirector.raise(ErrorServerError, "oidc callback does not contain an authorization code")
		return
	}

	provider, err := a.lookupProviderByID(r.Context(), state.OAuth2Provider, nil)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to get oauth2 provider")
		return
	}

	parameters := &types.CodeExchangeParameters{
		ConfigParameters: types.ConfigParameters{
			Host:     r.Host,
			Provider: provider,
		},
		Code:         query.Get("code"),
		CodeVerifier: state.CodeVerifier,
	}

	_, idToken, err := providers.New(provider.Spec.Type).CodeExchange(r.Context(), parameters)
	if err != nil {
		redirector.raise(ErrorServerError, "code exchange failed: "+err.Error())
		return
	}

	q := url.Values{}

	if clientQuery.Has("state") {
		q.Set("state", clientQuery.Get("state"))
	}

	user, err := a.rbac.GetActiveUser(r.Context(), idToken.Email.Email)
	if err != nil && !a.options.AuthenticateUnknownUsers {
		redirector.raise(ErrorAccessDenied, "user does not exist or is inactive")
		return
	}

	oauth2Code := &Code{
		ID:             uuid.New().String(),
		UserID:         user.Name,
		ClientQuery:    state.ClientQuery,
		OAuth2Provider: state.OAuth2Provider,
		Interactive:    true,
		IDToken:        idToken,
	}

	code, err := a.issuer.EncodeJWEToken(r.Context(), oauth2Code, jose.TokenTypeAuthorizationCode)
	if err != nil {
		redirector.raise(ErrorServerError, "failed to encode authorization code: "+err.Error())
		return
	}

	q.Set("code", code)

	a.codeCache.Add(code, nil, time.Minute)

	// OIDC support silent re-authentication, the expectation is that the user will
	// be able to reauthenticate for a period without a login prompt, up to the max_age
	// specified in the authentication request.  To trust the user we store away a cookie
	// we can use to establish trust, bind the to the client ID etc etc.
	cookie := &http.Cookie{
		Name:     SessionCookie,
		Path:     "/",
		Domain:   r.Host,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	cookie.Value = code

	w.Header().Add("Set-Cookie", cookie.String())

	redirector.redirect(q)
}

// tokenValidate does any request validation when issuing a token.
func tokenValidate(r *http.Request) error {
	if r.Form.Get("grant_type") != "authorization_code" {
		return errors.OAuth2UnsupportedGrantType("grant_type must be 'authorization_code'")
	}

	required := []string{
		"redirect_uri",
		"code",
	}

	for _, parameter := range required {
		if !r.Form.Has(parameter) {
			return errors.OAuth2InvalidRequest(parameter + " must be specified")
		}
	}

	return nil
}

// tokenValidateCode validates the request against the parsed code.
func tokenValidateCode(r *http.Request, query url.Values) error {
	if query.Get("redirect_uri") != r.Form.Get("redirect_uri") {
		return errors.OAuth2InvalidGrant("redirect_uri mismatch")
	}

	// PKCE is optional, but highly recommended!
	if query.Has("code_challenge") {
		switch getCodeChallengeMethod(query) {
		case openapi.Plain:
			if query.Get("code_challenge") != r.Form.Get("code_verifier") {
				return errors.OAuth2InvalidClient("code_verfier invalid")
			}
		case openapi.S256:
			if query.Get("code_challenge") != encodeCodeChallengeS256(r.Form.Get("code_verifier")) {
				return errors.OAuth2InvalidClient("code_verfier invalid")
			}
		}
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

// oidcIDToken builds an OIDC ID token.
func (a *Authenticator) oidcIDToken(r *http.Request, idToken *oidc.IDToken, query url.Values, expiry time.Duration, atHash string, lastAuthenticationTime time.Time) (*string, error) {
	scope := strings.Split(query.Get("scope"), " ")

	//nolint:nilnil
	if !slices.Contains(scope, "openid") {
		return nil, nil
	}

	claims := &oidc.IDToken{
		Claims: jwt.Claims{
			Issuer: "https://" + r.Host,
			// TODO: we should use the user ID.
			Subject: idToken.Email.Email,
			Audience: []string{
				query.Get("client_id"),
			},
			Expiry:   jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Default: oidc.Default{
			Nonce:           query.Get("nonce"),
			AuthTime:        ptr.To(lastAuthenticationTime.Unix()),
			AuthorizedParty: query.Get("client_id"),
		},
	}

	if atHash != "" {
		claims.Default.ATHash = atHash
	}

	// NOTE: the scope here is intended to defined what happens when you call the
	// userinfo endpoint (and probably the "code id_token" grant type), but Google
	// etc. all do this, so why not...
	if slices.Contains(scope, "email") {
		claims.Email = idToken.Email
	}

	if slices.Contains(scope, "profile") {
		claims.Profile = idToken.Profile
	}

	token, err := a.issuer.EncodeJWT(r.Context(), claims)
	if err != nil {
		return nil, err
	}

	return &token, nil
}

func (a *Authenticator) validateClientSecret(r *http.Request, query url.Values) error {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		if !r.Form.Has("client_id") || !r.Form.Has("client_secret") {
			return errors.OAuth2ServerError("client ID secret not set in request body")
		}

		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if query.Get("client_id") != clientID {
		return errors.OAuth2InvalidGrant("client_id mismatch")
	}

	client, err := a.lookupClient(r.Context(), query.Get("client_id"))
	if err != nil {
		return errors.OAuth2ServerError("failed to lookup client").WithError(err)
	}

	if client.Status.Secret == "" {
		return errors.OAuth2ServerError("client secret not set")
	}

	if client.Status.Secret != clientSecret {
		return errors.OAuth2InvalidRequest("client secret invalid")
	}

	return nil
}

// revokeSession revokes all tokens for a clientID.
func (a *Authenticator) revokeSession(ctx context.Context, clientID, codeID, subject string) error {
	user, err := a.rbac.GetActiveUser(ctx, subject)
	if err != nil {
		return errors.OAuth2ServerError("failed to lookup user").WithError(err)
	}

	lookupSession := func(session unikornv1.UserSession) bool {
		return session.ClientID == clientID && session.AuthorizationCodeID == codeID
	}

	index := slices.IndexFunc(user.Spec.Sessions, lookupSession)
	if index < 0 {
		return nil
	}

	// Things can still go wrong between here and issuing the new token, so invalidate
	// the session now rather than relying on the reissue doing it for us.
	a.InvalidateToken(ctx, user.Spec.Sessions[index].AccessToken)

	user.Spec.Sessions = append(user.Spec.Sessions[:index], user.Spec.Sessions[index+1:]...)

	if err := a.client.Update(ctx, user); err != nil {
		return errors.OAuth2ServerError("failed to revoke user session").WithError(err)
	}

	return nil
}

// TokenAuthorizationCode issues a token based on whether the provided code is correct and
// the client code verifier (PKCS) matches.
func (a *Authenticator) TokenAuthorizationCode(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	if err := tokenValidate(r); err != nil {
		return nil, err
	}

	codeRaw := r.Form.Get("code")

	code := &Code{}

	if err := a.issuer.DecodeJWEToken(r.Context(), codeRaw, code, jose.TokenTypeAuthorizationCode); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse code: " + err.Error())
	}

	clientQuery, err := url.ParseQuery(code.ClientQuery)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse client query").WithError(err)
	}

	clientID := clientQuery.Get("client_id")

	if err := tokenValidateCode(r, clientQuery); err != nil {
		return nil, err
	}

	if err := a.validateClientSecret(r, clientQuery); err != nil {
		return nil, err
	}

	// RFC 6749 4.1.2 - code reuse should revoke any tokens associated with the
	// authentication code, we just clear out anything associated with the client
	// session.
	if _, ok := a.codeCache.Get(codeRaw); !ok {
		_ = a.revokeSession(r.Context(), clientID, code.ID, code.IDToken.Email.Email)

		return nil, errors.OAuth2InvalidGrant("code is not present in cache")
	}

	a.codeCache.Remove(codeRaw)

	info := &IssueInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		// TODO: we should probably use the user ID here.
		Subject:  code.IDToken.Email.Email,
		ClientID: clientID,
		Federated: &Federated{
			UserID:   code.UserID,
			Provider: code.OAuth2Provider,
		},
		Scope:               NewScope(clientQuery.Get("scope")),
		AuthorizationCodeID: &code.ID,
		Interactive:         code.Interactive,
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		return nil, err
	}

	// Handle OIDC.
	idToken, err := a.oidcIDToken(r, code.IDToken, clientQuery, a.options.AccessTokenDuration, oidcHash(tokens.AccessToken), tokens.LastAuthenticationTime)
	if err != nil {
		return nil, err
	}

	result := &openapi.Token{
		TokenType:    "Bearer",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IdToken:      idToken,
		ExpiresIn:    int(time.Until(tokens.Expiry).Seconds()),
	}

	return result, nil
}

func (a *Authenticator) validateClientSecretRefresh(r *http.Request, claims *RefreshTokenClaims) error {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		if !r.Form.Has("client_id") || !r.Form.Has("client_secret") {
			return errors.OAuth2ServerError("client ID secret not set in request body")
		}

		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if claims.Custom.ClientID != clientID {
		return errors.OAuth2InvalidGrant("client_id mismatch")
	}

	client, err := a.lookupClient(r.Context(), claims.Custom.ClientID)
	if err != nil {
		return errors.OAuth2ServerError("failed to lookup client").WithError(err)
	}

	if client.Status.Secret == "" {
		return errors.OAuth2ServerError("client secret not set")
	}

	if client.Status.Secret != clientSecret {
		return errors.OAuth2InvalidRequest("client secret invalid")
	}

	return nil
}

// validateRefreshToken checks the refresh token ID is still valid (unused) and clears it
// from the user record.
func (a *Authenticator) validateRefreshToken(ctx context.Context, r *http.Request, refreshToken string, claims *RefreshTokenClaims) error {
	if err := a.validateClientSecretRefresh(r, claims); err != nil {
		return err
	}

	user, err := a.rbac.GetActiveUser(ctx, claims.Claims.Subject)
	if err != nil {
		return errors.OAuth2ServerError("failed to lookup user").WithError(err)
	}

	lookupSession := func(session unikornv1.UserSession) bool {
		return session.ClientID == claims.Custom.ClientID
	}

	index := slices.IndexFunc(user.Spec.Sessions, lookupSession)
	if index < 0 {
		return errors.OAuth2InvalidGrant("no active session for user found")
	}

	if user.Spec.Sessions[index].RefreshToken != refreshToken {
		return errors.OAuth2InvalidGrant("refresh token reuse")
	}

	// Things can still go wrong between here and issuing the new token, so invalidate
	// the session now rather than relying on the reissue doing it for us.
	a.InvalidateToken(ctx, user.Spec.Sessions[index].AccessToken)

	user.Spec.Sessions[index].RefreshToken = ""

	if err := a.client.Update(ctx, user); err != nil {
		return errors.OAuth2ServerError("failed to revoke user session").WithError(err)
	}

	return nil
}

// TokenRefreshToken issues a token if the provided refresh token is valid.
func (a *Authenticator) TokenRefreshToken(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	refreshTokenRaw := r.Form.Get("refresh_token")

	// Validate the refresh token and extract the claims.
	claims := &RefreshTokenClaims{}

	if err := a.issuer.DecodeJWEToken(r.Context(), refreshTokenRaw, claims, jose.TokenTypeRefreshToken); err != nil {
		return nil, errors.OAuth2InvalidGrant("refresh token is invalid or has expired").WithError(err)
	}

	if err := a.validateRefreshToken(r.Context(), r, refreshTokenRaw, claims); err != nil {
		return nil, err
	}

	info := &IssueInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Subject:  claims.Claims.Subject,
		ClientID: claims.Custom.ClientID,
		Federated: &Federated{
			UserID:   claims.Custom.UserID,
			Provider: claims.Custom.Provider,
		},
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		return nil, err
	}

	result := &openapi.Token{
		TokenType:    "Bearer",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    int(time.Until(tokens.Expiry).Seconds()),
	}

	return result, nil
}

// TokenClientCredentials issues a token if the client credentials are valid.  We only support
// mTLS based authentication.
func (a *Authenticator) TokenClientCredentials(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	certPEM, err := util.GetClientCertificateHeader(r.Header)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("mTLS client verification failed").WithError(err)
	}

	certificate, err := util.GetClientCertificate(certPEM)
	if err != nil {
		return nil, errors.OAuth2InvalidRequest("mTLS certificate validation failed").WithError(err)
	}

	thumbprint := util.GetClientCertiifcateThumbprint(certificate)

	info := &IssueInfo{
		Issuer:         "https://" + r.Host,
		Audience:       r.Host,
		Subject:        certificate.Subject.CommonName,
		X509Thumbprint: thumbprint,
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		return nil, err
	}

	result := &openapi.Token{
		TokenType:   "Bearer",
		AccessToken: tokens.AccessToken,
		ExpiresIn:   int(time.Until(tokens.Expiry).Seconds()),
	}

	return result, nil
}

// Token issues an OAuth2 access token from the provided authorization code.
func (a *Authenticator) Token(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse form data: " + err.Error())
	}

	// We support 3 garnt types:
	// * "authorization_code" is used by all humans in the system
	// * "refresh_token" is used by anyone to get a new access token
	// * "client_credentials" is used by other services for IPC
	switch openapi.GrantType(r.Form.Get("grant_type")) {
	case openapi.AuthorizationCode:
		return a.TokenAuthorizationCode(w, r)
	case openapi.RefreshToken:
		return a.TokenRefreshToken(w, r)
	case openapi.ClientCredentials:
		return a.TokenClientCredentials(w, r)
	}

	return nil, errors.OAuth2InvalidRequest("token grant type is not supported")
}

// GetUserinfo does access token introspection.
func (a *Authenticator) GetUserinfo(ctx context.Context, r *http.Request, token string) (*openapi.Userinfo, *AccessTokenClaims, error) {
	verifyInfo := &VerifyInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Token:    token,
	}

	// Check the token is from us, for us, and in date.
	claims, err := a.Verify(ctx, verifyInfo)
	if err != nil {
		return nil, nil, errors.OAuth2AccessDenied("token validation failed").WithError(err)
	}

	userinfo := &openapi.Userinfo{
		Sub: claims.Subject,
	}

	if claims.Custom != nil && slices.Contains(claims.Custom.Scope, "email") {
		userinfo.Email = ptr.To(claims.Subject)
		userinfo.EmailVerified = ptr.To(true)
	}

	// Need to expand the user information...
	// if slices.Contains(claims.Custom.Scope, "profile") {
	// }

	return userinfo, claims, nil
}
