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
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"

	coreopenapi "github.com/unikorn-cloud/core/pkg/openapi"
	"github.com/unikorn-cloud/core/pkg/server/errors"
	"github.com/unikorn-cloud/core/pkg/util/retry"
	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/html"
	"github.com/unikorn-cloud/identity/pkg/jose"
	"github.com/unikorn-cloud/identity/pkg/oauth2/providers"
	"github.com/unikorn-cloud/identity/pkg/openapi"
	"github.com/unikorn-cloud/identity/pkg/rbac"
	"github.com/unikorn-cloud/identity/pkg/util"

	"k8s.io/apimachinery/pkg/util/cache"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	ErrUnsupportedProviderType = goerrors.New("unhandled provider type")
	ErrReference               = goerrors.New("resource reference error")
	ErrUserNotDomainMapped     = goerrors.New("user is not domain mapped to an organization")
	ErrEmailLookup             = goerrors.New("failed to lookup email")
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

	// Bool to indicate whether sign up is allowed
	AuthenticateUnknownUsers bool
}

func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.DurationVar(&o.AccessTokenDuration, "access-token-duration", time.Hour, "Maximum time an access token can be active for.")
	f.DurationVar(&o.RefreshTokenDuration, "refresh-token-duration", 0, "Maximum time a refresh token can be active for.")
	f.DurationVar(&o.TokenVerificationLeeway, "token-verification-leeway", 0, "How mush leeway to permit for verification of token validity.")
	f.DurationVar(&o.TokenLeewayDuration, "token-leeway", time.Minute, "How long to remove from the provider token expiry to account for network and processing latency.")
	f.IntVar(&o.TokenCacheSize, "token-cache-size", 8192, "How many token cache entries to allow.")
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
	// IDToken is the full set of claims returned by the provider.
	IDToken *IDToken `json:"idt"`
	// AccessToken is the user's access token.
	AccessToken string `json:"at"`
	// RefreshToken is the users's refresh token.
	RefreshToken string `json:"rt"`
	// AccessTokenExpiry tells us how long the token will last for.
	AccessTokenExpiry time.Time `json:"ate"`
	// OAuth2Provider is the name of the provider configuration in
	// use, this will reference the issuer and allow discovery.
	OAuth2Provider string `json:"oap"`
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

// authorizationError redirects to the client's callback URI with an error
// code in the query.
func authorizationError(w http.ResponseWriter, r *http.Request, redirectURI string, kind Error, description string) {
	values := &url.Values{}
	values.Set("error", string(kind))
	values.Set("error_description", description)

	http.Redirect(w, r, redirectURI+"?"+values.Encode(), http.StatusFound)
}

// lookupClient returns the oauth2 client given its ID.
func (a *Authenticator) lookupClient(ctx context.Context, id string) (*unikornv1.OAuth2Client, error) {
	cli := &unikornv1.OAuth2Client{}

	if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: id}, cli); err != nil {
		return nil, err
	}

	return cli, nil
}

// OAuth2AuthorizationValidateNonRedirecting checks authorization request parameters
// are valid that directly control the ability to redirect, and returns some helpful
// debug in HTML.
func (a *Authenticator) authorizationValidateNonRedirecting(w http.ResponseWriter, r *http.Request) (*unikornv1.OAuth2Client, bool) {
	query := r.URL.Query()

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

// OAuth2AuthorizationValidateRedirecting checks autohorization request parameters after
// the redirect URI has been validated.  If any of these fail, we redirect but with an
// error query rather than a code for the client to pick up and run with.
func (a *Authenticator) authorizationValidateRedirecting(w http.ResponseWriter, r *http.Request, client *unikornv1.OAuth2Client) bool {
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

	authorizationError(w, r, client.Spec.RedirectURI, kind, description)

	return false
}

// useOauth2 is a quick hack, we should probably encode this as part of the CRD?
func useOauth2(provider *unikornv1.OAuth2Provider) bool {
	if provider.Spec.Type != nil && *provider.Spec.Type == unikornv1.GitHub {
		return true
	}

	return false
}

// oidcConfig returns a oauth2 configuration for the OIDC backend.
func oidcConfig(ctx context.Context, host string, provider *unikornv1.OAuth2Provider, scopes []string) (*oidc.Provider, *oauth2.Config, error) {
	// Do service disocvery.
	oidcProvider, err := newOIDCProvider(ctx, provider)
	if err != nil {
		return nil, nil, err
	}

	endpoint := oidcProvider.Endpoint()

	config := oauth2Config(host, provider, &endpoint, slices.Concat([]string{oidc.ScopeOpenID, "profile", "email"}, scopes))

	return oidcProvider, config, nil
}

// oauth2Config returns an oauth2 configuration for the oauth2 only backend.
func oauth2Config(host string, provider *unikornv1.OAuth2Provider, endpoint *oauth2.Endpoint, scopes []string) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     provider.Spec.ClientID,
		ClientSecret: provider.Spec.ClientSecret,
		RedirectURL:  "https://" + host + "/oidc/callback",
		Scopes:       scopes,
	}

	if endpoint != nil {
		config.Endpoint = *endpoint
	}

	if provider.Spec.AuthorizationURI != nil && provider.Spec.TokenURI != nil {
		config.Endpoint.AuthURL = *provider.Spec.AuthorizationURI
		config.Endpoint.TokenURL = *provider.Spec.TokenURI
	}

	return config
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

type LoginStateClaims struct {
	Query string `json:"query"`
}

// Authorization redirects the client to the OIDC autorization endpoint
// to get an authorization code.  Note that this function is responsible for
// either returning an authorization grant or error via a HTTP 302 redirect,
// or returning a HTML fragment for errors that cannot follow the provided
// redirect URI.
func (a *Authenticator) Authorization(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	query := r.URL.Query()

	client, ok := a.authorizationValidateNonRedirecting(w, r)
	if !ok {
		return
	}

	if !a.authorizationValidateRedirecting(w, r, client) {
		return
	}

	// Encrypt the query across the login dialog to prevent tampering.
	stateClaims := &LoginStateClaims{
		Query: query.Encode(),
	}

	state, err := a.issuer.EncodeJWEToken(r.Context(), stateClaims, jose.TokenTypeLoginDialogState)
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "failed to encode request state")
		return
	}

	supportedTypes, err := a.getProviderTypes(r.Context())
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "failed to get oauth2 providers")
		return
	}

	loginQuery := url.Values{}

	loginQuery.Set("state", state)
	loginQuery.Set("callback", "https://"+r.Host+"/oauth2/v2/login")
	// TODO: this needs to be driven by the available oauth2providers
	loginQuery.Set("providers", strings.Join(supportedTypes, " "))

	// Redirect to an external login handler, if you have chosen to.
	if client.Spec.LoginURI != nil {
		http.Redirect(w, r, fmt.Sprintf("%s?%s", *client.Spec.LoginURI, loginQuery.Encode()), http.StatusFound)
		return
	}

	// Otherwise use the internal version.
	body, err := html.Login(loginQuery.Encode())
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "failed to render login template")
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body); err != nil {
		log.Info("oauth2: failed to write HTML response")
		return
	}
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

// newOIDCProvider abstracts away any hacks for specific providers.
func newOIDCProvider(ctx context.Context, p *unikornv1.OAuth2Provider) (*oidc.Provider, error) {
	if p.Spec.Type != nil && *p.Spec.Type == unikornv1.MicrosoftEntra {
		ctx = oidc.InsecureIssuerURLContext(ctx, "https://login.microsoftonline.com/{tenantid}/v2.0")
	}

	return oidc.NewProvider(ctx, p.Spec.Issuer)
}

// providerAuthenticationRequest takes a client provided email address and routes it
// to the correct identity provider, if we can.
func (a *Authenticator) providerAuthenticationRequest(w http.ResponseWriter, r *http.Request, client *unikornv1.OAuth2Client, providerResource *unikornv1.OAuth2Provider, query url.Values, email string) {
	driver := providers.New(providerResource.Spec.Type)

	// OIDC requires a nonce, just some random data base64 URL encoded will suffice.
	nonce, err := randomString(16)
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "unable to create oidc nonce: "+err.Error())
		return
	}

	// We pass a hashed code challenge to the OIDC authorization endpoint when
	// requesting an authentication code.  When we exchange that for a token we
	// send the initial code challenge verifier so the token endpoint can validate
	// it's talking to the same client.
	codeVerifier, err := randomString(32)
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "unable to create oauth2 code verifier: "+err.Error())
		return
	}

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

	state, err := a.issuer.EncodeJWEToken(r.Context(), oidcState, jose.TokenTypeLoginState)
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "failed to encode oidc state: "+err.Error())
		return
	}

	// Take a short cut if using oauth2.
	if useOauth2(providerResource) {
		http.Redirect(w, r, oauth2Config(r.Host, providerResource, nil, nil).AuthCodeURL(state), http.StatusFound)
		return
	}

	// Otherwise handle OIDC via endpoint discovery.
	_, config, err := oidcConfig(r.Context(), r.Host, providerResource, driver.Scopes())
	if err != nil {
		authorizationError(w, r, client.Spec.RedirectURI, ErrorServerError, "unable to create oauth2 configuration: "+err.Error())
		return
	}

	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", encodeCodeChallengeS256(codeVerifier)),
		oidc.Nonce(nonce),
	}

	// If the user provided an email as part of the loging screen, send that to the IdP to
	// optimize the process.
	if email != "" {
		authURLParams = append(authURLParams, oauth2.SetAuthURLParam("login_hint", email))
	}

	for k, v := range driver.AuthorizationRequestParameters() {
		authURLParams = append(authURLParams, oauth2.SetAuthURLParam(k, v))
	}

	http.Redirect(w, r, config.AuthCodeURL(state, authURLParams...), http.StatusFound)
}

// Login handles the response from the user login prompt.
//
//nolint:cyclop
func (a *Authenticator) Login(w http.ResponseWriter, r *http.Request) {
	log := log.FromContext(r.Context())

	if err := r.ParseForm(); err != nil {
		log.Error(err, "form parse failed")
		return
	}

	if !r.Form.Has("state") {
		log.Info("state doesn't exist in form")
		return
	}

	state := &LoginStateClaims{}

	if err := a.issuer.DecodeJWEToken(r.Context(), r.Form.Get("state"), state, jose.TokenTypeLoginDialogState); err != nil {
		htmlError(w, r, http.StatusBadRequest, "login state failed to decode")
		return
	}

	query, err := url.ParseQuery(state.Query)
	if err != nil {
		log.Error(err, "failed to parse query")
		return
	}

	client, err := a.lookupClient(r.Context(), query.Get("client_id"))
	if err != nil {
		htmlError(w, r, http.StatusBadRequest, "unable to lookup client")
		return
	}

	if providerType := r.Form.Get("provider"); providerType != "" {
		provider, err := a.lookupProviderByType(r.Context(), unikornv1.IdentityProviderType(providerType))
		if err != nil {
			authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, err.Error())
			return
		}

		a.providerAuthenticationRequest(w, r, client, provider, query, "")

		return
	}

	email := r.Form.Get("email")

	if email == "" {
		authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, "email query parameter not specified")
		return
	}

	organization, err := a.lookupOrganization(r.Context(), email)
	if err != nil {
		authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, err.Error())
		return
	}

	provider, err := a.lookupProviderByID(r.Context(), *organization.Spec.ProviderID, organization)
	if err != nil {
		authorizationError(w, r, query.Get("redirect_uri"), ErrorServerError, err.Error())
		return
	}

	a.providerAuthenticationRequest(w, r, client, provider, query, email)
}

// oidcExtractIDToken wraps up token verification against the JWKS service and conversion
// to a concrete type.
func (a *Authenticator) oidcExtractIDToken(ctx context.Context, provider *oidc.Provider, providerResource *unikornv1.OAuth2Provider, token string) (*oidc.IDToken, error) {
	config := &oidc.Config{
		ClientID: providerResource.Spec.ClientID,
		// TODO: this is a Entra-ism
		SkipIssuerCheck: true,
	}

	idTokenVerifier := provider.Verifier(config)

	idToken, err := idTokenVerifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	return idToken, nil
}

//nolint:tagliatelle
type GitHubUser struct {
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type GitHubEmail struct {
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
	Primary  bool   `json:"primary"`
}

const githubAPIBase = "https://api.github.com"

type GitHubClient struct {
	token string
}

func NewGitHubClient(token string) *GitHubClient {
	return &GitHubClient{
		token: token,
	}
}

func (g *GitHubClient) do(ctx context.Context, path string, data interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPIBase+path, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "bearer "+g.token)
	req.Header.Set("X-Github-Api-Version", "2022-11-28")

	c := &http.Client{}

	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, data); err != nil {
		return err
	}

	return nil
}

func (g *GitHubClient) GetUser(ctx context.Context) (*GitHubUser, error) {
	user := &GitHubUser{}

	if err := g.do(ctx, "/user", user); err != nil {
		return nil, err
	}

	return user, nil
}

func (g *GitHubClient) GetEmails(ctx context.Context) ([]GitHubEmail, error) {
	var emails []GitHubEmail

	if err := g.do(ctx, "/user/emails", &emails); err != nil {
		return nil, err
	}

	return emails, nil
}

func (g *GitHubClient) GetPrimaryEmail(ctx context.Context) (*GitHubEmail, error) {
	emails, err := g.GetEmails(ctx)
	if err != nil {
		return nil, err
	}

	i := slices.IndexFunc(emails, func(email GitHubEmail) bool { return email.Primary })
	if i < 0 {
		return nil, ErrEmailLookup
	}

	return &emails[i], nil
}

func createGitHubIDToken(ctx context.Context, token string) (*IDToken, error) {
	github := NewGitHubClient(token)

	// User gives us information about the user...
	user, err := github.GetUser(ctx)
	if err != nil {
		return nil, err
	}

	// ...but not always an email address.
	email, err := github.GetPrimaryEmail(ctx)
	if err != nil {
		return nil, err
	}

	out := &IDToken{
		OIDCClaimsProfile: OIDCClaimsProfile{
			Name:    user.Name,
			Picture: user.AvatarURL,
		},
		OIDCClaimsEmail: OIDCClaimsEmail{
			Email:         email.Email,
			EmailVerified: email.Verified,
		},
	}

	return out, nil
}

// oauth2CodeExchange exchanges a code with a plain oauth2 server.
func (a *Authenticator) oauth2CodeExchange(ctx context.Context, provider *unikornv1.OAuth2Provider, host, code string) (*oauth2.Token, *IDToken, error) {
	token, err := oauth2Config(host, provider, nil, nil).Exchange(ctx, code)
	if err != nil {
		return nil, nil, err
	}

	if provider.Spec.Type == nil || *provider.Spec.Type != unikornv1.GitHub {
		return nil, nil, fmt.Errorf("%w: %v", ErrUnsupportedProviderType, provider.Spec.Type)
	}

	idToken, err := createGitHubIDToken(ctx, token.AccessToken)
	if err != nil {
		return nil, nil, err
	}

	return token, idToken, nil
}

// oidcCodeExchange exchanges a code with an IODC compliant server.
func (a *Authenticator) oidcCodeExchange(ctx context.Context, provider *unikornv1.OAuth2Provider, state *State, host, code string) (*oauth2.Token, *IDToken, error) {
	oidcProvider, config, err := oidcConfig(ctx, host, provider, nil)
	if err != nil {
		return nil, nil, err
	}

	// Exchange the code for an id_token, access_token and refresh_token with
	// the extracted code verifier.
	authURLParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_id", state.ClientID),
		oauth2.SetAuthURLParam("code_verifier", state.CodeVerfier),
	}

	token, err := config.Exchange(ctx, code, authURLParams...)
	if err != nil {
		return nil, nil, err
	}

	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, err
	}

	idToken, err := a.oidcExtractIDToken(ctx, oidcProvider, provider, idTokenRaw)
	if err != nil {
		return nil, nil, err
	}

	idTokenClaims := &IDToken{}

	if err := idToken.Claims(idTokenClaims); err != nil {
		return nil, nil, err
	}

	return token, idTokenClaims, nil
}

// codeExchange exchanges a code with any server in an abstract way.
func (a *Authenticator) codeExchange(ctx context.Context, provider *unikornv1.OAuth2Provider, state *State, host, code string) (*oauth2.Token, *IDToken, error) {
	if useOauth2(provider) {
		return a.oauth2CodeExchange(ctx, provider, host, code)
	}

	return a.oidcCodeExchange(ctx, provider, state, host, code)
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

	if query.Has("error") {
		authorizationError(w, r, state.ClientRedirectURI, Error(query.Get("error")), query.Get("description"))
		return
	}

	if !query.Has("code") {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "oidc callback does not contain an authorization code")
		return
	}

	provider, err := a.lookupProviderByID(r.Context(), state.OAuth2Provider, nil)
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to get oauth2 provider")
		return
	}

	tokens, idToken, err := a.codeExchange(r.Context(), provider, state, r.Host, query.Get("code"))
	if err != nil {
		authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "code exchange failed: "+err.Error())
		return
	}

	// Only check rbac if we are not allowing unknown users.
	if !a.options.AuthenticateUnknownUsers {
		userExists, err := a.rbac.UserExists(r.Context(), idToken.Email)

		if err != nil {
			authorizationError(w, r, state.ClientRedirectURI, ErrorServerError, "failed to perform RBAC user lookup: "+err.Error())
			return
		}

		if !userExists {
			authorizationError(w, r, state.ClientRedirectURI, ErrorAccessDenied, "user does not exist in any organization")
			return
		}
	}

	// NOTE: the email is the canonical one returned by the IdP, which removes
	// aliases from the equation.
	oauth2Code := &Code{
		ClientID:            state.ClientID,
		ClientRedirectURI:   state.ClientRedirectURI,
		ClientCodeChallenge: state.ClientCodeChallenge,
		ClientScope:         state.ClientScope,
		ClientNonce:         state.ClientNonce,
		OAuth2Provider:      state.OAuth2Provider,
		IDToken:             idToken,
		AccessTokenExpiry:   tokens.Expiry,
	}

	driver := providers.New(provider.Spec.Type)

	// These can be big, see the provider comment for why.
	if driver.RequiresAccessToken() {
		oauth2Code.AccessToken = tokens.AccessToken
		oauth2Code.RefreshToken = tokens.RefreshToken
	}

	code, err := a.issuer.EncodeJWEToken(r.Context(), oauth2Code, jose.TokenTypeAuthorizationCode)
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

// oidcIDToken builds an OIDC ID token.
func (a *Authenticator) oidcIDToken(r *http.Request, code *Code, expiry time.Duration, atHash string) (*string, error) {
	//nolint:nilnil
	if !slices.Contains(code.ClientScope, "openid") {
		return nil, nil
	}

	claims := &IDToken{
		Claims: jwt.Claims{
			Issuer:  "https://" + r.Host,
			Subject: code.IDToken.OIDCClaimsEmail.Email,
			Audience: []string{
				code.ClientID,
			},
			Expiry:   jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		OIDCClaims: OIDCClaims{
			Nonce:  code.ClientNonce,
			ATHash: atHash,
		},
	}

	if slices.Contains(code.ClientScope, "email") {
		claims.OIDCClaimsEmail = code.IDToken.OIDCClaimsEmail
	}

	if slices.Contains(code.ClientScope, "profile") {
		claims.OIDCClaimsProfile = code.IDToken.OIDCClaimsProfile
	}

	idToken, err := a.issuer.EncodeJWT(r.Context(), claims)
	if err != nil {
		return nil, err
	}

	return &idToken, nil
}

// TokenAuthorizationCode issues a token based on whether the provided code is correct and
// the client code verifier (PKCS) matches.
func (a *Authenticator) TokenAuthorizationCode(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	if err := tokenValidate(r); err != nil {
		return nil, err
	}

	code := &Code{}

	if err := a.issuer.DecodeJWEToken(r.Context(), r.Form.Get("code"), code, jose.TokenTypeAuthorizationCode); err != nil {
		return nil, errors.OAuth2InvalidRequest("failed to parse code: " + err.Error())
	}

	if err := tokenValidateCode(code, r); err != nil {
		return nil, err
	}

	info := &IssueInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Subject:  code.IDToken.OIDCClaimsEmail.Email,
		ClientID: code.ClientID,
		Federated: &Federated{
			Provider:    code.OAuth2Provider,
			Expiry:      code.AccessTokenExpiry,
			AccessToken: code.AccessToken,
		},
	}

	if code.RefreshToken != "" {
		info.Federated.RefreshToken = &code.RefreshToken
	}

	tokens, err := a.Issue(r.Context(), info)
	if err != nil {
		return nil, err
	}

	// Handle OIDC.
	idToken, err := a.oidcIDToken(r, code, a.options.AccessTokenDuration, oidcHash(tokens.AccessToken))
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

// tokenRefreshConfig selects the correct configuration for a token refresh.
func tokenRefreshConfig(ctx context.Context, provider *unikornv1.OAuth2Provider, host string) (*oauth2.Config, error) {
	if useOauth2(provider) {
		return oauth2Config(host, provider, nil, nil), nil
	}

	var config *oauth2.Config

	// Quality of life improvement, when you are a road-warrior, you are going
	// to get an expired access token almost immediately, and a token refresh
	// well before Wifi comes up, so allow retries while DNS errors are
	// occurring, within reason.
	callback := func() error {
		_, c, err := oidcConfig(ctx, host, provider, nil)
		if err != nil {
			return err
		}

		config = c

		return nil
	}

	retryContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := retry.Forever().DoWithContext(retryContext, callback); err != nil {
		return nil, err
	}

	return config, nil
}

// TokenRefreshToken issues a token if the provided refresh token is valid.
func (a *Authenticator) TokenRefreshToken(w http.ResponseWriter, r *http.Request) (*openapi.Token, error) {
	// Validate the refresh token and extract the claims.
	claims := &RefreshTokenClaims{}

	if err := a.issuer.DecodeJWEToken(r.Context(), r.Form.Get("refresh_token"), claims, jose.TokenTypeRefreshToken); err != nil {
		return nil, errors.OAuth2InvalidGrant("refresh token is invalid or has expired").WithError(err)
	}

	// Lookup the provider details, then do a token refresh against that to update
	// the access token.
	provider, err := a.lookupProviderByID(r.Context(), claims.Custom.Provider, nil)
	if err != nil {
		return nil, err
	}

	config, err := tokenRefreshConfig(r.Context(), provider, r.Host)
	if err != nil {
		return nil, errors.OAuth2ServerError("failed to get oauth2 config").WithError(err)
	}

	refreshToken := &oauth2.Token{
		Expiry:       time.Now(),
		RefreshToken: claims.Custom.RefreshToken,
	}

	providerTokens, err := config.TokenSource(r.Context(), refreshToken).Token()
	if err != nil {
		var rerr *oauth2.RetrieveError

		if goerrors.As(err, &rerr) && rerr.ErrorCode == string(coreopenapi.InvalidGrant) {
			return nil, errors.OAuth2InvalidGrant("provider refresh token has expired").WithError(err)
		}

		return nil, err
	}

	info := &IssueInfo{
		Issuer:   "https://" + r.Host,
		Audience: r.Host,
		Subject:  claims.Claims.Subject,
		ClientID: claims.Custom.ClientID,
		Federated: &Federated{
			Provider:    claims.Custom.Provider,
			Expiry:      providerTokens.Expiry,
			AccessToken: providerTokens.AccessToken,
		},
	}

	if providerTokens.RefreshToken != "" {
		info.Federated.RefreshToken = &providerTokens.RefreshToken
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
