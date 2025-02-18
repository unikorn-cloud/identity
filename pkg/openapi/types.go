// Package openapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package openapi

import (
	"time"

	externalRef0 "github.com/unikorn-cloud/core/pkg/openapi"
)

const (
	Oauth2AuthenticationScopes = "oauth2Authentication.Scopes"
)

// Defines values for AclOperation.
const (
	Create AclOperation = "create"
	Delete AclOperation = "delete"
	Read   AclOperation = "read"
	Update AclOperation = "update"
)

// Defines values for AuthMethod.
const (
	ClientSecretBasic AuthMethod = "client_secret_basic"
	ClientSecretPost  AuthMethod = "client_secret_post"
	TlsClientAuth     AuthMethod = "tls_client_auth"
)

// Defines values for Claim.
const (
	ClaimAud           Claim = "aud"
	ClaimEmail         Claim = "email"
	ClaimEmailVerified Claim = "email_verified"
	ClaimExp           Claim = "exp"
	ClaimFamilyName    Claim = "family_name"
	ClaimGivenName     Claim = "given_name"
	ClaimIat           Claim = "iat"
	ClaimIss           Claim = "iss"
	ClaimLocale        Claim = "locale"
	ClaimName          Claim = "name"
	ClaimPicture       Claim = "picture"
	ClaimSub           Claim = "sub"
)

// Defines values for CodeChallengeMethod.
const (
	Plain CodeChallengeMethod = "plain"
	S256  CodeChallengeMethod = "S256"
)

// Defines values for GrantType.
const (
	AuthorizationCode GrantType = "authorization_code"
	ClientCredentials GrantType = "client_credentials"
	RefreshToken      GrantType = "refresh_token"
)

// Defines values for Oauth2ProviderType.
const (
	Github    Oauth2ProviderType = "github"
	Google    Oauth2ProviderType = "google"
	Microsoft Oauth2ProviderType = "microsoft"
)

// Defines values for OrganizationType.
const (
	Adhoc  OrganizationType = "adhoc"
	Domain OrganizationType = "domain"
)

// Defines values for ProviderScope.
const (
	Global       ProviderScope = "global"
	Organization ProviderScope = "organization"
)

// Defines values for ResponseType.
const (
	ResponseTypeCode             ResponseType = "code"
	ResponseTypeCodeIdToken      ResponseType = "code id_token"
	ResponseTypeCodeToken        ResponseType = "code token"
	ResponseTypeCodeTokenIdToken ResponseType = "code token id_token"
	ResponseTypeIdToken          ResponseType = "id_token"
	ResponseTypeNone             ResponseType = "none"
	ResponseTypeToken            ResponseType = "token"
	ResponseTypeTokenIdToken     ResponseType = "token id_token"
)

// Defines values for Scope.
const (
	ScopeEmail   Scope = "email"
	ScopeOpenid  Scope = "openid"
	ScopeProfile Scope = "profile"
)

// Defines values for SigningAlgorithm.
const (
	ES512 SigningAlgorithm = "ES512"
)

// Defines values for UserState.
const (
	Active    UserState = "active"
	Pending   UserState = "pending"
	Suspended UserState = "suspended"
)

// Acl A list of access control scopes and permissions.
type Acl struct {
	// Global A list of access control scopes.
	Global *AclEndpoints `json:"global,omitempty"`

	// Organization Resource scoped endpoint permissions.
	Organization *AclScopedEndpoints `json:"organization,omitempty"`

	// Projects A list of resource scoped endpoint permissions.
	Projects *AclScopedEndpointsList `json:"projects,omitempty"`
}

// AclEndpoint A set of access control permissions for a resource type.
type AclEndpoint struct {
	// Name The resource name
	Name string `json:"name"`

	// Operations A list of access control operations.
	Operations AclOperations `json:"operations"`
}

// AclEndpoints A list of access control scopes.
type AclEndpoints = []AclEndpoint

// AclOperation An access control operation.
type AclOperation string

// AclOperations A list of access control operations.
type AclOperations = []AclOperation

// AclScopedEndpoints Resource scoped endpoint permissions.
type AclScopedEndpoints struct {
	// Endpoints A list of access control scopes.
	Endpoints AclEndpoints `json:"endpoints"`

	// Id The resource ID this scope applies to.
	Id string `json:"id"`
}

// AclScopedEndpointsList A list of resource scoped endpoint permissions.
type AclScopedEndpointsList = []AclScopedEndpoints

// AllocationRead An allocation of resources.
type AllocationRead struct {
	Metadata externalRef0.ProjectScopedResourceReadMetadata `json:"metadata"`

	// Spec A set of resource allocations.
	Spec AllocationSpec `json:"spec"`
}

// AllocationSpec A set of resource allocations.
type AllocationSpec struct {
	// Allocations A list of quotas.
	Allocations ResourceAllocationList `json:"allocations"`

	// Id The resource ID that owns this allocation.
	Id string `json:"id"`

	// Kind The resource kind that owns this allocation.
	Kind string `json:"kind"`
}

// AllocationWrite An allocation of resources.
type AllocationWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A set of resource allocations.
	Spec AllocationSpec `json:"spec"`
}

// Allocations A list of allocations.
type Allocations = []AllocationRead

// AuthMethod Supported authentication methods.
type AuthMethod string

// AuthenticationRequestOptions aith2/OIDC authorization endpoint request.
type AuthenticationRequestOptions struct {
	// AcrValues Requested content class reference values.
	AcrValues *string `json:"acr_values"`

	// ClientId The client identifier.
	ClientId string `json:"client_id"`

	// Display How to display the login prompt.
	Display *string `json:"display"`

	// IdTokenHint A previously issued ID token.
	IdTokenHint *string `json:"id_token_hint"`

	// LoginHint A login hint e.g. user name.
	LoginHint *string `json:"login_hint"`

	// MaxAge Max age of the login.
	MaxAge *string `json:"max_age"`

	// Nonce OIDC nonce.
	Nonce *string `json:"nonce"`

	// Prompt OIDC prompt.
	Prompt *string `json:"prompt"`

	// RedirectUri The registered callback address.
	RedirectUri string `json:"redirect_uri"`

	// ResponseType Supported response types.
	ResponseType ResponseType `json:"response_type"`

	// Scope Authorization scope.
	Scope *string `json:"scope"`

	// State Client state information.
	State *string `json:"state"`

	// UiLocales Language options.
	UiLocales *string `json:"ui_locales"`
}

// Claim Supported claims.
type Claim string

// CodeChallengeMethod Supported code challenge methods.
type CodeChallengeMethod string

// GrantType Supported grant type.
type GrantType string

// GroupIDs A list of group IDs.
type GroupIDs = []string

// GroupRead A group when read.
type GroupRead struct {
	Metadata externalRef0.OrganizationScopedResourceReadMetadata `json:"metadata"`

	// Spec A group.
	Spec GroupSpec `json:"spec"`
}

// GroupSpec A group.
type GroupSpec struct {
	// RoleIDs A list of strings.
	RoleIDs StringList `json:"roleIDs"`

	// ServiceAccountIDs A list of strings.
	ServiceAccountIDs StringList `json:"serviceAccountIDs"`

	// UserIDs A list of strings.
	UserIDs StringList `json:"userIDs"`
}

// GroupWrite A group when created or updated.
type GroupWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A group.
	Spec GroupSpec `json:"spec"`
}

// Groups A list of groups.
type Groups = []GroupRead

// JsonWebKey JSON web key. See the relevant JWKS documentation for further details.
type JsonWebKey = map[string]interface{}

// JsonWebKeySet JSON web key set. This data type is defined by an external 3rd party standards
// committee. Consult the relevant documentation for further details.
type JsonWebKeySet struct {
	Keys *[]JsonWebKey `json:"keys,omitempty"`
}

// LoginRequestOptions Login request options.
type LoginRequestOptions struct {
	// Email The user's email address.
	Email *string `json:"email"`

	// Provider The explcit provider type.
	Provider *string `json:"provider"`

	// State The state string supplied by the authorization endpoint.
	State string `json:"state"`
}

// Oauth2ProviderRead An OAuth2 provider when read.
type Oauth2ProviderRead struct {
	Metadata externalRef0.OrganizationScopedResourceReadMetadata `json:"metadata"`

	// Spec An oauth2 provider.
	Spec Oauth2ProviderSpec `json:"spec"`
}

// Oauth2ProviderSpec An oauth2 provider.
type Oauth2ProviderSpec struct {
	// ClientID The client identification, only shown for super admin or organization owned providers
	// that you are an admin for.
	ClientID string `json:"clientID"`

	// ClientSecret The client secret, only shown for super admin or organization owned providers
	// that you are an admin for.
	ClientSecret *string `json:"clientSecret,omitempty"`

	// Issuer The OIDC issuer, typically where to perform auto discovery relative to.
	Issuer string `json:"issuer"`

	// Type The type of identity provider.
	Type *Oauth2ProviderType `json:"type,omitempty"`
}

// Oauth2ProviderType The type of identity provider.
type Oauth2ProviderType string

// Oauth2ProviderWrite An OAuth2 provider when created or updated.
type Oauth2ProviderWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec An oauth2 provider.
	Spec Oauth2ProviderSpec `json:"spec"`
}

// Oauth2Providers A list of oauth2 providers.
type Oauth2Providers = []Oauth2ProviderRead

// OpenidConfiguration OpenID configuration.
type OpenidConfiguration struct {
	// AuthorizationEndpoint The oauth2 endpoint that initiates authentication.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// ClaimsSupported A list of supported claims
	ClaimsSupported []Claim `json:"claims_supported"`

	// CodeChallengeMethodsSupported A list of code challenge methods supported.
	CodeChallengeMethodsSupported []CodeChallengeMethod `json:"code_challenge_methods_supported"`

	// GrantTypesSupported A list of supported grants for the token endpoint.
	GrantTypesSupported []GrantType `json:"grant_types_supported"`

	// IdTokenSigningAlgValuesSupported A list of signing algorithms supported for ID tokens.
	IdTokenSigningAlgValuesSupported []SigningAlgorithm `json:"id_token_signing_alg_values_supported"`

	// Issuer The OpenID Issuer (iss field).
	Issuer string `json:"issuer"`

	// JwksUri The oauth2 endpoint that exposes public signing keys for token validation.
	JwksUri string `json:"jwks_uri"`

	// ResponseTypesSupported A list of supported response types that can be requested for the authorization endpoint.
	ResponseTypesSupported []ResponseType `json:"response_types_supported"`

	// ScopesSupported A list of supported oauth2 scopes.
	ScopesSupported []Scope `json:"scopes_supported"`

	// TokenEndpoint The oauth2 endpoint that is used to exchange an authentication code for tokens.
	TokenEndpoint string `json:"token_endpoint"`

	// TokenEndpointAuthMethodsSupported A list of supported authentication methods for the token endpoint.
	TokenEndpointAuthMethodsSupported []AuthMethod `json:"token_endpoint_auth_methods_supported"`

	// UserinfoEndpoint The oidc endpoint used to get information about an access token's user.
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

// OrganizationRead An organization when read.
type OrganizationRead struct {
	// Metadata Resource metadata valid for all reads.
	Metadata externalRef0.ResourceReadMetadata `json:"metadata"`

	// Spec An organization.
	Spec OrganizationSpec `json:"spec"`
}

// OrganizationSpec An organization.
type OrganizationSpec struct {
	// Domain The email domain of the organization.
	Domain *string `json:"domain,omitempty"`

	// GoogleCustomerID When set this identifies the customer ID for the google managed organization.
	// This enables the access to, and use of, Google groups as a source of truth
	// for RBAC.
	GoogleCustomerID *string `json:"googleCustomerID,omitempty"`

	// OrganizationType Describes the authntication menthod of the organization.  Adhoc authentication
	// means that users are exclusively added via explicit group membership  And must
	// use a 'sign-in via' option.  Domain authentication means that users may login
	// via their email address, must in the case of custom identity providers, that
	// maps from domain to an identity provider.  This enables authentication options
	// such as implicit group mappings for RBAC.
	OrganizationType OrganizationType `json:"organizationType"`

	// ProviderID The ID of the provider to use, the scope is determined by useCustomProvider.
	// If false, this refers to a built in provider, if true, then to an organization
	// specific one.
	ProviderID *string `json:"providerID,omitempty"`

	// ProviderScope Describes how to lookup the provider, when global, use a built in generic provider
	// e.g. Google/Microsoft, when organization, us an organization scoped provider.
	ProviderScope *ProviderScope `json:"providerScope,omitempty"`
}

// OrganizationType Describes the authntication menthod of the organization.  Adhoc authentication
// means that users are exclusively added via explicit group membership  And must
// use a 'sign-in via' option.  Domain authentication means that users may login
// via their email address, must in the case of custom identity providers, that
// maps from domain to an identity provider.  This enables authentication options
// such as implicit group mappings for RBAC.
type OrganizationType string

// OrganizationWrite An organization when created or updated.
type OrganizationWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec An organization.
	Spec OrganizationSpec `json:"spec"`
}

// Organizations A list of organizations.
type Organizations = []OrganizationRead

// ProjectRead A project when read.
type ProjectRead struct {
	Metadata externalRef0.OrganizationScopedResourceReadMetadata `json:"metadata"`

	// Spec A project.
	Spec ProjectSpec `json:"spec"`
}

// ProjectSpec A project.
type ProjectSpec struct {
	// GroupIDs A list of group IDs.
	GroupIDs GroupIDs `json:"groupIDs"`
}

// ProjectWrite A project when created or updated.
type ProjectWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A project.
	Spec ProjectSpec `json:"spec"`
}

// Projects A list of projects.
type Projects = []ProjectRead

// ProviderScope Describes how to lookup the provider, when global, use a built in generic provider
// e.g. Google/Microsoft, when organization, us an organization scoped provider.
type ProviderScope string

// QuotaRead A single quota.
type QuotaRead struct {
	// Committed Tha amount of that resource always in use.
	Committed int `json:"committed"`

	// Default The default value of the quota.
	Default int `json:"default"`

	// Description A verbose explanation of what the quota limits.
	Description string `json:"description"`

	// DisplayName The name that should be displayed to end users.
	DisplayName string `json:"displayName"`

	// Free The amount of that resource that is free.
	Free int `json:"free"`

	// Kind The kind of resource.
	Kind string `json:"kind"`

	// Quantity Tha maximum amount of that resource.
	Quantity int `json:"quantity"`

	// Reserved The amount of that resource that may be used e.g. autoscaled.
	Reserved int `json:"reserved"`

	// Used The amount of that resource that is used.
	Used int `json:"used"`
}

// QuotaReadList A list of quotas.
type QuotaReadList = []QuotaRead

// QuotaWrite A single quota.
type QuotaWrite struct {
	// Kind The kind of resource.
	Kind string `json:"kind"`

	// Quantity Tha maximum amount of that resource.
	Quantity int `json:"quantity"`
}

// QuotaWriteList A list of quotas.
type QuotaWriteList = []QuotaWrite

// QuotasRead A list of quotas.
type QuotasRead struct {
	// Quotas A list of quotas.
	Quotas QuotaReadList `json:"quotas"`
}

// QuotasWrite A list of quotas.
type QuotasWrite struct {
	// Quotas A list of quotas.
	Quotas QuotaWriteList `json:"quotas"`
}

// ResourceAllocation A single quota but taking into account dynamic allocation.
type ResourceAllocation struct {
	// Committed Tha amount of that resource always in use.
	Committed int `json:"committed"`

	// Kind The kind of resource.
	Kind string `json:"kind"`

	// Reserved The amount of that resource that may be used e.g. autoscaled.
	Reserved int `json:"reserved"`
}

// ResourceAllocationList A list of quotas.
type ResourceAllocationList = []ResourceAllocation

// ResponseType Supported response types.
type ResponseType string

// RoleRead A role.
type RoleRead struct {
	// Metadata Resource metadata valid for all reads.
	Metadata externalRef0.ResourceReadMetadata `json:"metadata"`
}

// Roles A list of roles.
type Roles = []RoleRead

// Scope Supported scopes.
type Scope string

// ServiceAccountCreate A new service account.
type ServiceAccountCreate struct {
	Metadata externalRef0.OrganizationScopedResourceReadMetadata `json:"metadata"`

	// Spec A service account specification.
	Spec ServiceAccountSpec `json:"spec"`

	// Status A service account status.
	Status ServiceAccountStatus `json:"status"`
}

// ServiceAccountRead A service account.
type ServiceAccountRead struct {
	Metadata externalRef0.OrganizationScopedResourceReadMetadata `json:"metadata"`

	// Spec A service account specification.
	Spec ServiceAccountSpec `json:"spec"`

	// Status A service account status.
	Status ServiceAccountStatus `json:"status"`
}

// ServiceAccountSpec A service account specification.
type ServiceAccountSpec struct {
	// GroupIDs A list of group IDs.
	GroupIDs GroupIDs `json:"groupIDs"`
}

// ServiceAccountStatus A service account status.
type ServiceAccountStatus struct {
	// AccessToken A long lived acccess token that can be exchanged for an API access token.
	AccessToken *string `json:"accessToken,omitempty"`

	// Expiry When the service token is due to expire.
	Expiry time.Time `json:"expiry"`
}

// ServiceAccountWrite A service account creation request.
type ServiceAccountWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata externalRef0.ResourceWriteMetadata `json:"metadata"`

	// Spec A service account specification.
	Spec ServiceAccountSpec `json:"spec"`
}

// ServiceAccounts A list of service accounts.
type ServiceAccounts = []ServiceAccountRead

// SigningAlgorithm Supported signing algorithms.
type SigningAlgorithm string

// StringList A list of strings.
type StringList = []string

// Token Oauth2 token result.
type Token struct {
	// AccessToken The opaque access token.
	AccessToken string `json:"access_token"`

	// ExpiresIn The time in seconds the token will last for.
	ExpiresIn int `json:"expires_in"`

	// IdToken An OIDC ID token.
	IdToken *string `json:"id_token,omitempty"`

	// RefreshToken The opaque refresh token.
	RefreshToken *string `json:"refresh_token,omitempty"`

	// TokenType How the access token is to be presented to the resource server.
	TokenType string `json:"token_type"`
}

// TokenRequestOptions oauth2 token endpoint.
type TokenRequestOptions struct {
	// ClientId Client ID. Required with the "code" grant type.
	ClientId *string `json:"client_id"`

	// Code Authorization code. Required with the "code" grant type.
	Code *string `json:"code"`

	// CodeVerifier Client code verifier. Required with the "code" grant type.
	CodeVerifier *string `json:"code_verifier"`

	// GrantType Supported grant type.  Must be either "code" or "password".
	GrantType string `json:"grant_type"`

	// Password Resource owner password. Required with the "password" grant type.
	Password *string `json:"password"`

	// RedirectUri Client redirect URI. Required with the "code" grant type.
	RedirectUri *string `json:"redirect_uri"`

	// RefreshToken A refresh token for the refresh_token grant type.
	RefreshToken *string `json:"refresh_token"`

	// Username Resource owner username. Required with the "password" grant type.
	Username *string `json:"username"`
}

// UserRead A user read object.
type UserRead struct {
	Metadata externalRef0.OrganizationScopedResourceReadMetadata `json:"metadata"`

	// Spec A user specification.
	Spec UserSpec `json:"spec"`

	// Status Additional user metadata.
	Status UserStatus `json:"status"`
}

// UserSpec A user specification.
type UserSpec struct {
	// GroupIDs A list of group IDs.
	GroupIDs GroupIDs `json:"groupIDs"`

	// State The state a user is in.
	State UserState `json:"state"`

	// Subject The uers's canonical name, usually an email address.
	Subject string `json:"subject"`
}

// UserState The state a user is in.
type UserState string

// UserStatus Additional user metadata.
type UserStatus struct {
	// LastActive The last time a user performed some action.  This is not guaranteed to
	// be completely accurate depending on performance constraints.
	LastActive *time.Time `json:"lastActive,omitempty"`
}

// UserWrite A user create/update object.
type UserWrite struct {
	// Metadata Resource metadata valid for all API resource reads and writes.
	Metadata *externalRef0.ResourceWriteMetadata `json:"metadata,omitempty"`

	// Spec A user specification.
	Spec UserSpec `json:"spec"`
}

// Userinfo Access token introspection data.
type Userinfo struct {
	// Birthdate The users' birth date formatted according to ISO8601.  The year portion may be 0000 if they choose not to reveal they are really old.
	Birthdate *time.Time `json:"birthdate,omitempty"`

	// Email The user's email address.
	Email *string `json:"email,omitempty"`

	// EmailVerified Whether the email address has been verified.
	EmailVerified *bool `json:"email_verified,omitempty"`

	// FamilyName The user's surname.
	FamilyName *string `json:"family_name,omitempty"`

	// Gender The user's gender.
	Gender *string `json:"gender,omitempty"`

	// GivenName The user's forename.
	GivenName *string `json:"given_name,omitempty"`

	// Locale The user's RFC5646 language tag.
	Locale *string `json:"locale,omitempty"`

	// MiddleName The user's middle name(s).
	MiddleName *string `json:"middle_name,omitempty"`

	// Name The user's full name.
	Name *string `json:"name,omitempty"`

	// Nickname The user's nickname.
	Nickname *string `json:"nickname,omitempty"`

	// Picture URL to the user's picture.
	Picture *string `json:"picture,omitempty"`

	// PreferredUsername How the user chooses to be addressed.
	PreferredUsername *string `json:"preferred_username,omitempty"`

	// Profile URL to the user's profile page.
	Profile *string `json:"profile,omitempty"`

	// Sub The access token's subject.
	Sub string `json:"sub"`

	// UpdatedAt Then the user's profile was last updated.
	UpdatedAt *string `json:"updated_at,omitempty"`

	// Website URL to the user's website.
	Website *string `json:"website,omitempty"`

	// Zoneinfo The user's IANA assigned timezone.
	Zoneinfo *string `json:"zoneinfo,omitempty"`
}

// Users A list of users.
type Users = []UserRead

// AllocationIDParameter defines model for allocationIDParameter.
type AllocationIDParameter = string

// GroupidParameter defines model for groupidParameter.
type GroupidParameter = string

// Oauth2ProvderIDParameter defines model for oauth2ProvderIDParameter.
type Oauth2ProvderIDParameter = string

// OrganizationIDParameter defines model for organizationIDParameter.
type OrganizationIDParameter = string

// ProjectIDParameter defines model for projectIDParameter.
type ProjectIDParameter = string

// ServiceAccountIDParameter defines model for serviceAccountIDParameter.
type ServiceAccountIDParameter = string

// UserIDParameter defines model for userIDParameter.
type UserIDParameter = string

// AclResponse A list of access control scopes and permissions.
type AclResponse = Acl

// AllocationResponse An allocation of resources.
type AllocationResponse = AllocationRead

// AllocationsResponse A list of allocations.
type AllocationsResponse = Allocations

// GroupResponse A group when read.
type GroupResponse = GroupRead

// GroupsResponse A list of groups.
type GroupsResponse = Groups

// JwksResponse JSON web key set. This data type is defined by an external 3rd party standards
// committee. Consult the relevant documentation for further details.
type JwksResponse = JsonWebKeySet

// Oauth2ProviderResponse An OAuth2 provider when read.
type Oauth2ProviderResponse = Oauth2ProviderRead

// Oauth2ProvidersResponse A list of oauth2 providers.
type Oauth2ProvidersResponse = Oauth2Providers

// OpenidConfigurationResponse OpenID configuration.
type OpenidConfigurationResponse = OpenidConfiguration

// OrganizationResponse An organization when read.
type OrganizationResponse = OrganizationRead

// OrganizationsResponse A list of organizations.
type OrganizationsResponse = Organizations

// ProjectResponse A project when read.
type ProjectResponse = ProjectRead

// ProjectsResponse A list of projects.
type ProjectsResponse = Projects

// QuotasResponse A list of quotas.
type QuotasResponse = QuotasRead

// RolesResponse A list of roles.
type RolesResponse = Roles

// ServiceAccountCreateResponse A new service account.
type ServiceAccountCreateResponse = ServiceAccountCreate

// ServiceAccountResponse A service account.
type ServiceAccountResponse = ServiceAccountRead

// ServiceAccountsResponse A list of service accounts.
type ServiceAccountsResponse = ServiceAccounts

// SystemOauth2ProvidersResponse A list of oauth2 providers.
type SystemOauth2ProvidersResponse = Oauth2Providers

// TokenResponse Oauth2 token result.
type TokenResponse = Token

// UserResponse A user read object.
type UserResponse = UserRead

// UserinfoResponse Access token introspection data.
type UserinfoResponse = Userinfo

// UsersResponse A list of users.
type UsersResponse = Users

// AllocationRequest An allocation of resources.
type AllocationRequest = AllocationWrite

// CreateGroupRequest A group when created or updated.
type CreateGroupRequest = GroupWrite

// CreateProjectRequest A project when created or updated.
type CreateProjectRequest = ProjectWrite

// Oauth2ProviderRequest An OAuth2 provider when created or updated.
type Oauth2ProviderRequest = Oauth2ProviderWrite

// QuotasRequest A list of quotas.
type QuotasRequest = QuotasWrite

// ServiceAccountCreateRequest A service account creation request.
type ServiceAccountCreateRequest = ServiceAccountWrite

// UpdateGroupRequest A group when created or updated.
type UpdateGroupRequest = GroupWrite

// UpdateOrganizationRequest An organization when created or updated.
type UpdateOrganizationRequest = OrganizationWrite

// UpdateProjectRequest A project when created or updated.
type UpdateProjectRequest = ProjectWrite

// UserCreateRequest A user create/update object.
type UserCreateRequest = UserWrite

// PostApiV1OrganizationsJSONRequestBody defines body for PostApiV1Organizations for application/json ContentType.
type PostApiV1OrganizationsJSONRequestBody = OrganizationWrite

// PutApiV1OrganizationsOrganizationIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDJSONRequestBody = OrganizationWrite

// PostApiV1OrganizationsOrganizationIDGroupsJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDGroups for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDGroupsJSONRequestBody = GroupWrite

// PutApiV1OrganizationsOrganizationIDGroupsGroupidJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDGroupsGroupid for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDGroupsGroupidJSONRequestBody = GroupWrite

// PostApiV1OrganizationsOrganizationIDOauth2providersJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDOauth2providers for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDOauth2providersJSONRequestBody = Oauth2ProviderWrite

// PutApiV1OrganizationsOrganizationIDOauth2providersProviderIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDOauth2providersProviderID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDOauth2providersProviderIDJSONRequestBody = Oauth2ProviderWrite

// PostApiV1OrganizationsOrganizationIDProjectsJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjects for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsJSONRequestBody = ProjectWrite

// PutApiV1OrganizationsOrganizationIDProjectsProjectIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDProjectsProjectID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDProjectsProjectIDJSONRequestBody = ProjectWrite

// PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocations for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsJSONRequestBody = AllocationWrite

// PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDProjectsProjectIDAllocationsAllocationIDJSONRequestBody = AllocationWrite

// PutApiV1OrganizationsOrganizationIDQuotasJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDQuotas for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDQuotasJSONRequestBody = QuotasWrite

// PostApiV1OrganizationsOrganizationIDServiceaccountsJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDServiceaccounts for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDServiceaccountsJSONRequestBody = ServiceAccountWrite

// PutApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDServiceaccountsServiceAccountIDJSONRequestBody = ServiceAccountWrite

// PostApiV1OrganizationsOrganizationIDUsersJSONRequestBody defines body for PostApiV1OrganizationsOrganizationIDUsers for application/json ContentType.
type PostApiV1OrganizationsOrganizationIDUsersJSONRequestBody = UserWrite

// PutApiV1OrganizationsOrganizationIDUsersUserIDJSONRequestBody defines body for PutApiV1OrganizationsOrganizationIDUsersUserID for application/json ContentType.
type PutApiV1OrganizationsOrganizationIDUsersUserIDJSONRequestBody = UserWrite

// PostOauth2V2AuthorizationFormdataRequestBody defines body for PostOauth2V2Authorization for application/x-www-form-urlencoded ContentType.
type PostOauth2V2AuthorizationFormdataRequestBody = AuthenticationRequestOptions

// PostOauth2V2LoginFormdataRequestBody defines body for PostOauth2V2Login for application/x-www-form-urlencoded ContentType.
type PostOauth2V2LoginFormdataRequestBody = LoginRequestOptions

// PostOauth2V2TokenFormdataRequestBody defines body for PostOauth2V2Token for application/x-www-form-urlencoded ContentType.
type PostOauth2V2TokenFormdataRequestBody = TokenRequestOptions
