/*
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

//nolint:tagliatelle
package v1alpha1

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IdentityProviderType defines the type of identity provider, and in turn
// that defines the required configuration and API interfaces.
// +kubebuilder:validation:Enum=custom;google;microsoft;github
type IdentityProviderType string

const (
	GoogleIdentity IdentityProviderType = "google"
	MicrosoftEntra IdentityProviderType = "microsoft"
	GitHub         IdentityProviderType = "github"
)

// OAuth2ClientList is a typed list of frontend clients.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OAuth2ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2Client `json:"items"`
}

// OAuth2Client describes an oauth2 client.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="redirect uri",type="string",JSONPath=".spec.redirectUri"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OAuth2Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OAuth2ClientSpec   `json:"spec"`
	Status            OAuth2ClientStatus `json:"status,omitempty"`
}

// OAuth2ClientSpec defines the required configuration for the client.
type OAuth2ClientSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// RedirectURI is the URI to pass control back to the client.
	RedirectURI string `json:"redirectUri"`
	// HomeURI is a URI to pass control to get to the console.
	HomeURI *string `json:"homeUri,omitempty"`
	// LoginURI is a URI to pass control to for login dialogs.
	LoginURI *string `json:"loginUri,omitempty"`
	// ErrorURI is a URI to pass control to for error dialogs.
	ErrorURI *string `json:"errorUri,omitempty"`
}

// OAuth2ClientStatus defines the status of the client.
type OAuth2ClientStatus struct {
}

// OAuth2ProviderList is a typed list of backend servers.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OAuth2ProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2Provider `json:"items"`
}

// OAuth2Provider describes an oauth2 provider.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="issuer",type="string",JSONPath=".spec.issuer"
// +kubebuilder:printcolumn:name="client ID",type="string",JSONPath=".spec.clientID"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OAuth2Provider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OAuth2ProviderSpec   `json:"spec"`
	Status            OAuth2ProviderStatus `json:"status,omitempty"`
}

// OAuth2ProviderSpec defines the required configuration for an oauth2
// provider.
type OAuth2ProviderSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Type defines the interface to use with the provider, specifically
	// how to retrieve group information for fine-grained RBAC.  For certain
	// global provider types e.g. Google or Microsoft, only a single instance
	// of that type should be specified, doing otherwise will result in
	// undefined behaviour.
	Type *IdentityProviderType `json:"type,omitempty"`
	// The issuer is typically provided by the identity provider as an
	// OIDC discovery endpoint e.g. https://accounts.google.com.
	// This will be used to verify issued JWTs have the same "iss" claim.
	Issuer string `json:"issuer"`
	// ClientID is the assigned client identifier.
	ClientID string `json:"clientID"`
	// ClientSecret is created by the IdP for token exchange.
	ClientSecret string `json:"clientSecret,omitempty"`
	// AuthorizationURI is used when OIDC (discovery) is not available.
	AuthorizationURI *string `json:"authorizatonURI,omitempty"`
	// TokenURI is used when OIDC (discovery) is not available.
	TokenURI *string `json:"tokenURI,omitempty"`
}

// OAuth2ProviderStatus defines the status of the server.
type OAuth2ProviderStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type RoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Role `json:"items"`
}

// Role defines a role type that forms the basis of RBAC.  Permissions are
// applied to arbitrary scopes that are used by individual components to
// allow or prevent API access.  Roles are additive, so effective RBAC
// permssions should be create from the boolean union for any roles that apply
// to a user.  Roles can optionally be scoped to an organization to allow
// deep customization of roles and permissions within that organization, for
// example the system management organization may have an onboarding role that
// allows basic account creation before handing off to the user.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RoleSpec   `json:"spec"`
	Status            RoleStatus `json:"status,omitempty"`
}

// RoleSpec defines the role's requested state.
type RoleSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Scopes are a list of uniquely named scopes for the role.
	Scopes RoleScopes `json:"scopes,omitempty"`
}

type RoleScopes struct {
	// Global grants access to any resource anywhere.
	// +listType=map
	// +listMapKey=name
	Global []RoleScope `json:"global,omitempty"`
	// Organization grants access to the user across the organization and
	// implicitly any project in the organization.
	// +listType=map
	// +listMapKey=name
	Organization []RoleScope `json:"organization,omitempty"`
	// Project grants access to the user for projects linked to groups
	// that contain them.
	// +listType=map
	// +listMapKey=name
	Project []RoleScope `json:"project,omitempty"`
}

type RoleScope struct {
	// Name is a unique name that applies to the scope.  Individual APIs should
	// coordinate with one another to avoid clashes and privilege escallation.
	Name string `json:"name"`
	// Operations defines a set of CRUD permissions for the scope.
	// +listType=set
	Operations []Operation `json:"operations,omitempty"`
}

// +kubebuilder:validation:Enum=create;read;update;delete
type Operation string

const (
	Create Operation = "create"
	Read   Operation = "read"
	Update Operation = "update"
	Delete Operation = "delete"
)

// RoleStatus defines any role status information.
type RoleStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type SigningKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SigningKey `json:"items"`
}

// SigningKey is a circular buffer of signing keys used to atomically process
// key rotations, and ensure issued tokens can be verified even after a key rotation.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
type SigningKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SigningKeySpec   `json:"spec"`
	Status            SigningKeyStatus `json:"status,omitempty"`
}

type SigningKeySpec struct {
	// PrivateKeys is an ordered list of private keys, the first is
	// the most recent, so essentially a FIFO queue.
	PrivateKeys []PrivateKey `json:"privateKeys,omitempty"`
}

type PrivateKey struct {
	// PEM is the PEM encded private key.
	PEM []byte `json:"pem,omitempty"`
}

type SigningKeyStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

// User represents an entity with a federated login credential.  Users are
// scoped to an organization, and may exist in multiple organizations
// at once.  At least one user must be in the "active" state to allow
// authentication.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="subject",type="string",JSONPath=".spec.subject"
// +kubebuilder:printcolumn:name="state",type="string",JSONPath=".spec.state"
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              UserSpec   `json:"spec"`
	Status            UserStatus `json:"status,omitempty"`
}

// UserState describes the state a user is in.
type UserState string

const (
	// UserStateActive means the user can authenticate.
	UserStateActive UserState = "active"
	// UserStatePending means the user is registered with the system
	// but needs to complete some onboarding action e.g. security checks.
	UserStatePending UserState = "pending"
	// UserStateSuspended means the user is not allowed to authenticate.
	// But is still alive to maintain foreign key mappings e.g. groups.
	UserStateSuspended UserState = "suspended"
)

type UserSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// Subject is usually and email address, sadly this cannot be made
	// a label for selection that way.  This will map to the subject in
	// a JWT.
	Subject string `json:"subject"`
	// State controls what the user is allowed to do.
	State UserState `json:"state"`
	// LastActive is updated when the user last requested an access token.
	LastActive *metav1.Time `json:"lastActive,omitempty"`
	// Signup is set when the user is being verified.
	Signup *UserSignup `json:"signup,omitempty"`
}

type UserSignup struct {
	// Token is used to store a time limited one use sign-up token
	// in order to transition from the pending to active state.  It typically
	// involves an email to notify the user they have been added.
	Token string `json:"token"`
	// ClientID remembers the oauth2 client that added the user in the first
	// place so that we can link to per-client email templates and error
	// handling dialogs.
	ClientID string `json:"clientID"`
}

type UserStatus struct {
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ServiceAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceAccount `json:"items"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".metadata.labels['unikorn-cloud\\.org/name']"
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
type ServiceAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ServiceAccountSpec   `json:"spec"`
	Status            ServiceAccountStatus `json:"status,omitempty"`
}

type ServiceAccountSpec struct {
	// Tags are aribrary user data.
	Tags unikornv1core.TagList `json:"tags,omitempty"`
	// AccessToken is the encrypted access token that is valid for this
	// service acocunt.
	AccessToken string `json:"accessToken"`
	// Expiry is a hint as to when the issued token will exipre.
	// The access token itself is the source of truth, provided the private key is
	// still around, so this is a fallback, as well as a cache to improve API read
	// performance by avoiding the decryption.
	Expiry *metav1.Time `json:"expiry"`
}

type ServiceAccountStatus struct {
}
