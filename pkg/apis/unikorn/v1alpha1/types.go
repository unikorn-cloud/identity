/*
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

//nolint:tagliatelle
package v1alpha1

import (
	"github.com/unikorn-cloud/core/pkg/authorization/constants"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// IdentityProviderType defines the type of identity provider, and in turn
// that defines the required configuration and API interfaces.
// +kubebuilder:validation:Enum=custom;google;microsoft
type IdentityProviderType string

const (
	GoogleIdentity IdentityProviderType = "google"
	MicrosoftEntra IdentityProviderType = "microsoft"
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
// +kubebuilder:printcolumn:name="client id",type="string",JSONPath=".spec.id"
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
	// ID uniquely identifes the client.
	ID string `json:"id"`
	// RedirectURI is the URI to pass control back to the client.
	RedirectURI string `json:"redirectUri"`
	// LoginURI is a URI to pass control to for login dialogs.
	LoginURI *string `json:"loginUri,omitempty"`
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
	ClientSecret *string `json:"clientSecret,omitempty"`
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
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Role struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RoleSpec   `json:"spec"`
	Status            RoleStatus `json:"status,omitempty"`
}

// RoleSpec defines the role's requested state.
type RoleSpec struct {
	// IsDefault indicates that all authenticated users are granted
	// the following scopes regardless of organizational group membership
	// and typically are required for organization discovery and RBAC functionality
	// in the first instance.
	IsDefault bool `json:"isDefault,omitempty"`
	// Scopes are a list of uniquely named scopes for the role.
	// +listType=map
	// +listMapKey=name
	Scopes []RoleScope `json:"scopes,omitempty"`
}

type RoleScope struct {
	// Name is a unique name that applies to the scope.  Individual APIs should
	// coordinate with one another to avoid clashes and privilege escallation.
	Name string `json:"name"`
	// Permissions defines a set of CRUD permissions for the scope.
	// +listType=set
	Permissions []constants.Permission `json:"permissions,omitempty"`
}

// RoleStatus defines any role status information.
type RoleStatus struct {
}
