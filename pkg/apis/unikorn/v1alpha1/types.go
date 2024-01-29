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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
// +kubebuilder:printcolumn:name="display name",type="string",JSONPath=".spec.displayName"
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
	// HumanReadableName is a user readable issuer name.
	HumanReadableName string `json:"displayName"`
	// The issuer is typically provided by the identity provider as an
	// OIDC discovery endpoint e.g. https://accounts.google.com.
	// This will be used to verify issued JWTs have the same "iss" claim.
	Issuer string `json:"issuer"`
	// ClientID is the assigned client identifier.
	ClientID string `json:"clientID"`
	// ClientSecret is created by the IdP for token exchange.
	ClientSecret string `json:"clientSecret"`
}

// OAuth2ProviderStatus defines the status of the server.
type OAuth2ProviderStatus struct {
}

// OAuth2MappingList is a typed list of identity mappings.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OAuth2MappingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2Mapping `json:"items"`
}

// OAuth2Mapping describes an identity mapping.  The main job of this type
// is to take an email address identity, extract the domain and use it to
// resolve an identity provider.  It also is the place where users within
// that domain can be allowed based on groups/claims offered by that identity
// provider to limit access.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:printcolumn:name="domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="provider",type="string",JSONPath=".spec.providerName"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type OAuth2Mapping struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OAuth2MappingSpec   `json:"spec"`
	Status            OAuth2MappingStatus `json:"status,omitempty"`
}

// OAuth2MappingSpec defines the required configuration for the server.
type OAuth2MappingSpec struct {
	// Domain is used by unikorn-identity to map an end-user provided
	// email address to an identity provider.
	Domain string `json:"domain"`
	// ProviderName is the name of an oauth2/oidc provider.
	ProviderName string `json:"providerName"`
}

// OAuth2MappingStatus defines the status of the server.
type OAuth2MappingStatus struct {
}
