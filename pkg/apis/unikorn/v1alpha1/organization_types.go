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

package v1alpha1

import (
	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OrganizationList is a typed list of identity mappings.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OrganizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Organization `json:"items"`
}

// Organization describes an identity mapping.  The main job of this type
// is to take an email address identity, extract the domain and use it to
// resolve an identity provider.  It also is the place where users within
// that domain can be allowed based on groups/claims offered by that identity
// provider to limit access.
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,categories=unikorn
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="domain",type="string",JSONPath=".spec.domain"
// +kubebuilder:printcolumn:name="provider",type="string",JSONPath=".spec.providerName"
// +kubebuilder:printcolumn:name="age",type="date",JSONPath=".metadata.creationTimestamp"
type Organization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OrganizationSpec   `json:"spec"`
	Status            OrganizationStatus `json:"status,omitempty"`
}

// OrganizationSpec defines the required configuration for the server.
type OrganizationSpec struct {
	// Pause, if true, will inhibit reconciliation.
	Pause bool `json:"pause,omitempty"`
	// Domain is used by unikorn-identity to map an end-user provided
	// email address to an identity provider.
	Domain *string `json:"domain,omitempty"`
	// ProviderName is the name of an explicit oauth2/oidc provider.
	// When using a domain mapping.
	ProviderName *string `json:"providerName,omitempty"`
	// ProviderOptions is the configuration for a specific provider type.
	// When using domain mapping.
	ProviderOptions *OrganizationProviderOptions `json:"providerOptions,omitempty"`
	// Groups defines the set of groups that are allowed to be mapped
	// from the identity provider into unikorn.  If no groups are specified
	// then it is assumed all users have access to everything.
	Groups []OrganizationGroup `json:"groups,omitempty"`
}

type OrganizationProviderOptions struct {
	// If the referenced provider is set to "google" then the following
	// parameters should be specified.
	Google *OrganizationProviderGoogleSpec `json:"google,omitempty"`
}

type OrganizationProviderGoogleSpec struct {
	// CustomerID is retrieved from the "Account Settings > Profile" page on
	// https://admin.google.com for your organisation and is required to
	// lookup user groups for fine-grained RBAC.
	CustomerID string `json:"customerId"`
}

type OrganizationGroup struct {
	// ID is the a unique, and immutable identifier for the group, the intent
	// being that resources will belong to a group irrespective of display name
	// changes.
	ID string `json:"id"`
	// Name is the name to display the group as in UIs and other UX
	// interfaces.  This should again be unique within the organization to
	// avoid ambiguity, but may be changed.
	Name string `json:"name"`
	// ProviderName is the name of the group as returned by the provider.
	// For example a query of https://cloudidentity.googleapis.com/v1/groups/
	// will return something like groups/01664s551ax43ok.
	ProviderGroupNames []string `json:"providerGroupNames,omitempty"`
	// Users are a list of user names that are members of the group.
	Users []string `json:"users,omitempty"`
	// Roles are a list of roles users of the group inherit.
	Roles []string `json:"roles,omitempty"`
}

// OrganizationStatus defines the status of the server.
type OrganizationStatus struct {
	// Namespace defines the namespace an organization's child resources reside in.
	Namespace string `json:"namespace,omitempty"`

	// Current service state of the resource.
	Conditions []unikornv1core.Condition `json:"conditions,omitempty"`
}
