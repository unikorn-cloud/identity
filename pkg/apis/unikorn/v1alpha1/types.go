/*
Copyright 2022-2024 EscherCloud.

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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OAuth2ClientList is a typed list of control planes.
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type OAuth2ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OAuth2Client `json:"items"`
}

// OAuth2Client is an abstraction around resource provisioning, for example
// it may contain a provider like Cluster API that can provision KubernetesCluster
// resources.
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

// OAuth2ClientSpec defines any control plane specific options.
type OAuth2ClientSpec struct {
	ID          string `json:"id"`
	RedirectURI string `json:"redirectUri"`
}

// OAuth2ClientStatus defines the status of the project.
type OAuth2ClientStatus struct {
}
