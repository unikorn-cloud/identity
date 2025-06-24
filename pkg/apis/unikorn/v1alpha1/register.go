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

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

const (
	// APIGroupName is the Kubernetes API group our resources belong to.
	APIGroupName = "identity.unikorn-cloud.org"
	// APIGroupVersion is the version of our custom resources.
	APIGroupVersion = "v1alpha1"
	// Group is group/version of our resources.
	APIGroup = APIGroupName + "/" + APIGroupVersion
)

var (
	// SchemeGroupVersion defines the GV of our resources.
	//nolint:gochecknoglobals
	SchemeGroupVersion = schema.GroupVersion{Group: APIGroupName, Version: APIGroupVersion}

	// SchemeBuilder creates a mapping between GVK and type.
	//nolint:gochecknoglobals
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}

	// AddToScheme adds our GVK to resource mappings to an existing scheme.
	//nolint:gochecknoglobals
	AddToScheme = SchemeBuilder.AddToScheme
)

//nolint:gochecknoinits
func init() {
	SchemeBuilder.Register(&OAuth2Client{}, &OAuth2ClientList{})
	SchemeBuilder.Register(&OAuth2Provider{}, &OAuth2ProviderList{})
	SchemeBuilder.Register(&Role{}, &RoleList{})
	SchemeBuilder.Register(&Organization{}, &OrganizationList{})
	SchemeBuilder.Register(&Group{}, &GroupList{})
	SchemeBuilder.Register(&Project{}, &ProjectList{})
	SchemeBuilder.Register(&SigningKey{}, &SigningKeyList{})
	SchemeBuilder.Register(&User{}, &UserList{})
	SchemeBuilder.Register(&OrganizationUser{}, &OrganizationUserList{})
	SchemeBuilder.Register(&ServiceAccount{}, &ServiceAccountList{})
	SchemeBuilder.Register(&QuotaMetadata{}, &QuotaMetadataList{})
	SchemeBuilder.Register(&Quota{}, &QuotaList{})
	SchemeBuilder.Register(&Allocation{}, &AllocationList{})
	SchemeBuilder.Register(&SystemAccount{}, &SystemAccountList{})
}

// Resource maps a resource type to a group resource.
func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}
