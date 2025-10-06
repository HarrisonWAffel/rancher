// +kubebuilder:skip
package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GCP / GKE Resource example

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type GCPMetaRequest struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object metadata; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +optional
	Spec GCPMetaSpec `json:"spec,omitempty"`
	// +optional
	Status GCPMetaStatus `json:"status,omitempty"`
}

type GCPMetaSpec struct {
	CloudCredentialID string `json:"cloudCredentialID"`
	// +optional
	Project string `json:"project,omitempty"`
	// +optional
	Zone string `json:"zone,omitempty"`
	// +optional
	Region string `json:"region,omitempty"`
	// +optional
	ListMachineTypes bool `json:"listMachineTypes,omitempty"`
	// +optional
	ListNetworks bool `json:"listNetworks,omitempty"`
	// +optional
	ListSubnetworks bool `json:"listSubnetworks,omitempty"`
	// +optional
	ListServiceAccounts bool `json:"listServiceAccounts,omitempty"`
	// +optional
	ListVersions bool `json:"listVersions,omitempty"`
	// +optional
	ListZones bool `json:"listZones,omitempty"`
	// +optional
	ListClusters bool `json:"listClusters,omitempty"`
	// +optional
	ListSharedSubnets bool `json:"listSharedSubnets,omitempty"`
	// +optional
	ListDiskTypes bool `json:"listDiskTypes,omitempty"`
	// +optional
	ListFamiliesFromProject *ListFamiliesFromProject `json:"listFamiliesFromProject,omitempty"`
	// +optional
	ListImageFamilyForProject *ListImageFamilyForProject `json:"listImageFamilyForProject,omitempty"`
}

type ListFamiliesFromProject struct {
	Projects []string `json:"projects,omitempty"`
	// +optional
	ShowDeprecated bool `json:"showDeprecated,omitempty"`
}

type ListImageFamilyForProject struct {
	ImageProject  string `json:"imageProject,omitempty"`
	ImageFamilies string `json:"imageFamilies,omitempty"`
	// +optional
	ShowDeprecated bool `json:"showDeprecated,omitempty"`
}

type GCPMetaStatus struct {
	Conditions []metav1.Condition `json:"conditions"`
	// +optional
	MachineTypesResponse MetaRequestResponse `json:"machineTypesResponse,omitempty"`
	// +optional
	NetworksResponse MetaRequestResponse `json:"networksResponse,omitempty"`
	// +optional
	SubnetworksResponse MetaRequestResponse `json:"subnetworksResponse,omitempty"`
	// +optional
	ServiceAccountsResponse MetaRequestResponse `json:"serviceAccountsResponse,omitempty"`
	// +optional
	VersionsResponse MetaRequestResponse `json:"versionsResponse,omitempty"`
	// +optional
	ZonesResponse MetaRequestResponse `json:"zonesResponse,omitempty"`
	// +optional
	ClustersResponse MetaRequestResponse `json:"clustersResponse,omitempty"`
	// +optional
	SharedSubnetsResponse MetaRequestResponse `json:"sharedSubnetsResponse,omitempty"`
	// +optional
	DiskTypesResponse MetaRequestResponse `json:"diskTypesResponse,omitempty"`
	// +optional
	FamiliesFromProjectResponse MetaRequestResponse `json:"familiesFromProjectResponse,omitempty"`
	// +optional
	ImageFamilyForProjectResponse MetaRequestResponse `json:"imageFamilyForProjectResponse,omitempty"`
}

type MetaRequestResponse struct {
	ResponseCode  int    `json:"responseCode,omitempty"`
	ResponseValue string `json:"responseValue,omitempty"`
	//+optional
	Error string `json:"error,omitempty"`
}
