package v1

import (
	"github.com/rancher/wrangler/v3/pkg/genericcondition"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
)

type RKECommonNodeConfig struct {
	Labels                    map[string]string `json:"labels,omitempty"`
	Taints                    []corev1.Taint    `json:"taints,omitempty"`
	CloudCredentialSecretName string            `json:"cloudCredentialSecretName,omitempty"`
}

type RKEMachineStatus struct {
	Conditions                []genericcondition.GenericCondition `json:"conditions,omitempty"`
	JobName                   string                              `json:"jobName,omitempty"`
	Ready                     bool                                `json:"ready,omitempty"`
	DriverHash                string                              `json:"driverHash,omitempty"`
	DriverURL                 string                              `json:"driverUrl,omitempty"`
	CloudCredentialSecretName string                              `json:"cloudCredentialSecretName,omitempty"`
	FailureReason             string                              `json:"failureReason,omitempty"`
	FailureMessage            string                              `json:"failureMessage,omitempty"`
	Addresses                 []capi.MachineAddress               `json:"addresses,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced

// CustomMachine represents an unmanaged CAPI
// machine registered to a Rancher custom cluster.
type CustomMachine struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Status represents the most recently observed status of the machine.
	// +optional
	Status CustomMachineStatus `json:"status,omitempty"`

	// Spec represents the desired configuration of the machine.
	// +optional
	Spec CustomMachineSpec `json:"spec,omitempty"`
}

type CustomMachineSpec struct {
	// ProviderID is a reference to the CAPI node object corresponding to
	// this machine. This field is automatically set by CAPI during the
	// machine provisioning process.
	// +optional
	ProviderID string `json:"providerID,omitempty"`
}

type CustomMachineStatus struct {
	// Conditions is a representation of the current state of the machine.
	// +optional
	Conditions []genericcondition.GenericCondition `json:"conditions,omitempty"`
	// Ready indicates that the machine infrastructure is fully provisioned.
	// This is automatically set when the CAPI ProviderID field is populated
	// by the core CAPI controllers. The value of this field is not
	// updated after it has been set.
	// +optional
	Ready bool `json:"ready,omitempty"`
	// Addresses contains the associated addresses for the machine.
	// +optional
	Addresses []capi.MachineAddress `json:"addresses,omitempty"`
}
