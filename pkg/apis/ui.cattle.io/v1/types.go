package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// +genclient
// +kubebuilder:skipversion
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type NavLink struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NavLinkSpec `json:"spec"`
}

type NavLinkSpec struct {
	Label       string                `json:"label,omitempty"`
	Description string                `json:"description,omitempty"`
	SideLabel   string                `json:"sideLabel,omitempty"`
	IconSrc     string                `json:"iconSrc,omitempty"`
	Group       string                `json:"group,omitempty"`
	Target      string                `json:"target,omitempty"`
	ToURL       string                `json:"toURL,omitempty"`
	ToService   *NavLinkTargetService `json:"toService,omitempty"`
}

type NavLinkTargetService struct {
	Namespace string              `json:"namespace,omitempty" wrangler:"required"`
	Name      string              `json:"name,omitempty" wrangler:"required"`
	Scheme    string              `json:"scheme,omitempty" wrangler:"default=http,options=http|https,type=enum"`
	Port      *intstr.IntOrString `json:"port,omitempty"`
	Path      string              `json:"path,omitempty"`
}

// +genclient
// +kubebuilder:resource:scope=Cluster
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type ProxyEndpointCollection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ProxyEndpointCollectionSpec `json:"spec,omitempty"`
}

type ProxyEndpointCollectionSpec struct {
	// +required
	SourceID string `json:"sourceID,omitempty"`
	// +required
	Endpoints []ProxyEndpointSet `json:"endpoints,omitempty"`
}

type ProxyEndpointSet struct {
	// +required
	Name string `json:"name,omitempty"`
	// +required
	Endpoints []Endpoint `json:"endpoint,omitempty"`
}

type Endpoint struct {
	// +required
	UrlPattern string `json:"urlpattern,omitempty"`

	// +optional
	DenyAccess bool

	// +optional
	AllowedCredentials []ProxyEndpointCredentialType `json:"allowedCredentials,omitempty"`

	// +optional
	Certificates string `json:"certificates,omitempty"`

	// +optional
	InjectionDetails ProxyEndpointInjectionDetails `json:"injectionDetails,omitempty"`
}

type ProxyEndpointCredentialType struct {
	// something like amazonec2credentialconfig I guess
	// this field HEAVILY depends on the CC public API stuff and
	// the related security issue (that I have no information about T_T)
	// +required
	AllowedSchema string `json:"allowedSchema,omitempty"`
	// determines if a field must be populated in order for the
	// request to proceed
	// +required
	RequiredFields []string `json:"requiredFields,omitempty"`
}

type ProxyEndpointInjectionDetails struct {
	// +optional
	AllowedHeaders []string `json:"allowedHeaders,omitempty"`
	// +optional
	BodyInjectionRules []ProxyEndpointBodyRule `json:"bodyInjectionRules,omitempty"`
}

type ProxyEndpointBodyRule struct {
	// ContentType denotes that the following body paths
	// should only be respected when working with a specific
	// request body content type. If empty, this is assumed to be
	// JSON.
	// +optional
	ContentType string `json:"contentType,omitempty"`
	// BodyPaths is a slice of ContentType specific
	// notation that specifies where in a request body
	// templating can take place.
	//
	// For JSON request bodies, this is expected to be a slice of
	// strings which adhere to the JSONPath specification.
	// +optional
	Paths []string `json:"paths,omitempty"`
}
