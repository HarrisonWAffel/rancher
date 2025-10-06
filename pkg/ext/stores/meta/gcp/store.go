package gcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/rancher/rancher/pkg/api/norman/customization/gke"
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/rancher/pkg/ext/stores/meta"
	ctrlv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/wrangler"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/rest"
)

const (
	SingularName = "gcpmetarequest"
	kind         = "GCPMetaRequest"
)

var (
	_ rest.Creater                  = &Store{}
	_ rest.Storage                  = &Store{}
	_ rest.Scoper                   = &Store{}
	_ rest.SingularNameProvider     = &Store{}
	_ rest.GroupVersionKindProvider = &Store{}
)

var GVK = ext.SchemeGroupVersion.WithKind(kind)

// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false

type Store struct {
	userCache   ctrlv3.UserCache
	secretCache v1.SecretCache
	authorizer  authorizer.Authorizer
}

// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false

func New(wCtx *wrangler.Context, auth authorizer.Authorizer) *Store {
	return &Store{
		userCache:   wCtx.Mgmt.User().Cache(),
		secretCache: wCtx.Core.Secret().Cache(),
		authorizer:  auth,
	}
}

// GroupVersionKind implements [rest.GroupVersionKindProvider], a required interface.
func (s *Store) GroupVersionKind(_ schema.GroupVersion) schema.GroupVersionKind {
	return GVK
}

// NamespaceScoped implements [rest.Scoper], a required interface.
func (s *Store) NamespaceScoped() bool {
	return false
}

// GetSingularName implements [rest.SingularNameProvider], a required interface.
func (s *Store) GetSingularName() string {
	return SingularName
}

// New implements [rest.Storage], a required interface.
func (s *Store) New() runtime.Object {
	return &ext.GCPMetaRequest{}
}

// Destroy implements [rest.Storage], a required interface.
func (s *Store) Destroy() {
}

// Create implements [rest.Creator], the interface to support the `create`
// verb. Delegates to the actual store method after some generic boilerplate.
func (s *Store) Create(
	ctx context.Context,
	obj runtime.Object,
	_ rest.ValidateObjectFunc,
	_ *metav1.CreateOptions) (runtime.Object, error) {

	gcp, ok := obj.(*ext.GCPMetaRequest)
	if !ok {
		return obj, fmt.Errorf("failed to convert object to meta request")
	}

	// Ensure that the user has GET access to the specified cloud credential.
	cc, err := meta.GetCloudCredential(ctx, meta.CommonArgs{
		Auth:              s.authorizer,
		UserCache:         s.userCache,
		SecretCache:       s.secretCache,
		CloudCredentialID: gcp.Spec.CloudCredentialID,
	})
	if err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	capa, err := s.BuildCapabilities(cc, gcp)
	if err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	if gcp.Spec.ListMachineTypes {
		resp, status, err := gke.ListMachineTypes(ctx, &capa)
		if err != nil {
			gcp.Status.MachineTypesResponse.Error = err.Error()
		}
		gcp.Status.MachineTypesResponse.ResponseValue = string(resp)
		gcp.Status.MachineTypesResponse.ResponseCode = status
	}

	if gcp.Spec.ListNetworks {
		resp, status, err := gke.ListNetworks(ctx, &capa)
		if err != nil {
			gcp.Status.NetworksResponse.Error = err.Error()
		}
		gcp.Status.NetworksResponse.ResponseValue = string(resp)
		gcp.Status.NetworksResponse.ResponseCode = status
	}

	if gcp.Spec.ListSubnetworks {
		resp, status, err := gke.ListSubnetworks(ctx, &capa)
		if err != nil {
			gcp.Status.SubnetworksResponse.Error = err.Error()
		}
		gcp.Status.SubnetworksResponse.ResponseValue = string(resp)
		gcp.Status.SubnetworksResponse.ResponseCode = status
	}

	if gcp.Spec.ListServiceAccounts {
		resp, status, err := gke.ListServiceAccounts(ctx, &capa)
		if err != nil {
			gcp.Status.ServiceAccountsResponse.Error = err.Error()
		}
		gcp.Status.ServiceAccountsResponse.ResponseValue = string(resp)
		gcp.Status.ServiceAccountsResponse.ResponseCode = status
	}

	if gcp.Spec.ListVersions {
		resp, status, err := gke.ListVersions(ctx, &capa)
		if err != nil {
			gcp.Status.VersionsResponse.Error = err.Error()
		}
		gcp.Status.VersionsResponse.ResponseValue = string(resp)
		gcp.Status.VersionsResponse.ResponseCode = status
	}

	if gcp.Spec.ListZones {
		resp, status, err := gke.ListZones(ctx, &capa)
		if err != nil {
			gcp.Status.ZonesResponse.Error = err.Error()
		}
		gcp.Status.ZonesResponse.ResponseValue = string(resp)
		gcp.Status.ZonesResponse.ResponseCode = status
	}

	if gcp.Spec.ListClusters {
		resp, status, err := gke.ListClusters(ctx, &capa)
		if err != nil {
			gcp.Status.ClustersResponse.Error = err.Error()
		}
		gcp.Status.ClustersResponse.ResponseValue = string(resp)
		gcp.Status.ClustersResponse.ResponseCode = status
	}

	if gcp.Spec.ListSharedSubnets {
		resp, status, err := gke.ListSharedSubnets(ctx, &capa)
		if err != nil {
			gcp.Status.SharedSubnetsResponse.Error = err.Error()
		}
		gcp.Status.SharedSubnetsResponse.ResponseValue = string(resp)
		gcp.Status.SharedSubnetsResponse.ResponseCode = status
	}

	if gcp.Spec.ListDiskTypes {
		resp, status, err := gke.ListDiskTypes(ctx, &capa)
		if err != nil {
			gcp.Status.DiskTypesResponse.Error = err.Error()
		}
		gcp.Status.DiskTypesResponse.ResponseValue = string(resp)
		gcp.Status.DiskTypesResponse.ResponseCode = status
	}

	if gcp.Spec.ListFamiliesFromProject != nil {
		projects := strings.Join(gcp.Spec.ListFamiliesFromProject.Projects, ",")
		showDep := gcp.Spec.ListFamiliesFromProject.ShowDeprecated
		resp, status, err := gke.ListFamiliesFromProject(ctx, &capa, projects, showDep)
		if err != nil {
			gcp.Status.FamiliesFromProjectResponse.Error = err.Error()
		}
		gcp.Status.FamiliesFromProjectResponse.ResponseValue = string(resp)
		gcp.Status.FamiliesFromProjectResponse.ResponseCode = status
	}

	if gcp.Spec.ListImageFamilyForProject != nil {
		imgProj := gcp.Spec.ListImageFamilyForProject.ImageProject
		imgFam := gcp.Spec.ListImageFamilyForProject.ImageFamilies
		showDep := gcp.Spec.ListImageFamilyForProject.ShowDeprecated
		resp, statuscode, err := gke.ListImageFamilyForProject(ctx, &capa, imgProj, imgFam, showDep)
		if err != nil {
			gcp.Status.ImageFamilyForProjectResponse.Error = err.Error()
		}
		gcp.Status.ImageFamilyForProjectResponse.ResponseValue = string(resp)
		gcp.Status.ImageFamilyForProjectResponse.ResponseCode = statuscode
	}

	return gcp, nil
}

func (s *Store) BuildCapabilities(cc *corev1.Secret, req *ext.GCPMetaRequest) (gke.Capabilities, error) {
	authString := string(cc.Data["googlecredentialConfig-authEncodedJson"])
	if authString == "" {
		return gke.Capabilities{}, fmt.Errorf("invalid cloud credential contents")
	}

	return gke.Capabilities{
		Credentials: authString,
		ProjectID:   req.Spec.Project,
		Zone:        req.Spec.Zone,
		Region:      req.Spec.Region,
	}, nil
}
