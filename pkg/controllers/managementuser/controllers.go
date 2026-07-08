package managementuser

import (
	"context"
	"fmt"

	"github.com/k3s-io/api/pkg/generated/controllers/k3s.cattle.io"
	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/controllers/managementlegacy/compose/common"
	"github.com/rancher/rancher/pkg/controllers/managementuser/cavalidator"
	"github.com/rancher/rancher/pkg/controllers/managementuser/clusterauthtoken"
	"github.com/rancher/rancher/pkg/controllers/managementuser/healthsyncer"
	"github.com/rancher/rancher/pkg/controllers/managementuser/machinerole"
	"github.com/rancher/rancher/pkg/controllers/managementuser/networkpolicy"
	"github.com/rancher/rancher/pkg/controllers/managementuser/nodesyncer"
	"github.com/rancher/rancher/pkg/controllers/managementuser/nsserviceaccount"
	"github.com/rancher/rancher/pkg/controllers/managementuser/rbac"
	"github.com/rancher/rancher/pkg/controllers/managementuser/resourcequota"
	"github.com/rancher/rancher/pkg/controllers/managementuser/rkecontrolplanecondition"
	"github.com/rancher/rancher/pkg/controllers/managementuser/secret"
	"github.com/rancher/rancher/pkg/controllers/managementuser/snapshotbackpopulate"
	"github.com/rancher/rancher/pkg/controllers/managementuser/windows"
	"github.com/rancher/rancher/pkg/controllers/managementuserlegacy"
	"github.com/rancher/rancher/pkg/features"
	"github.com/rancher/rancher/pkg/generated/controllers/upgrade.cattle.io"
	nv3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/impersonation"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/wrangler"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
)

func Register(ctx context.Context, mgmt *config.ScaledContext, cluster *config.UserContext, clusterRec *apimgmtv3.Cluster, kubeConfigGetter common.KubeConfigGetter) error {
	if err := rbac.Register(ctx, cluster); err != nil {
		return err
	}
	healthsyncer.Register(ctx, cluster)
	networkpolicy.Register(ctx, cluster)

	secret.Register(ctx, mgmt, cluster, clusterRec)
	resourcequota.Register(ctx, cluster)
	windows.Register(ctx, clusterRec, cluster)
	nsserviceaccount.Register(ctx, cluster)

	// For the local cluster, register nodesyncer immediately without waiting for CAPI.
	// The nodesyncer can work without CAPI for the local cluster since
	// isClusterRestoring() is skipped for local clusters (see nodessyncer.go:reconcileAll).
	// For other clusters, we still need to wait for CAPI to be ready because both the node syncer
	// and the controllers within 'registerProvV2' rely on CAPI resources.
	if cluster.ClusterName == "local" {
		// DeferredStartWithError is used in both cases to generate a stateful controller starter function, which is then
		// invoked using dedicated onChange controllers. This ensures that transient network errors encountered when
		// contacting the downstream cluster which prevent the registration from initially succeeding
		// will be retried via controller backoff + resync.
		starter := cluster.DeferredStartWithError(ctx, func(ctx context.Context) error {
			nodesyncer.Register(ctx, cluster, nil, kubeConfigGetter)
			return nil
		})
		cluster.Management.Management.Clusters("").AddHandler(ctx, "local-deferred-node-syncer-start",
			func(key string, obj *nv3.Cluster) (runtime.Object, error) {
				if obj == nil || obj.Name != cluster.ClusterName {
					return obj, nil
				}
				err := starter()
				if err != nil {
					logrus.Errorf("[STARTER-ERROR] Error starting node sync controllers for local cluster: %v", err)
				}
				return obj, err
			})
	}

	mgmt.Wrangler.DeferredCAPIRegistration.DeferFunc(func(capi *wrangler.CAPIContext) {
		starter := cluster.DeferredStartWithError(ctx, func(ctx context.Context) error {
			// For non-local clusters, register nodesyncer with CAPI context
			if cluster.ClusterName != "local" {
				nodesyncer.Register(ctx, cluster, capi, kubeConfigGetter)
			}
			registerProvV2(ctx, cluster, capi, clusterRec)
			return nil
		})
		cluster.Management.Management.Clusters("").AddHandler(ctx, "user-controllers-capi-deferred-start-"+cluster.ClusterName,
			func(key string, obj *nv3.Cluster) (runtime.Object, error) {
				if obj == nil || obj.Name != cluster.ClusterName {
					return obj, nil
				}
				err := starter()
				if err != nil {
					logrus.Errorf("[STARTER-ERROR] Error starting provv2 controllers for cluster %s: %v", cluster.ClusterName, err)
				}
				return obj, err
			})
	})

	registerCaches(cluster)

	// early request an impersonator for initializing it
	if _, err := impersonation.ForCluster(cluster); err != nil {
		return fmt.Errorf("unable to create impersonator for cluster %q: %w", cluster.ClusterName, err)
	}

	if err := cavalidator.Register(ctx, cluster); err != nil {
		return err
	}

	// register controller for API
	cluster.APIAggregation.APIServices("").Controller()

	if clusterRec.Spec.LocalClusterAuthEndpoint.Enabled {
		err := clusterauthtoken.CRDSetup(ctx, cluster.RESTConfig, cluster.Management.Schemas)
		if err != nil {
			return err
		}
		secretsCache, err := clusterauthtoken.RegisterFactory(cluster)
		if err != nil {
			return fmt.Errorf("registering clusterauthtoken factory: %w", err)
		}
		clusterauthtoken.Register(ctx, cluster, secretsCache)
	}

	return managementuserlegacy.Register(ctx, mgmt, cluster, clusterRec, kubeConfigGetter)
}

func registerProvV2(ctx context.Context, cluster *config.UserContext, capi *wrangler.CAPIContext, clusterRec *apimgmtv3.Cluster) {
	if !features.RKE2.Enabled() {
		return
	}

	// Just register the snapshot controller if the cluster is administrated by rancher.
	if clusterRec.Annotations["provisioning.cattle.io/administrated"] == "true" {
		if features.Provisioningv2ETCDSnapshotBackPopulation.Enabled() {
			cluster.K3s = k3s.New(cluster.ControllerFactory)
			snapshotbackpopulate.Register(ctx, cluster, clusterRec)
		}
		cluster.Plan = upgrade.New(cluster.ControllerFactory)
		rkecontrolplanecondition.Register(ctx,
			cluster.ClusterName,
			cluster.Catalog.V1().App(),
			cluster.Management.Wrangler.RKE.RKEControlPlane())
	} else {
		if features.Provisioningv2ETCDSnapshotBackPopulation.Enabled() {
			resources, err := cluster.K8sClient.Discovery().ServerResourcesForGroupVersion("k3s.cattle.io/v1")
			if apierrors.IsNotFound(err) {
				logrus.Tracef("refusing to start snapshotbackpopulate controller for non RKE2/K3s cluster")
			} else if err != nil {
				logrus.Errorf("failed to find k3s server resources: %v", err)
			} else if resources == nil || len(resources.APIResources) == 0 {
				logrus.Tracef("skipping snapshotbackpopulate controller because k3s.cattle.io/v1 returned no resources")
			} else {
				found := false
				for _, resource := range resources.APIResources {
					if resource.Kind == "ETCDSnapshotFile" {
						cluster.K3s = k3s.New(cluster.ControllerFactory)
						snapshotbackpopulate.Register(ctx, cluster, clusterRec)
						found = true
						break
					}
				}
				if !found {
					logrus.Tracef("skipping snapshotbackpopulate controller because ETCDSnapshotFile is not served downstream")
				}
			}
		}
	}
	machinerole.Register(ctx, cluster)
}

func RegisterFollower(cluster *config.UserContext) error {
	registerCaches(cluster)

	// early request an impersonator for initializing it
	if _, err := impersonation.ForCluster(cluster); err != nil {
		return fmt.Errorf("unable to create impersonator for cluster %q: %w", cluster.ClusterName, err)
	}
	return nil
}

// registerCaches initializes caches early in the initialization process to have them available as soon as possible (instead of on demand when Lister/Cache or Controller are called)
func registerCaches(cluster *config.UserContext) {
	cluster.Corew.Namespace().Informer()
	cluster.RBACw.ClusterRoleBinding().Informer()
	cluster.RBACw.ClusterRole().Informer()
	cluster.RBACw.RoleBinding().Informer()
	cluster.RBACw.Role().Informer()
}

// PreBootstrap is a list of functions that _need_ to be run before the rest of the controllers start
// the functions should return an error if they fail, and the start of the controllers will be blocked until all of them succeed
func PreBootstrap(ctx context.Context, mgmt *config.ScaledContext, cluster *config.UserContext, clusterRec *apimgmtv3.Cluster, kubeConfigGetter common.KubeConfigGetter) error {
	if cluster.ClusterName == "local" {
		return nil
	}

	err := secret.Bootstrap(ctx, mgmt, cluster, clusterRec)
	if err != nil {
		return fmt.Errorf("failed to bootstrap secrets: %w", err)
	}

	return nil
}
