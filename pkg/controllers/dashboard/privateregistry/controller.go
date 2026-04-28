package privateregistry

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	util "github.com/rancher/rancher/pkg/cluster"
	"github.com/rancher/rancher/pkg/controllers/dashboard/clusterindex"
	"github.com/rancher/rancher/pkg/controllers/managementuser/secret"
	mgmtcontrollers "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	provisioningv1 "github.com/rancher/rancher/pkg/generated/controllers/provisioning.cattle.io/v1"
	namespaces "github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/rancher/rancher/pkg/wrangler"
	corecontrollers "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/relatedresource"
	"github.com/sirupsen/logrus"
	kcorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
)

type handler struct {
	settings                 mgmtcontrollers.SettingController
	secrets                  corecontrollers.SecretController
	secretCache              corecontrollers.SecretCache
	project                  mgmtcontrollers.ProjectController
	projectCache             mgmtcontrollers.ProjectCache
	mgmtCluster              mgmtcontrollers.ClusterController
	mgmtClusterCache         mgmtcontrollers.ClusterCache
	provisioningClusterCache provisioningv1.ClusterCache
}

const clusterToSysProjIndex = "mgmnt-system-project"

func Register(ctx context.Context, wContext *wrangler.Context) {
	h := &handler{
		settings:                 wContext.Mgmt.Setting(),
		secrets:                  wContext.Core.Secret(),
		secretCache:              wContext.Core.Secret().Cache(),
		project:                  wContext.Mgmt.Project(),
		projectCache:             wContext.Mgmt.Project().Cache(),
		mgmtCluster:              wContext.Mgmt.Cluster(),
		mgmtClusterCache:         wContext.Mgmt.Cluster().Cache(),
		provisioningClusterCache: wContext.Provisioning.Cluster().Cache(),
	}

	// maps cluster names to their system projects
	h.projectCache.AddIndexer(clusterToSysProjIndex, func(obj *v3.Project) ([]string, error) {
		if obj != nil && obj.ObjectMeta.Labels["authz.management.cattle.io/system-project"] == "true" {
			if obj.Spec.ClusterName == "" {
				return nil, fmt.Errorf("system project has empty cluster name")
			}
			return []string{obj.Spec.ClusterName}, nil
		}
		return []string{}, nil
	})

	h.settings.OnChange(ctx, "sync-source-secrets", h.labelSourceGlobalRegistryPullSecret)
	h.mgmtCluster.OnChange(ctx, "manage-system-project-pull-secret-label", h.labelSystemProject)
	h.mgmtCluster.OnChange(ctx, "manage-pss-downstream-clusters", h.manageImportedAndHostedClusterPSS)

	relatedresource.WatchClusterScoped(ctx, "sync-cluster-global-pull-secrets", func(namespace, name string, obj runtime.Object) ([]relatedresource.Key, error) {
		if name == settings.SystemDefaultRegistryPullSecrets.Name || name == settings.SystemDefaultRegistry.Name {
			clusters, err := h.mgmtClusterCache.List(labels.Everything())
			if err != nil {
				return nil, err
			}
			var clusterNames []relatedresource.Key
			for _, cluster := range clusters {
				_, isGlobalDefault := util.GetPrivateRegistry(cluster)
				if isGlobalDefault {
					continue
				}
				if util.MgmtNameRegexp.MatchString(cluster.Name) {
					clusterNames = append(clusterNames, relatedresource.Key{
						Name: cluster.Name,
					})
				}
			}
			return clusterNames, nil
		}
		return nil, nil
	}, wContext.Mgmt.Cluster(), wContext.Mgmt.Setting())
}

// labelSystemProject automatically adds the 'management.cattle.io/use-global-private-registry-pull-secret' label
// onto system projects associated with imported and hosted clusters which rely on the global system default
// registry pull secrets. This label is used throughout Rancher to ensure that those pull secrets are properly
// copied into the relevant namespaces in the local and downstream imported and hosted clusters.
func (h *handler) labelSystemProject(_ string, cluster *v3.Cluster) (*v3.Cluster, error) {
	if cluster == nil {
		return cluster, nil
	}

	logrus.Infof("[PRIVATE-REGISTRY] labelSystemProject invoked for cluster %q", cluster.Name)

	if !v3.ClusterConditionSystemProjectCreated.IsTrue(cluster) && !v3.ClusterConditionAgentDeployed.IsTrue(cluster) && cluster.Name != "local" {
		logrus.Infof("[PRIVATE-REGISTRY] cluster %q is not ready (systemProjectCreated=%v, agentDeployed=%v); skipping",
			cluster.Name,
			v3.ClusterConditionSystemProjectCreated.IsTrue(cluster),
			v3.ClusterConditionAgentDeployed.IsTrue(cluster))
		return cluster, nil
	}

	v1cluster, err := h.provisioningClusterCache.GetByIndex(clusterindex.ClusterV1ByClusterV3Reference, cluster.Name)
	if err != nil {
		logrus.Errorf("[PRIVATE-REGISTRY] failed to get v1 provisioning cluster for cluster %q: %v", cluster.Name, err)
		return cluster, err
	}

	if cluster.Name != "local" && len(v1cluster) == 0 {
		logrus.Infof("[PRIVATE-REGISTRY] no v1 provisioning cluster found for cluster %q; skipping", cluster.Name)
		return cluster, nil
	}

	// Don't do this for provisioned clusters, the creds will be passed via prov2 and the system-agent.
	// Skip this check for the local cluster, we already know its type without having to look at the v1 cluster
	// (and it's name won't match anyway)
	if cluster.Name != "local" && !util.MgmtNameRegexp.MatchString(cluster.Name) {
		logrus.Infof("[PRIVATE-REGISTRY] cluster %q is a provisioned cluster (not imported/hosted); skipping label management", cluster.Name)
		return cluster, nil
	}

	sysProj, found, err := h.getSystemProjectForCluster(cluster.Name)
	if err != nil {
		logrus.Errorf("[PRIVATE-REGISTRY] failed to get system project for cluster %q: %v", cluster.Name, err)
		return cluster, err
	}

	if !found {
		logrus.Infof("[PRIVATE-REGISTRY] no system project found for cluster %q; skipping", cluster.Name)
		return cluster, nil
	}

	logrus.Infof("[PRIVATE-REGISTRY] found system project %q for cluster %q", sysProj.Name, cluster.Name)

	// Do we need to use the global pull secrets for this system project?
	usesGlobalSecrets := sysProj.Labels[secret.NeedsGlobalPrivateRegistryPullSecret] == "true"
	registry, isGlobalDefault := util.GetPrivateRegistry(cluster)

	logrus.Infof("[PRIVATE-REGISTRY] cluster %q registry state: isGlobalDefault=%v, usesGlobalSecrets=%v, registryNil=%v",
		cluster.Name, isGlobalDefault, usesGlobalSecrets, registry == nil)

	// If pull secrets have been removed at the global level, or redefined at the cluster level, ensure the system project no longer requests them
	if ((registry == nil || len(registry.PullSecrets) == 0) && usesGlobalSecrets) || (!isGlobalDefault && usesGlobalSecrets) {
		logrus.Infof("[PRIVATE-REGISTRY] removing %q label from system project %q for cluster %q (pull secrets no longer applicable)",
			secret.NeedsGlobalPrivateRegistryPullSecret, sysProj.Name, cluster.Name)
		sysProj = sysProj.DeepCopy()
		delete(sysProj.Labels, secret.NeedsGlobalPrivateRegistryPullSecret)
		_, err = h.project.Update(sysProj)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to remove global pull secret label from system project %q for cluster %q: %v", sysProj.Name, cluster.Name, err)
			return cluster, err
		}
		logrus.Infof("[PRIVATE-REGISTRY] successfully removed global pull secret label from system project %q for cluster %q", sysProj.Name, cluster.Name)
		return cluster, nil
	}

	if isGlobalDefault && usesGlobalSecrets {
		logrus.Infof("[PRIVATE-REGISTRY] system project %q for cluster %q already has the global pull secret label; no update needed", sysProj.Name, cluster.Name)
		return cluster, nil
	}

	if isGlobalDefault {
		logrus.Infof("[PRIVATE-REGISTRY] adding %q label to system project %q for cluster %q",
			secret.NeedsGlobalPrivateRegistryPullSecret, sysProj.Name, cluster.Name)
		sysProj = sysProj.DeepCopy()
		if sysProj.Labels == nil {
			sysProj.Labels = map[string]string{}
		}
		sysProj.Labels[secret.NeedsGlobalPrivateRegistryPullSecret] = "true"
		_, err = h.project.Update(sysProj)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to add global pull secret label to system project %q for cluster %q: %v", sysProj.Name, cluster.Name, err)
			return cluster, err
		}
		logrus.Infof("[PRIVATE-REGISTRY] successfully updated system project %q with global pull secret label for cluster %q", sysProj.Name, cluster.Name)
	} else {
		logrus.Infof("[PRIVATE-REGISTRY] cluster %q does not use global default registry; no label change required", cluster.Name)
	}

	return cluster, nil
}

// labelSourceGlobalRegistryPullSecret handles the labeling and unlabeling of global system default registry pull secrets.
// The label is used by other controllers to synchronize the project scoped secret used in the local system project
// local and downstream clusters.
func (h *handler) labelSourceGlobalRegistryPullSecret(_ string, setting *v3.Setting) (*v3.Setting, error) {
	if setting == nil || setting.Name != settings.SystemDefaultRegistryPullSecrets.Name {
		return setting, nil
	}

	logrus.Infof("[PRIVATE-REGISTRY] labelSourceGlobalRegistryPullSecret invoked for setting %q", setting.Name)

	existingGlobalPullSecrets, err := h.secretCache.List(namespaces.System, labels.SelectorFromSet(map[string]string{
		util.SourcePullSecretLabel: "true",
	}))
	if err != nil {
		logrus.Errorf("[PRIVATE-REGISTRY] failed to list existing labeled source pull secrets in namespace %q: %v", namespaces.System, err)
		return setting, err
	}

	existingSecretsSet := sets.New[string]()
	for _, s := range existingGlobalPullSecrets {
		existingSecretsSet.Insert(s.Name)
	}
	logrus.Infof("[PRIVATE-REGISTRY] found %d existing labeled source pull secret(s): %v", existingSecretsSet.Len(), existingSecretsSet.UnsortedList())

	v := setting.Default
	if setting.Value != "" {
		v = setting.Value
	}

	specifiedSecretsSet := sets.New[string]()
	if v != "" {
		specifiedSecretsSet.Insert(strings.Split(v, ",")...)
	}

	logrus.Infof("[PRIVATE-REGISTRY] setting %q specifies %d pull secret(s): %v", setting.Name, specifiedSecretsSet.Len(), specifiedSecretsSet.UnsortedList())

	toRemove := existingSecretsSet.Difference(specifiedSecretsSet).UnsortedList()
	if len(toRemove) > 0 {
		logrus.Infof("[PRIVATE-REGISTRY] removing %q label from %d secret(s) no longer in the setting: %v", util.SourcePullSecretLabel, len(toRemove), toRemove)
	}
	for _, s := range toRemove {
		sec, err := h.secretCache.Get(namespaces.System, s)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to get secret %q from namespace %q during label removal: %v", s, namespaces.System, err)
			return setting, err
		}
		sec = sec.DeepCopy()
		delete(sec.Labels, util.SourcePullSecretLabel)
		delete(sec.Annotations, secret.PSSIgnoreNamespacesAnnotations)
		logrus.Infof("[PRIVATE-REGISTRY] removing source label and PSS annotation from secret %q in namespace %q", s, namespaces.System)
		_, err = h.secrets.Update(sec)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to update secret %q in namespace %q after removing label: %v", s, namespaces.System, err)
			return setting, err
		}
		logrus.Infof("[PRIVATE-REGISTRY] successfully removed source label from secret %q", s)
	}

	toLabel := specifiedSecretsSet.UnsortedList()
	if len(toLabel) > 0 {
		logrus.Infof("[PRIVATE-REGISTRY] ensuring %q label on %d specified secret(s): %v", util.SourcePullSecretLabel, len(toLabel), toLabel)
	}

	for _, s := range specifiedSecretsSet.Difference(existingSecretsSet).UnsortedList() {
		sec, err := h.secretCache.Get(namespaces.System, s)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to get secret %q from namespace %q during label application: %v", s, namespaces.System, err)
			return nil, err
		}
		if sec.Labels != nil && sec.Labels[util.SourcePullSecretLabel] == "true" {
			continue
		}
		sec = sec.DeepCopy()
		if sec.Labels == nil {
			sec.Labels = map[string]string{}
		}
		sec.Labels[util.SourcePullSecretLabel] = "true"
		if sec.Annotations == nil {
			sec.Annotations = map[string]string{}
		}
		sec.Annotations[secret.PSSIgnoreNamespacesAnnotations] = strings.Join(settings.SystemNamespacesIgnoringPullSecrets, ",")
		logrus.Infof("[PRIVATE-REGISTRY] applying source label and PSS annotation to secret %q in namespace %q", s, namespaces.System)
		_, err = h.secrets.Update(sec)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to update secret %q in namespace %q after applying label: %v", s, namespaces.System, err)
			return nil, err
		}
		logrus.Infof("[PRIVATE-REGISTRY] successfully applied source label to secret %q", s)
	}

	logrus.Infof("[PRIVATE-REGISTRY] labelSourceGlobalRegistryPullSecret complete for setting %q", setting.Name)
	return setting, nil
}

// manageImportedAndHostedClusterPSS handles the synchronization of source image pull secrets and project scoped secrets
// for downstream imported and hosted clusters only. This handler specifically focuses on the cluster level configuration,
// and ignores any global changes. Imported / Hosted clusters which rely on the GSDR will receive their pull secrets via
// alternative PSS logic incorporated in the PSS implementation.
func (h *handler) manageImportedAndHostedClusterPSS(_ string, cluster *v3.Cluster) (*v3.Cluster, error) {
	if cluster == nil || cluster.Name == "local" {
		return cluster, nil
	}

	logrus.Infof("[PRIVATE-REGISTRY] manageImportedAndHostedClusterPSS invoked for cluster %q", cluster.Name)
	privateRegistry, isGlobalDefault := util.GetPrivateRegistry(cluster)
	if privateRegistry == nil {
		return cluster, nil
	}

	// don't use PSS mirroring if we're working with a provisioned cluster.
	if !util.MgmtNameRegexp.MatchString(cluster.Name) {
		logrus.Infof("[PRIVATE-REGISTRY] cluster %q is a provisioned cluster (not imported/hosted); skipping label management", cluster.Name)
		return cluster, nil
	}

	if !v3.ClusterConditionSystemProjectCreated.IsTrue(cluster) && !v3.ClusterConditionAgentDeployed.IsTrue(cluster) {
		logrus.Infof("[PRIVATE-REGISTRY] cluster %q is not ready (systemProjectCreated=%v, agentDeployed=%v); skipping",
			cluster.Name,
			v3.ClusterConditionSystemProjectCreated.IsTrue(cluster),
			v3.ClusterConditionAgentDeployed.IsTrue(cluster))
		return cluster, nil
	}

	logrus.Infof("[PRIVATE-REGISTRY] cluster %q has %d cluster-level pull secret(s) to manage", cluster.Name, len(privateRegistry.PullSecrets))

	sysProj, found, err := h.getSystemProjectForCluster(cluster.Name)
	if err != nil {
		logrus.Errorf("[PRIVATE-REGISTRY] failed to get system project for cluster %q: %v", cluster.Name, err)
		return cluster, err
	}
	if !found {
		logrus.Infof("[PRIVATE-REGISTRY] no system project found for cluster %q; skipping PSS management", cluster.Name)
		return cluster, nil
	}

	// the backing namespace on downstream clusters is actually a
	// combination of the v3 cluster name and project name.
	backingNamespace := sysProj.GetProjectBackingNamespace()
	logrus.Infof("[PRIVATE-REGISTRY] using backing namespace %q for system project %q on cluster %q", backingNamespace, sysProj.Name, cluster.Name)

	// gather all PSS's for this specific cluster
	createdPSS, err := h.secretCache.List(backingNamespace, labels.SelectorFromSet(map[string]string{
		util.CopiedPullSecretLabel: "true",
	}))
	if err != nil {
		logrus.Errorf("[PRIVATE-REGISTRY] failed to list existing copied PSS(s) in backing namespace %q for cluster %q: %v", backingNamespace, cluster.Name, err)
		return cluster, err
	}

	if (len(privateRegistry.PullSecrets) == 0 || isGlobalDefault) && len(createdPSS) == 0 {
		logrus.Infof("[PRIVATE-REGISTRY] cluster %q has no applicable cluster-level pull secrets (registryNil=%v, pullSecretsEmpty=%v, isGlobalDefault=%v); skipping",
			cluster.Name, privateRegistry == nil, privateRegistry != nil && len(privateRegistry.PullSecrets) == 0, isGlobalDefault)
		return cluster, nil
	}

	// This finds the secrets that are either specified on the cluster or
	// in the global settings and creates a slice of all the secrets
	// which currently exist and can be copied.
	var sourceAuthSecrets []*kcorev1.Secret
	for _, ds := range privateRegistry.PullSecrets {
		s, err := h.secretCache.Get(ds.Namespace, ds.Name)
		if err != nil {
			if errors.IsNotFound(err) {
				logrus.Warnf("[PRIVATE-REGISTRY] pull secret %q in namespace %q defined on cluster %q not found; skipping", ds.Name, ds.Namespace, cluster.Name)
				continue
			}
			logrus.Errorf("[PRIVATE-REGISTRY] failed to get pull secret %q in namespace %q for cluster %q: %v", ds.Name, ds.Namespace, cluster.Name, err)
			return cluster, err
		}
		logrus.Infof("[PRIVATE-REGISTRY] resolved source pull secret %q from namespace %q for cluster %q", ds.Name, ds.Namespace, cluster.Name)
		// TODO: Actual validation?
		sourceAuthSecrets = append(sourceAuthSecrets, s)
	}
	logrus.Infof("[PRIVATE-REGISTRY] %d source pull secret(s) resolved for cluster %q", len(sourceAuthSecrets), cluster.Name)

	logrus.Infof("[PRIVATE-REGISTRY] found %d existing copied PSS(s) in backing namespace %q for cluster %q", len(createdPSS), backingNamespace, cluster.Name)

	// Delete any PSS's that were created for secrets no longer specified on the cluster object.
	// This handles the case where a source secret was removed from the cluster spec, but also when
	// a secret is removed from the global setting (as util.GetPrivateRegistry may pull from either)
	for _, pss := range createdPSS {
		if !slices.ContainsFunc(sourceAuthSecrets, func(s *kcorev1.Secret) bool { return s.Name == pss.Name }) {
			logrus.Infof("[PRIVATE-REGISTRY] deleting stale PSS %q from backing namespace %q (no longer in cluster pull secret list)", pss.Name, backingNamespace)
			err = h.secrets.Delete(pss.Namespace, pss.Name, &metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				logrus.Errorf("[PRIVATE-REGISTRY] failed to delete stale PSS %q from backing namespace %q: %v", pss.Name, backingNamespace, err)
				return cluster, err
			}
			logrus.Infof("[PRIVATE-REGISTRY] successfully deleted stale PSS %q from backing namespace %q", pss.Name, backingNamespace)
		}
	}

	if isGlobalDefault {
		return cluster, nil
	}

	// Create any missing PSS's
	for _, sourcePullSecret := range sourceAuthSecrets {
		// need to convert to a dockerconfigjson
		data, err := util.ConvertToDockerConfigJson(sourcePullSecret.Type, privateRegistry.URL, sourcePullSecret.Data)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] convertToDockerConfigJson failed for secret %q on cluster %q: %v", sourcePullSecret.Name, cluster.Name, err)
			continue
		}

		// does the PSS already exist?
		var existingSecret *kcorev1.Secret
		pssAlreadyExists := slices.ContainsFunc(createdPSS, func(s *kcorev1.Secret) bool {
			if s.Name == sourcePullSecret.Name {
				existingSecret = s
				return true
			}
			return false
		})

		if !pssAlreadyExists || existingSecret == nil {
			logrus.Infof("[PRIVATE-REGISTRY] PSS %q does not exist in backing namespace %q; creating it now", sourcePullSecret.Name, backingNamespace)
			pss := buildPSS(sysProj, backingNamespace, sourcePullSecret.Name, data)
			_, err = h.secrets.Create(pss)
			if err != nil && !errors.IsAlreadyExists(err) {
				logrus.Errorf("[PRIVATE-REGISTRY] failed to create PSS %q in backing namespace %q: %v", sourcePullSecret.Name, backingNamespace, err)
				return cluster, err
			}
			logrus.Infof("[PRIVATE-REGISTRY] successfully created PSS %q in backing namespace %q", sourcePullSecret.Name, backingNamespace)
			continue
		}

		existingData := existingSecret.Data[kcorev1.DockerConfigJsonKey]
		if bytes.Equal(existingData, data) {
			logrus.Infof("[PRIVATE-REGISTRY] PSS %q in backing namespace %q is up to date; no update needed", sourcePullSecret.Name, backingNamespace)
			continue
		}

		logrus.Infof("[PRIVATE-REGISTRY] PSS %q in backing namespace %q has stale data; updating", sourcePullSecret.Name, backingNamespace)
		existingSecret = existingSecret.DeepCopy()
		existingSecret.Data[kcorev1.DockerConfigJsonKey] = data
		_, err = h.secrets.Update(existingSecret)
		if err != nil {
			logrus.Errorf("[PRIVATE-REGISTRY] failed to update PSS %q in backing namespace %q: %v", sourcePullSecret.Name, backingNamespace, err)
			return cluster, err
		}
		logrus.Infof("[PRIVATE-REGISTRY] successfully updated PSS %q in backing namespace %q", sourcePullSecret.Name, backingNamespace)
	}

	logrus.Infof("[PRIVATE-REGISTRY] PSS management complete for cluster %q", cluster.Name)
	return cluster, nil
}

func buildPSS(proj *v3.Project, systemProjectBackingNamespace, name string, dockerconfigjson []byte) *kcorev1.Secret {
	logrus.Infof("[PRIVATE-REGISTRY] PSS secret %q does not exist in namespace %q, creating it now", name, systemProjectBackingNamespace)
	PSS := &kcorev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: systemProjectBackingNamespace,
			Annotations: map[string]string{
				// this is new, and required to keep the secret out of namespaces that only hold user data and not workloads.
				secret.PSSIgnoreNamespacesAnnotations: strings.Join(settings.SystemNamespacesIgnoringPullSecrets, ","),
			},
			Labels: map[string]string{
				util.CopiedPullSecretLabel:                    "true",
				"management.cattle.io/project-scoped-secret":  proj.Name,
				"management.cattle.io/registry-scoped-secret": "true",
			},
		},
		Data: map[string][]byte{
			kcorev1.DockerConfigJsonKey: dockerconfigjson,
		},
		Type: kcorev1.SecretTypeDockerConfigJson,
	}

	return PSS
}

func (h *handler) getSystemProjectForCluster(clusterName string) (*v3.Project, bool, error) {
	logrus.Infof("[PRIVATE-REGISTRY] looking up system project for cluster %q", clusterName)
	localSystemProjs, err := h.projectCache.GetByIndex(clusterToSysProjIndex, clusterName)
	if err != nil {
		logrus.Errorf("[PRIVATE-REGISTRY] failed to look up system project for cluster %q via index: %v", clusterName, err)
		return nil, false, err
	}
	if localSystemProjs == nil || len(localSystemProjs) == 0 {
		logrus.Infof("[PRIVATE-REGISTRY] no system project found in index for cluster %q", clusterName)
		return nil, false, nil
	}
	localSystemProj := localSystemProjs[0]
	logrus.Infof("[PRIVATE-REGISTRY] resolved system project %q for cluster %q", localSystemProj.Name, clusterName)
	return localSystemProj, true, nil
}
