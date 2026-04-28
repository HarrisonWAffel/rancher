package cluster

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "github.com/rancher/rancher/pkg/generated/norman/core/v1"
	namespaces "github.com/rancher/rancher/pkg/namespace"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/sirupsen/logrus"
	kcorev1 "k8s.io/api/core/v1"
)

const (
	// SourcePullSecretLabel is used to track secrets in the cattle-system namespace which are used
	// as the global system default registry pull secrets (via the global setting).
	SourcePullSecretLabel = "management.cattle.io/rancher-default-registry-pull-secret"
	// CopiedPullSecretLabel is used to track the project scoped secrets created by the below controllers,
	// so that their life cycle can be managed by other controllers (e.g. imported cluster cleanup).
	CopiedPullSecretLabel = "management.cattle.io/rancher-managed-pull-secret"
)

var MgmtNameRegexp = regexp.MustCompile("^(c-[a-z0-9]{5}|local)$")

type AgentPullSecret struct {
	Name             string
	DockerConfigJSON string
}

type PrivateRegistry struct {
	// URL is The hostname of the private registry. This value should not include any protocols (e.g. https://) or ports.
	URL string
	// PullSecrets are a slice of object references to secrets in the relevant cluster.
	PullSecrets []kcorev1.SecretReference
}

func (p *PrivateRegistry) PullSecretNamesAsSlice() []string {
	var out []string
	for _, secret := range p.PullSecrets {
		out = append(out, secret.Name)
	}
	return out
}

func (p *PrivateRegistry) PullSecretsAsObjectReferences() []kcorev1.LocalObjectReference {
	var out []kcorev1.LocalObjectReference
	for _, secret := range p.PullSecrets {
		out = append(out, kcorev1.LocalObjectReference{
			Name: secret.Name,
		})
	}
	return out
}

// GetPrivateRegistryURL returns the URL of the private registry specified. It will return the cluster level registry if
// one is found, or the global system default registry if no cluster level registry is found. If neither is found, it will
// return an empty string.
func GetPrivateRegistryURL(cluster *v3.Cluster) string {
	registry, _ := GetPrivateRegistry(cluster)
	if registry == nil {
		return ""
	}
	return registry.URL
}

// GetPrivateRegistry returns a PrivateRegistry entry (or nil if one is not found) for the given
// clusters.management.cattle.io/v3 object. If a cluster-level registry is not defined, or
// the provided cluster is nil, it will return the system default registry configuration if one exists.
func GetPrivateRegistry(importedOrHostedCluster *v3.Cluster) (*PrivateRegistry, bool) {
	if clr := GetPrivateImportedClusterLevelRegistry(importedOrHostedCluster); clr != nil {
		return clr, false
	}
	return getDefaultRegistryConfiguration(), true
}

func getDefaultRegistryConfiguration() *PrivateRegistry {
	gsdr := settings.SystemDefaultRegistry.Get()
	if gsdr == "" {
		return nil
	}
	return &PrivateRegistry{
		URL:         gsdr,
		PullSecrets: buildDefaultPullSecrets(),
	}
}

func buildDefaultPullSecrets() []kcorev1.SecretReference {
	var globalSecrets []kcorev1.SecretReference
	for _, pullSecret := range strings.Split(settings.SystemDefaultRegistryPullSecrets.Get(), ",") {
		if pullSecret == "" {
			continue
		}
		// The GSDR configuration always pulls from cattle-system
		globalSecrets = append(globalSecrets, kcorev1.SecretReference{
			Namespace: namespaces.System,
			Name:      strings.TrimSpace(pullSecret),
		})
	}
	return globalSecrets
}

// GetPrivateImportedClusterLevelRegistry returns the cluster-level registry for the given clusters.management.cattle.io/v3
// object (or nil if one is not found).
func GetPrivateImportedClusterLevelRegistry(cluster *v3.Cluster) *PrivateRegistry {
	if cluster == nil {
		return nil
	}

	importedCfg := cluster.Spec.ImportedConfig
	if importedCfg == nil {
		// falls back to global configuration
		return nil
	}

	url := importedCfg.PrivateRegistryURL
	secrets := importedCfg.PrivateRegistryPullSecrets
	if url == "" {
		return nil
	}

	var pullSecrets []kcorev1.SecretReference
	if len(secrets) > 0 {
		for _, pullSecret := range cluster.Spec.ImportedConfig.PrivateRegistryPullSecrets {
			pullSecrets = append(pullSecrets, kcorev1.SecretReference{
				// Like many other cluster scoped resources, secrets added to v3 clusters
				// should be placed in the fleet-default namespace by either the UI or users.
				Namespace: "fleet-default",
				Name:      pullSecret,
			})
		}
	}

	return &PrivateRegistry{
		URL:         cluster.Spec.ImportedConfig.PrivateRegistryURL,
		PullSecrets: pullSecrets,
	}
}

// GeneratePrivateRegistryEncodedDockerConfig generates one or AgentPullSecret for the provided cluster, with each AgentPullSecret
// containing a mapping between a registry hostname and a base64 encoded docker config json blob. If the cluster is nil or no registry is configured
// at both the cluster or global level, no registry url, AgentPullSecrets, or errors are returned. If a cluster is configured such that we know what
// the URL is, but do not have enough information to generate the AgentPullSecrets, we simply return the URL and a nil slice. An inability to determine
// the pull secrets indicates that the provided registry does not require authentication. For provisioning v2 clusters, we extract the username and password
// keys from the configured registry auth config (located in the ClusterSecrets section of the spec), and convert it to a valid .dockerconfigjson format. As provisioning v2
// clusters can only reference a single auth config secret, only one AgentPullSecret will be returned. For imported or provisioned hosted clusters, the .spec.ImportedConfig field
// is referenced to determine both the private registry URL and image pull secrets. Imported and hosted clusters may return one or more AgentPullSecrets, however they will all
// map to the same registry hostname.
func GeneratePrivateRegistryEncodedDockerConfig(cluster *v3.Cluster, secretLister v1.SecretLister) (string, []AgentPullSecret, error) {
	if cluster == nil {
		return "", nil, nil
	}

	// cluster.GetSecret("PrivateRegistryURL") will only be populated for provisioned
	// rke2/k3s clusters which have defined a system default registry, either at the cluster level
	// or by inheriting the global system default registry configuration setup in Rancher.
	// Imported and hosted clusters will not have these fields set, as they are only populated by the provv2 generating handlers.
	// This field is the only reference to the cluster level registry URL for v2prov clusters.
	if cluster.GetSecret(v3.ClusterPrivateRegistryURL) != "" {
		return generateProvisionedClusterDockerConfig(cluster, secretLister)
	}

	// Otherwise, look elsewhere on the v3 cluster for registry info.
	// This will also return the global system default registry configuration if the cluster
	// doesn't provide any overrides.
	if systemDefaultRegistry, _ := GetPrivateRegistry(cluster); systemDefaultRegistry != nil {
		return generateImportedClusterDockerConfig(cluster, secretLister, systemDefaultRegistry)
	}

	// no registry configured
	return "", nil, nil
}

func generateProvisionedClusterDockerConfig(cluster *v3.Cluster, secretLister v1.SecretLister) (string, []AgentPullSecret, error) {
	v2ProvRegistryURL := cluster.GetSecret(v3.ClusterPrivateRegistryURL)

	// The PrivateRegistrySecret has the same name both for v1 or v2 provisioning clusters despite being in different areas of the spec
	registrySecretName := cluster.GetSecret(v3.ClusterPrivateRegistrySecret)
	if registrySecretName == "" {
		return v2ProvRegistryURL, nil, nil
	}

	registrySecret, err := secretLister.Get(cluster.Spec.FleetWorkspaceName, registrySecretName)
	if err != nil {
		return v2ProvRegistryURL, nil, err
	}

	configJson, err := ConvertToDockerConfigJson(registrySecret.Type, v2ProvRegistryURL, registrySecret.Data)
	if err != nil {
		return "", nil, fmt.Errorf("clusterDeploy: failed to convert pull secret to json: %w", err)
	}

	// note:
	//       Provisioned rke2/k3s clusters only support a single image pull secret,
	//       additional registry credentials are passed using the containerd configuration
	//       delivered by the planner.
	return v2ProvRegistryURL, []AgentPullSecret{{
		Name:             "cattle-private-registry",
		DockerConfigJSON: base64.StdEncoding.EncodeToString(configJson),
	}}, nil
}

func generateImportedClusterDockerConfig(cluster *v3.Cluster, secretLister v1.SecretLister, registry *PrivateRegistry) (string, []AgentPullSecret, error) {
	clusterSystemDefaultURL := registry.URL
	// Only generate credentials for imported or hosted clusters.
	if !MgmtNameRegexp.MatchString(cluster.Name) {
		return clusterSystemDefaultURL, nil, nil
	}

	if len(registry.PullSecrets) == 0 {
		return clusterSystemDefaultURL, nil, nil
	}
	var pullSecrets []AgentPullSecret

	// build out all the cluster level pull secrets
	for _, pullSecret := range registry.PullSecrets {
		sec, err := secretLister.Get(pullSecret.Namespace, pullSecret.Name)
		if err != nil {
			logrus.Errorf("Failed to get pull secret %s in namespace %s for cluster %s: %v", pullSecret.Name, pullSecret.Namespace, cluster.Name, err)
			continue
		}
		configJson, err := ConvertToDockerConfigJson(sec.Type, clusterSystemDefaultURL, sec.Data)
		if err != nil {
			return "", nil, fmt.Errorf("clusterDeploy: failed to convert pull secret to json: %w", err)
		}
		pullSecrets = append(pullSecrets, AgentPullSecret{
			Name:             sec.Name,
			DockerConfigJSON: base64.StdEncoding.EncodeToString(configJson),
		})
	}

	return clusterSystemDefaultURL, pullSecrets, nil
}
