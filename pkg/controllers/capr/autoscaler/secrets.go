package autoscaler

// Secret management for the autoscaler HelmOp.
//
// Two types of secrets are managed to support deploying the cluster-autoscaler chart via Fleet:
//
//  1. HelmOp secret (username/password) — used by Fleet to authenticate with the chart's OCI registry.
//     The canonical copy lives in fleet-default, managed by syncRootHelmOpSecret (Setting OnChange handler).
//     For clusters in other namespaces, a copy is created by ensureHelmOpSecretInNamespace.
//
//  2. Image pull secret (.dockerconfigjson) — used by the downstream kubelet to pull the autoscaler image.
//     For fleet-default clusters, the existing global secret is referenced directly (another controller
//     ensures it is present there). For clusters in other namespaces, a copy is created by
//     ensureImagePullSecretInNamespace.
//
// Both per-namespace copies are owned by the CAPI cluster and will be garbage collected on cluster deletion.
// The root HelmOp secret in fleet-default is cleaned up when the feature flag is disabled (see Register)
// or when the registry configuration is removed (see syncRootHelmOpSecret).

import (
	stderrors "errors"
	"fmt"
	"reflect"

	"github.com/rancher/rancher/pkg/cluster"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	capi "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

func (h *autoscalerHandler) cleanupHelmSecrets(cluster *capi.Cluster) error {
	// delete the per-cluster image pull secret and helm op secret
	if cluster.Namespace == "fleet-default" {
		// Clusters in the fleet-default namespace share common
		// secrets, so we shouldn't clean them up here.
		return nil
	}

	var errs []error

	imagePullSecretName := autoscalerClusterScopedImagePullSecretName(cluster)
	if err := h.secretClient.Delete(cluster.Namespace, imagePullSecretName, &metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete image pull secret %s in namespace %s: %w", imagePullSecretName, cluster.Namespace, err))
	}

	opSecret := helmOpSecretName(cluster)
	if err := h.secretClient.Delete(cluster.Namespace, opSecret, &metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Errorf("failed to delete helm op secret %s in namespace %s: %w", opSecret, cluster.Namespace, err))
	}

	return stderrors.Join(errs...)
}

func (h *autoscalerHandler) manageHelmOpSecrets(capiCluster *capi.Cluster) (helmOpSecretName string, imagePullSecretName string, err error) {
	helmOpSecretName, err = h.ensureHelmOpSecretInNamespace(capiCluster)
	if err != nil {
		return "", "", err
	}

	imagePullSecretName, err = h.ensureImagePullSecretInNamespace(capiCluster)
	if err != nil {
		return "", "", err
	}

	return helmOpSecretName, imagePullSecretName, nil
}

// ensureImagePullSecretInNamespace ensures that if a global image pull secret is configured, each cluster
// has a copy of it in their own namespace. This is required because the HelmOp which installs the autoscaler
// is created in the cluster's namespace, which may not be part of the system project.
// For fleet-default clusters, the existing global secret name is returned directly.
// For other namespaces, a copy of the first globally-defined image pull secret is created and kept in sync.
func (h *autoscalerHandler) ensureImagePullSecretInNamespace(capiCluster *capi.Cluster) (string, error) {
	registry, _ := cluster.GetPrivateRegistry(nil)

	// do we already have our own copy?
	found := true
	existingSec, err := h.secretCache.Get(capiCluster.Namespace, autoscalerClusterScopedImagePullSecretName(capiCluster))
	if err != nil {
		if !errors.IsNotFound(err) {
			return "", err
		}
		found = false
	}

	if found && (registry == nil || len(registry.PullSecrets) == 0) {
		// delete the secret, since it's no longer needed
		return "", h.secretClient.Delete(existingSec.Namespace, existingSec.Name, &metav1.DeleteOptions{})
	}

	if registry == nil || len(registry.PullSecrets) == 0 {
		return "", nil
	}

	// other controllers already ensure that the globally defined secrets will be
	// present in fleet-default, no need to make a new copy.
	if capiCluster.Namespace == "fleet-default" {
		return registry.PullSecrets[0].Name, nil
	}

	// get the first image pull secret configured globally and use its configuration
	pullSec, err := h.secretCache.Get(registry.PullSecrets[0].Namespace, registry.PullSecrets[0].Name)
	if err != nil {
		return "", err
	}

	clusterScopedPullSecretName := autoscalerClusterScopedImagePullSecretName(capiCluster)
	if !found {
		// create the secret
		pullSecret := &v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            clusterScopedPullSecretName,
				Namespace:       capiCluster.Namespace,
				OwnerReferences: ownerReference(capiCluster),
			},
			Type: v1.SecretTypeDockerConfigJson,
			Data: map[string][]byte{
				v1.DockerConfigJsonKey: pullSec.Data[v1.DockerConfigJsonKey],
			},
		}
		_, err = h.secretClient.Create(pullSecret)
		if err != nil {
			return "", err
		}
		return clusterScopedPullSecretName, nil
	}

	// make sure it's up to date
	config, ok := existingSec.Data[v1.DockerConfigJsonKey]
	if !ok || !reflect.DeepEqual(config, pullSec.Data[v1.DockerConfigJsonKey]) {
		existingSec = existingSec.DeepCopy()
		existingSec.Data[v1.DockerConfigJsonKey] = pullSec.Data[v1.DockerConfigJsonKey]
		_, err = h.secretClient.Update(existingSec)
		if err != nil {
			return "", err
		}
	}

	return clusterScopedPullSecretName, nil
}

// ensureHelmOpSecretInNamespace creates or updates a copy of the root HelmOp secret (from fleet-default)
// in the cluster's namespace. This is needed for the Fleet controller to authenticate with the OCI registry
// hosting the autoscaler chart. For fleet-default clusters, the root secret name is returned directly.
// If the root secret does not exist, any previously-created cluster-scoped copy is cleaned up.
func (h *autoscalerHandler) ensureHelmOpSecretInNamespace(capiCluster *capi.Cluster) (string, error) {
	sec, err := h.secretCache.Get("fleet-default", autoscalerHelmSecretResourceName)
	if err != nil {
		if errors.IsNotFound(err) {
			// Root secret doesn't exist yet. If a private registry is configured, try to
			// create it now as a fallback (the Setting handler may not have fired yet).
			sec, err = h.ensureRootHelmOpSecret()
			if err != nil {
				return "", err
			}
			if sec == nil {
				// No registry configured or source secret not available — clean up any stale copies.
				if capiCluster.Namespace != "fleet-default" {
					err = h.secretClient.Delete(capiCluster.Namespace, helmOpSecretName(capiCluster), &metav1.DeleteOptions{})
					if err != nil && !errors.IsNotFound(err) {
						return "", err
					}
				}
				return "", nil
			}
		} else {
			return "", err
		}
	}

	if capiCluster.Namespace == "fleet-default" {
		return autoscalerHelmSecretResourceName, nil
	}

	// do we already have our own copy?
	found := true
	existingSec, err := h.secretCache.Get(capiCluster.Namespace, helmOpSecretName(capiCluster))
	if err != nil {
		if !errors.IsNotFound(err) {
			return "", err
		}
		found = false
	}

	opSecretName := helmOpSecretName(capiCluster)

	// create it if we don't
	if !found {
		copiedSecret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:            opSecretName,
				Namespace:       capiCluster.Namespace,
				OwnerReferences: ownerReference(capiCluster),
			},
			Data: map[string][]byte{
				"username": sec.Data["username"],
				"password": sec.Data["password"],
			},
		}
		_, err = h.secretClient.Create(&copiedSecret)
		return opSecretName, err
	}

	// check that it's up to date
	currentUsername := string(existingSec.Data["username"])
	currentPassword := string(existingSec.Data["password"])
	if currentUsername != string(sec.Data["username"]) || currentPassword != string(sec.Data["password"]) {
		existingSec = existingSec.DeepCopy()
		existingSec.Data["username"] = sec.Data["username"]
		existingSec.Data["password"] = sec.Data["password"]
		_, err = h.secretClient.Update(existingSec)
		if err != nil {
			return "", err
		}
		return opSecretName, nil
	}

	return opSecretName, nil
}

// ensureRootHelmOpSecret ensures the canonical HelmOp auth secret exists in fleet-default
// with the correct credentials derived from the global registry configuration. It handles
// create, update, and delete. Returns the secret if one exists/was created, or nil if no
// private registry is configured.
// This is called by both syncRootHelmOpSecret (Setting handler) and ensureHelmOpSecretInNamespace
// (per-cluster fallback) to avoid duplicating the registry → username/password extraction logic.
func (h *autoscalerHandler) ensureRootHelmOpSecret() (*v1.Secret, error) {
	registry, _ := cluster.GetPrivateRegistry(nil)

	existingSec, err := h.secretCache.Get("fleet-default", autoscalerHelmSecretResourceName)
	if err != nil && !errors.IsNotFound(err) {
		return nil, err
	}
	found := err == nil

	// Registry removed — delete the secret if it exists.
	if registry == nil || len(registry.PullSecrets) == 0 {
		if found {
			err = h.secretClient.Delete("fleet-default", autoscalerHelmSecretResourceName, &metav1.DeleteOptions{})
			if err != nil && !errors.IsNotFound(err) {
				return nil, err
			}
		}
		return nil, nil
	}

	// Read the source pull secret and extract credentials.
	pullSecRef := registry.PullSecrets[0]
	pullSec, err := h.secretCache.Get(pullSecRef.Namespace, pullSecRef.Name)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if _, ok := pullSec.Data[v1.DockerConfigJsonKey]; !ok {
		return nil, nil
	}

	username, password, _, err := cluster.UnwrapDockerConfigJson(registry.URL, pullSec.Data)
	if err != nil {
		return nil, err
	}

	// Create if it doesn't exist.
	if !found {
		sec, err := h.secretClient.Create(&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      autoscalerHelmSecretResourceName,
				Namespace: "fleet-default",
			},
			Data: map[string][]byte{
				"username": []byte(username),
				"password": []byte(password),
			},
		})
		if err != nil {
			if errors.IsAlreadyExists(err) {
				return h.secretCache.Get("fleet-default", autoscalerHelmSecretResourceName)
			}
			return nil, err
		}
		return sec, nil
	}

	// Update if credentials have changed.
	existingSec = existingSec.DeepCopy()
	if existingSec.Data == nil {
		existingSec.Data = map[string][]byte{}
	}

	hasChanged := false
	if string(existingSec.Data["username"]) != username {
		existingSec.Data["username"] = []byte(username)
		hasChanged = true
	}
	if string(existingSec.Data["password"]) != password {
		existingSec.Data["password"] = []byte(password)
		hasChanged = true
	}

	if hasChanged {
		updated, err := h.secretClient.Update(existingSec)
		if err != nil {
			return nil, err
		}
		return updated, nil
	}

	return existingSec, nil
}
