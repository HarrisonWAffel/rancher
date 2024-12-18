package cluster

import (
	"encoding/json"
	"fmt"
	"github.com/rancher/rancher/pkg/features"
	"reflect"
	"strconv"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	corev1 "k8s.io/api/core/v1"
)

const PriorityClassDescription = "Rancher managed Priority Class for the cattle-cluster-agent"

// GetClusterAgentTolerations returns additional tolerations for the cluster agent if they have been user defined. If
// not, nil is returned.
func GetClusterAgentTolerations(cluster *v3.Cluster) []corev1.Toleration {
	if cluster.Spec.ClusterAgentDeploymentCustomization != nil &&
		cluster.Spec.ClusterAgentDeploymentCustomization.AppendTolerations != nil {
		return cluster.Spec.ClusterAgentDeploymentCustomization.AppendTolerations
	}

	return nil
}

// GetClusterAgentAffinity returns node affinity for the cluster agent if it has been user defined. If not, then the
// default affinity is returned.
func GetClusterAgentAffinity(cluster *v3.Cluster) (*corev1.Affinity, error) {
	if cluster.Spec.ClusterAgentDeploymentCustomization != nil &&
		cluster.Spec.ClusterAgentDeploymentCustomization.OverrideAffinity != nil {
		return cluster.Spec.ClusterAgentDeploymentCustomization.OverrideAffinity, nil
	}

	return unmarshalAffinity(settings.ClusterAgentDefaultAffinity.Get())
}

// GetClusterAgentResourceRequirements returns resource requirements (cpu, memory) for the cluster agent if it has been
// user defined. If not, nil is returned.
func GetClusterAgentResourceRequirements(cluster *v3.Cluster) *corev1.ResourceRequirements {
	if cluster.Spec.ClusterAgentDeploymentCustomization != nil &&
		cluster.Spec.ClusterAgentDeploymentCustomization.OverrideResourceRequirements != nil {
		return cluster.Spec.ClusterAgentDeploymentCustomization.OverrideResourceRequirements
	}

	return nil
}

// GetFleetAgentTolerations returns additional tolerations for the fleet agent if it has been user defined. If not,
// then nil is returned.
func GetFleetAgentTolerations(cluster *v3.Cluster) []corev1.Toleration {
	if cluster.Spec.FleetAgentDeploymentCustomization != nil &&
		cluster.Spec.FleetAgentDeploymentCustomization.AppendTolerations != nil {
		return cluster.Spec.FleetAgentDeploymentCustomization.AppendTolerations
	}

	return nil
}

// GetFleetAgentAffinity returns node affinity for the fleet agent if it has been user defined. If not, then the
// default affinity is returned.
func GetFleetAgentAffinity(cluster *v3.Cluster) (*corev1.Affinity, error) {
	if cluster.Spec.FleetAgentDeploymentCustomization != nil &&
		cluster.Spec.FleetAgentDeploymentCustomization.OverrideAffinity != nil {
		return cluster.Spec.FleetAgentDeploymentCustomization.OverrideAffinity, nil
	}

	return unmarshalAffinity(settings.FleetAgentDefaultAffinity.Get())
}

// GetFleetAgentResourceRequirements returns resource requirements (cpu, memory) for the fleet agent if it has been
// user defined. If not, nil is returned.
func GetFleetAgentResourceRequirements(cluster *v3.Cluster) *corev1.ResourceRequirements {
	if cluster.Spec.FleetAgentDeploymentCustomization != nil &&
		cluster.Spec.FleetAgentDeploymentCustomization.OverrideResourceRequirements != nil {
		return cluster.Spec.FleetAgentDeploymentCustomization.OverrideResourceRequirements
	}

	return nil
}

// unmarshalAffinity returns an unmarshalled object of the v1 node affinity. If unable to be unmarshalled, it returns
// nil and an error.
func unmarshalAffinity(affinity string) (*corev1.Affinity, error) {
	var affinityObj corev1.Affinity
	err := json.Unmarshal([]byte(affinity), &affinityObj)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal node affinity: %w", err)
	}

	return &affinityObj, nil
}

// AgentDeploymentCustomizationChanged determines if the ClusterAgentDeploymentCustomization spec field
// matches the values set in the status. The returned boolean indicates that either the desired Affinities,
// tolerations, or resource requirements have been changed. AgentDeploymentCustomizationChanged Does not indicate
// if any SchedulingCustomization options have been changed.
func AgentDeploymentCustomizationChanged(cluster *v3.Cluster) bool {
	if cluster == nil {
		return false
	}

	var specCustomization *v3.AgentDeploymentCustomization
	var statusCustomization *v3.AgentDeploymentCustomization

	if cluster.Spec.ClusterAgentDeploymentCustomization != nil {
		specCustomization = cluster.Spec.ClusterAgentDeploymentCustomization
	}

	if cluster.Status.AppliedClusterAgentDeploymentCustomization != nil {
		statusCustomization = cluster.Status.AppliedClusterAgentDeploymentCustomization
	}

	if specCustomization == nil && statusCustomization == nil {
		return false
	}

	// if we had something but now have nothing, everything changed
	if specCustomization == nil && statusCustomization != nil {
		return true
	}

	var affinitiesDiffer, tolerationsDiffer, resourcesDiffer bool
	// if nothing is in the status then it is the first time we're creating these objects
	if specCustomization != nil && statusCustomization == nil {
		affinitiesDiffer = specCustomization.OverrideAffinity != nil
		tolerationsDiffer = specCustomization.AppendTolerations != nil
		resourcesDiffer = specCustomization.OverrideResourceRequirements != nil

		return affinitiesDiffer || tolerationsDiffer || resourcesDiffer
	}

	if specCustomization.AppendTolerations != nil && statusCustomization.AppendTolerations != nil {
		tolerationsDiffer = !reflect.DeepEqual(specCustomization.AppendTolerations, statusCustomization.AppendTolerations)
	}

	if specCustomization.OverrideAffinity != nil && statusCustomization.OverrideAffinity != nil {
		affinitiesDiffer = !reflect.DeepEqual(specCustomization.OverrideAffinity, statusCustomization.OverrideAffinity)
	}

	if specCustomization.OverrideResourceRequirements != nil && statusCustomization.OverrideResourceRequirements != nil {
		resourcesDiffer = !reflect.DeepEqual(specCustomization.OverrideResourceRequirements, statusCustomization.OverrideResourceRequirements)
	}

	return affinitiesDiffer || tolerationsDiffer || resourcesDiffer
}

// AgentSchedulingCustomizationChanged Determines if the values set in the ClusterAgentDeploymentCustomization.SchedulingCustomization
// spec field matches those set in the status. Four booleans are returned to indicate (in this order) if the PDB has been changed, if the Priority Class
// has been changed, if the PDB has been deleted, if the Priority Class has been deleted, or if the PriorityCLass has been created for the first time.
func AgentSchedulingCustomizationChanged(cluster *v3.Cluster) (bool, bool, bool, bool, bool) {
	if cluster == nil {
		return false, false, false, false, false
	}

	specCustomization := cluster.Spec.ClusterAgentDeploymentCustomization
	statusCustomization := cluster.Status.AppliedClusterAgentDeploymentCustomization

	if specCustomization == nil && statusCustomization == nil {
		return false, false, false, false, false
	}

	var specScheduling *v3.AgentSchedulingCustomization
	if specCustomization != nil && specCustomization.SchedulingCustomization != nil {
		specScheduling = specCustomization.SchedulingCustomization
	}

	var statusScheduling *v3.AgentSchedulingCustomization
	if statusCustomization != nil && statusCustomization.SchedulingCustomization != nil {
		statusScheduling = statusCustomization.SchedulingCustomization
	}

	if specScheduling == nil && statusScheduling == nil {
		return false, false, false, false, false
	}

	// all objects deleted
	if specScheduling == nil && statusScheduling != nil {
		return true, true, true, true, false
	}

	// first time creating the objects
	if specScheduling != nil && statusScheduling == nil {
		// if the feature isn't enabled
		// and the PC/PDB has not been previously created
		// then we should not indicate any changes
		if !features.ClusterAgentSchedulingCustomization.Enabled() {
			return false, false, false, false, false
		}

		pcExists := specCustomization.SchedulingCustomization.PriorityClass != nil
		pdbExists := specCustomization.SchedulingCustomization.PodDisruptionBudget != nil
		return pdbExists, pcExists, false, false, pcExists
	}

	// per object handling
	pdbDiffer := !reflect.DeepEqual(specScheduling.PodDisruptionBudget, statusScheduling.PodDisruptionBudget)
	pcDiffer := !reflect.DeepEqual(specScheduling.PriorityClass, statusScheduling.PriorityClass)
	pdbDelete := specScheduling.PodDisruptionBudget == nil && statusScheduling.PodDisruptionBudget != nil
	pcDelete := specScheduling.PriorityClass == nil && statusScheduling.PriorityClass != nil
	pcCreate := specScheduling.PriorityClass != nil && statusScheduling.PriorityClass == nil

	return pdbDiffer, pcDiffer, pdbDelete, pcDelete, pcCreate
}

// AgentSchedulingCustomizationEnabled determines if scheduling customization has been defined for either the
// PriorityClass or PodDisruptionBudget. It returns three bools, which indicate if either field has been defined,
// if the Priority Class has been defined, and if the Pod Disruption Budget has been defined.
func AgentSchedulingCustomizationEnabled(cluster *v3.Cluster) (bool, bool, bool) {
	if cluster == nil {
		return false, false, false
	}

	if !features.ClusterAgentSchedulingCustomization.Enabled() {
		return false, false, false
	}

	agentCustomization := cluster.Spec.ClusterAgentDeploymentCustomization

	if agentCustomization == nil || agentCustomization.SchedulingCustomization == nil {
		return false, false, false
	}

	pdbEnabled := agentCustomization.SchedulingCustomization.PodDisruptionBudget != nil
	pcEnabled := agentCustomization.SchedulingCustomization.PriorityClass != nil

	return pdbEnabled || pcEnabled, pcEnabled, pdbEnabled
}

// GetDesiredDisruptionBudgetValues returns the minAvailable and maxUnavailable fields values in the agent SchedulingCustomization
// if they have been set. If both fields are set to zero, only a value for maxUnavailable will be returned, as Pod Disruption Budgets
// can only set one of the two fields at a time. The validating webhook ensures that both fields cannot be set on the cluster agent prior
// to this function being invoked.
func GetDesiredDisruptionBudgetValues(cluster *v3.Cluster) (string, string, error) {
	if cluster == nil {
		return "", "", nil
	}

	PDBMaxUnavailable := ""
	PDBMinAvailable := ""
	agentCustomization := cluster.Spec.ClusterAgentDeploymentCustomization
	if agentCustomization == nil || agentCustomization.SchedulingCustomization == nil || agentCustomization.SchedulingCustomization.PodDisruptionBudget == nil {
		return "", "", nil
	}

	var minAvailInt, maxUnavailInt int
	var err error

	minAvailStr := agentCustomization.SchedulingCustomization.PodDisruptionBudget.MinAvailable
	if minAvailStr != "" && !strings.Contains(minAvailStr, "%") {
		minAvailInt, err = strconv.Atoi(minAvailStr)
		if err != nil {
			return "", "", err
		}
	}

	maxUnavailStr := agentCustomization.SchedulingCustomization.PodDisruptionBudget.MaxUnavailable
	if maxUnavailStr != "" && !strings.Contains(maxUnavailStr, "%") {
		maxUnavailInt, err = strconv.Atoi(maxUnavailStr)
		if err != nil {
			return "", "", err
		}
	}

	if minAvailInt > 0 {
		PDBMinAvailable = strconv.Itoa(minAvailInt)
	} else if minAvailStr != "0" {
		PDBMinAvailable = minAvailStr
	}

	if maxUnavailInt > 0 {
		PDBMaxUnavailable = strconv.Itoa(maxUnavailInt)
	} else if maxUnavailStr != "0" {
		PDBMaxUnavailable = maxUnavailStr
	}

	if PDBMinAvailable == "" && PDBMaxUnavailable != "" {
		return "", PDBMaxUnavailable, nil
	}

	if PDBMinAvailable != "" && PDBMaxUnavailable == "" {
		return PDBMinAvailable, "", nil
	}

	// if both are set to zero, default to using maxUnavailable
	return "", "0", nil
}

// GetDesiredPriorityClassValueAndPreemption returns the Priority Class priority value and Preemption setting
// if configured in the agent SchedulingCustomization field.
func GetDesiredPriorityClassValueAndPreemption(cluster *v3.Cluster) (int, string) {
	if cluster == nil {
		return 0, ""
	}

	var PCPreemption string
	var PCValue int

	agentCustomization := cluster.Spec.ClusterAgentDeploymentCustomization
	if agentCustomization == nil || agentCustomization.SchedulingCustomization == nil {
		return 0, ""
	}

	if agentCustomization.SchedulingCustomization.PriorityClass == nil {
		return 0, ""
	}

	PCValue = agentCustomization.SchedulingCustomization.PriorityClass.Value
	if agentCustomization.SchedulingCustomization.PriorityClass.Preemption != nil {
		PCPreemption = string(*agentCustomization.SchedulingCustomization.PriorityClass.Preemption)
	}

	return PCValue, PCPreemption
}

func UpdateAppliedAgentDeploymentCustomization(cluster *v3.Cluster, updatePC bool) {
	if cluster == nil {
		return
	}

	agentCustomization := cluster.Spec.ClusterAgentDeploymentCustomization
	if agentCustomization == nil {
		return
	}

	appliedCustomization := &v3.AgentDeploymentCustomization{}

	appliedCustomization.OverrideAffinity = agentCustomization.OverrideAffinity
	appliedCustomization.OverrideResourceRequirements = agentCustomization.OverrideResourceRequirements
	appliedCustomization.AppendTolerations = agentCustomization.AppendTolerations

	// if the feature is disabled then we shouldn't do anything
	if agentCustomization.SchedulingCustomization == nil || !features.ClusterAgentSchedulingCustomization.Enabled() {
		cluster.Status.AppliedClusterAgentDeploymentCustomization = appliedCustomization
		return
	}

	appliedCustomization.SchedulingCustomization = &v3.AgentSchedulingCustomization{
		PodDisruptionBudget: agentCustomization.SchedulingCustomization.PodDisruptionBudget,
	}

	if updatePC {
		appliedCustomization.SchedulingCustomization.PriorityClass = agentCustomization.SchedulingCustomization.PriorityClass
	}

	cluster.Status.AppliedClusterAgentDeploymentCustomization = appliedCustomization

	return
}
