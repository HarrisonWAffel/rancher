package cluster

import (
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAgentCustomization_getPriorityClassValueAndPreemption(t *testing.T) {
	neverPreemptionPolicy := corev1.PreemptionPolicy("Never")
	tests := []struct {
		name               string
		cluster            *v3.Cluster
		expectedValue      int
		expectedPreemption string
	}{
		{
			name:               "cluster is nil",
			cluster:            nil,
			expectedValue:      0,
			expectedPreemption: "",
		},
		{
			name: "PC is not configured",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{},
			},
			expectedValue:      0,
			expectedPreemption: "",
		},
		{
			name: "Only PC value is configured",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PriorityClass: &v3.PriorityClassSpec{
									Value: 12345,
								},
							},
						},
					},
				},
			},
			expectedValue:      12345,
			expectedPreemption: "",
		},
		{
			name: "Only PC Preemption is configured",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PriorityClass: &v3.PriorityClassSpec{
									Preemption: &neverPreemptionPolicy,
								},
							},
						},
					},
				},
			},
			expectedValue:      0,
			expectedPreemption: "Never",
		},
		{
			name: "Both fields are configured",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PriorityClass: &v3.PriorityClassSpec{
									Value:      12345,
									Preemption: &neverPreemptionPolicy,
								},
							},
						},
					},
				},
			},
			expectedValue:      12345,
			expectedPreemption: "Never",
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pcValue, preemption := GetDesiredPriorityClassValueAndPreemption(tt.cluster)
			assert.Equal(t, tt.expectedPreemption, preemption)
			assert.Equal(t, tt.expectedValue, pcValue)
		})
	}
}

func TestAgentCustomization_getDesiredPodDisruptionBudgetValuesAsString(t *testing.T) {
	tests := []struct {
		name                   string
		cluster                *v3.Cluster
		expectedMinAvailable   string
		expectedMaxUnavailable string
	}{
		{
			name:                   "nil cluster",
			expectedMaxUnavailable: "",
			expectedMinAvailable:   "",
		},
		{
			name: "no PDB Configured",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{},
			},
			expectedMaxUnavailable: "",
			expectedMinAvailable:   "",
		},
		{
			name: "max unavailable configured as int",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MaxUnavailable: "1",
								},
							},
						},
					},
				},
			},
			expectedMaxUnavailable: "1",
			expectedMinAvailable:   "",
		},
		{
			name: "min available configured as int",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MinAvailable: "1",
								},
							},
						},
					},
				},
			},
			expectedMaxUnavailable: "",
			expectedMinAvailable:   "1",
		},
		{
			name: "max unavailable configured as percentage",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MaxUnavailable: "50%",
								},
							},
						},
					},
				},
			},
			expectedMaxUnavailable: "50%",
			expectedMinAvailable:   "",
		},
		{
			name: "min available configured as percentage",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MinAvailable: "50%",
								},
							},
						},
					},
				},
			},
			expectedMaxUnavailable: "",
			expectedMinAvailable:   "50%",
		},
		{
			name: "both values are set to zero ints",
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MinAvailable:   "0",
									MaxUnavailable: "0",
								},
							},
						},
					},
				},
			},
			expectedMaxUnavailable: "0",
			expectedMinAvailable:   "",
		},
	}

	t.Parallel()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			minAvailable, maxUnavailable, _ := GetDesiredDisruptionBudgetValues(tt.cluster)
			assert.Equal(t, tt.expectedMinAvailable, minAvailable)
			assert.Equal(t, tt.expectedMaxUnavailable, maxUnavailable)
		})
	}

}

func TestAgentCustomization_agentSchedulingCustomizationEnabled(t *testing.T) {
	tests := []struct {
		name            string
		cluster         *v3.Cluster
		shouldBeEnabled bool
		pcEnabled       bool
		pdbEnabled      bool
	}{
		{
			name:            "customization is not enabled",
			shouldBeEnabled: false,
			pcEnabled:       false,
			pdbEnabled:      false,
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{},
			},
		},
		{
			name:            "customization is enabled - only PC",
			shouldBeEnabled: true,
			pcEnabled:       true,
			pdbEnabled:      false,
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PriorityClass: &v3.PriorityClassSpec{
									Value: 1,
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "customization is enabled - only PDB",
			shouldBeEnabled: true,
			pcEnabled:       false,
			pdbEnabled:      true,
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MinAvailable: "1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:            "customization is enabled - both",
			shouldBeEnabled: true,
			pcEnabled:       true,
			pdbEnabled:      true,
			cluster: &v3.Cluster{
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: &v3.PodDisruptionBudgetSpec{
									MinAvailable: "1",
								},
								PriorityClass: &v3.PriorityClassSpec{
									Value: 1,
								},
							},
						},
					},
				},
			},
		},
	}

	t.Parallel()

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			enabled, pcEnabled, pdbEnabled := AgentSchedulingCustomizationEnabled(tt.cluster)
			assert.Equal(t, tt.shouldBeEnabled, enabled)
			assert.Equal(t, tt.pdbEnabled, pdbEnabled)
			assert.Equal(t, tt.pcEnabled, pcEnabled)
		})
	}
}

func TestAgentCustomization_agentSchedulingCustomizationChanged(t *testing.T) {
	type test struct {
		name       string
		cluster    *v3.Cluster
		PDBDiffers bool
		PCDiffers  bool
		PCDeleted  bool
		PCCreated  bool
	}

	preemption := corev1.PreemptionPolicy("PreemptLowerPriority")

	testPC := &v3.PriorityClassSpec{
		Value:      5000,
		Preemption: &preemption,
	}

	modifiedTestPC := &v3.PriorityClassSpec{
		Value:      1,
		Preemption: &preemption,
	}

	testPDB := &v3.PodDisruptionBudgetSpec{
		MinAvailable: "1",
	}

	modifiedTestPDB := &v3.PodDisruptionBudgetSpec{
		MaxUnavailable: "1",
	}

	tests := []test{
		{
			name:       "no customization",
			PDBDiffers: false,
			PCDeleted:  false,
			PCDiffers:  false,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec:   v3.ClusterSpec{},
				Status: v3.ClusterStatus{},
			},
		},
		{
			name:       "no scheduling customization",
			PDBDiffers: false,
			PCDeleted:  false,
			PCDiffers:  false,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{},
				},
			},
		},
		{
			name:       "first time creating PC",
			PDBDiffers: false,
			PCDiffers:  true,
			PCDeleted:  false,
			PCCreated:  true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PriorityClass: testPC,
							},
						},
					},
				},
				Status: v3.ClusterStatus{},
			},
		},
		{
			name:       "first time creating PDB",
			PDBDiffers: true,
			PCDiffers:  false,
			PCDeleted:  false,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: testPDB,
							},
						},
					},
				},
				Status: v3.ClusterStatus{},
			},
		},
		{
			name:       "first time creating PDB and PC",
			PDBDiffers: true,
			PCDiffers:  true,
			PCDeleted:  false,
			PCCreated:  true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: testPDB,
								PriorityClass:       testPC,
							},
						},
					},
				},
				Status: v3.ClusterStatus{},
			},
		},
		{
			name:       "updating PDB",
			PDBDiffers: true,
			PCDiffers:  false,
			PCDeleted:  false,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PodDisruptionBudget: modifiedTestPDB,
							},
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						SchedulingCustomization: &v3.AgentSchedulingCustomization{
							PodDisruptionBudget: testPDB,
						},
					},
				},
			},
		},
		{
			name:       "updating PC",
			PDBDiffers: false,
			PCDiffers:  true,
			PCDeleted:  false,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{
								PriorityClass: modifiedTestPC,
							},
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						SchedulingCustomization: &v3.AgentSchedulingCustomization{
							PriorityClass: testPC,
						},
					},
				},
			},
		},
		{
			name:       "deleting PC",
			PDBDiffers: false,
			PCDiffers:  true,
			PCDeleted:  true,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{},
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						SchedulingCustomization: &v3.AgentSchedulingCustomization{
							PriorityClass: testPC,
						},
					},
				},
			},
		},
		{
			name:       "deleting PDB",
			PDBDiffers: true,
			PCDiffers:  false,
			PCDeleted:  false,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{},
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						SchedulingCustomization: &v3.AgentSchedulingCustomization{
							PodDisruptionBudget: testPDB,
						},
					},
				},
			},
		},
		{
			name:       "deleting both PDB and PC",
			PDBDiffers: true,
			PCDiffers:  true,
			PCDeleted:  true,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							SchedulingCustomization: &v3.AgentSchedulingCustomization{},
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						SchedulingCustomization: &v3.AgentSchedulingCustomization{
							PriorityClass:       testPC,
							PodDisruptionBudget: testPDB,
						},
					},
				},
			},
		},
		{
			name:       "deleting both PDB and PC",
			PDBDiffers: true,
			PCDiffers:  true,
			PCDeleted:  true,
			PCCreated:  false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						SchedulingCustomization: &v3.AgentSchedulingCustomization{
							PriorityClass:       testPC,
							PodDisruptionBudget: testPDB,
						},
					},
				},
			},
		},
	}

	for _, tst := range tests {
		tst := tst
		t.Run(tst.name, func(t *testing.T) {
			pdbChanged, pcChanged, pcDeleted, pcCreated := AgentSchedulingCustomizationChanged(tst.cluster)
			if pdbChanged != tst.PDBDiffers {
				t.Fail()
			}
			if pcChanged != tst.PCDiffers {
				t.Fail()
			}
			if pcDeleted != tst.PCDeleted {
				t.Fail()
			}
			if pcCreated != tst.PCCreated {
				t.Fail()
			}
		})
	}
}

func TestAgentCustomization_agentDeploymentCustomizationChanged(t *testing.T) {
	type test struct {
		name     string
		cluster  *v3.Cluster
		expected bool
	}

	testClusterAgentToleration := []corev1.Toleration{{
		Effect: "NoSchedule",
		Key:    "node-role.kubernetes.io/controlplane-test",
		Value:  "true",
	}}

	modifiedTestClusterAgentToleration := []corev1.Toleration{{
		Effect: "NoSchedule",
		Key:    "node-role.kubernetes.io/controlplane-test",
		Value:  "false",
	}}

	testClusterAgentAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
				{
					Weight: 1,
					Preference: corev1.NodeSelectorTerm{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "cattle.io/cluster-agent-test",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"true"},
							},
						},
					},
				},
			},
		},
	}

	modifiedTestClusterAgentAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
				{
					Weight: 1,
					Preference: corev1.NodeSelectorTerm{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "cattle.io/cluster-agent-modified",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"false"},
							},
						},
					},
				},
			},
		},
	}

	testClusterAgentResourceReq := &corev1.ResourceRequirements{
		Limits: map[corev1.ResourceName]resource.Quantity{
			"cpu":    *resource.NewQuantity(500, resource.DecimalSI),
			"memory": *resource.NewQuantity(250, resource.DecimalSI),
		},
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    *resource.NewQuantity(500, resource.DecimalSI),
			"memory": *resource.NewQuantity(250, resource.DecimalSI),
		},
	}

	modifiedTestClusterAgentResourceReq := &corev1.ResourceRequirements{
		Limits: map[corev1.ResourceName]resource.Quantity{
			"cpu":    *resource.NewQuantity(5, resource.DecimalSI),
			"memory": *resource.NewQuantity(2, resource.DecimalSI),
		},
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    *resource.NewQuantity(5, resource.DecimalSI),
			"memory": *resource.NewQuantity(2, resource.DecimalSI),
		},
	}

	tests := []test{
		{
			name:     "No customization",
			expected: false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec:   v3.ClusterSpec{},
				Status: v3.ClusterStatus{},
			},
		},
		{
			name:     "First time setting customization",
			expected: true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							AppendTolerations:            testClusterAgentToleration,
							OverrideAffinity:             testClusterAgentAffinity,
							OverrideResourceRequirements: testClusterAgentResourceReq,
						},
					},
				},
				Status: v3.ClusterStatus{},
			},
		},
		{
			name:     "No changes to existing customization",
			expected: false,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							AppendTolerations:            testClusterAgentToleration,
							OverrideAffinity:             testClusterAgentAffinity,
							OverrideResourceRequirements: testClusterAgentResourceReq,
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						AppendTolerations:            testClusterAgentToleration,
						OverrideAffinity:             testClusterAgentAffinity,
						OverrideResourceRequirements: testClusterAgentResourceReq,
					},
				},
			},
		},
		{
			name:     "changes to affinity override",
			expected: true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							OverrideAffinity: modifiedTestClusterAgentAffinity,
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						OverrideAffinity: testClusterAgentAffinity,
					},
				},
			},
		},
		{
			name:     "changes to tolerations",
			expected: true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							AppendTolerations: modifiedTestClusterAgentToleration,
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						AppendTolerations: testClusterAgentToleration,
					},
				},
			},
		},
		{
			name:     "changes to resource requirements",
			expected: true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							OverrideResourceRequirements: modifiedTestClusterAgentResourceReq,
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						OverrideResourceRequirements: testClusterAgentResourceReq,
					},
				},
			},
		},
		{
			name:     "changes to all",
			expected: true,
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							AppendTolerations:            testClusterAgentToleration,
							OverrideAffinity:             testClusterAgentAffinity,
							OverrideResourceRequirements: testClusterAgentResourceReq,
						},
					},
				},
				Status: v3.ClusterStatus{
					AppliedClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
						AppendTolerations:            modifiedTestClusterAgentToleration,
						OverrideAffinity:             modifiedTestClusterAgentAffinity,
						OverrideResourceRequirements: modifiedTestClusterAgentResourceReq,
					},
				},
			},
		},
	}

	for _, tst := range tests {
		tst := tst
		t.Run(tst.name, func(t *testing.T) {
			matches := AgentDeploymentCustomizationChanged(tst.cluster)
			if matches != tst.expected {
				t.Fail()
			}
		})
	}
}

func TestAgentCustomization_getAgentCustomization(t *testing.T) {
	testClusterAgentToleration := []corev1.Toleration{{
		Effect: "NoSchedule",
		Key:    "node-role.kubernetes.io/controlplane-test",
		Value:  "true",
	},
	}
	testClusterAgentAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
				{
					Weight: 1,
					Preference: corev1.NodeSelectorTerm{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "cattle.io/cluster-agent-test",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"true"},
							},
						},
					},
				},
			},
		},
	}
	testClusterAgentResourceReq := &corev1.ResourceRequirements{
		Limits: map[corev1.ResourceName]resource.Quantity{
			"cpu":    *resource.NewQuantity(500, resource.DecimalSI),
			"memory": *resource.NewQuantity(250, resource.DecimalSI),
		},
		Requests: map[corev1.ResourceName]resource.Quantity{
			"cpu":    *resource.NewQuantity(500, resource.DecimalSI),
			"memory": *resource.NewQuantity(250, resource.DecimalSI),
		},
	}

	testFleetAgentToleration := []corev1.Toleration{
		{
			Key:      "key",
			Operator: corev1.TolerationOpEqual,
			Value:    "value",
		},
	}
	testFleetAgentAffinity := &corev1.Affinity{
		NodeAffinity: &corev1.NodeAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
				{
					Weight: 1,
					Preference: corev1.NodeSelectorTerm{
						MatchExpressions: []corev1.NodeSelectorRequirement{
							{
								Key:      "fleet.cattle.io/agent",
								Operator: corev1.NodeSelectorOpIn,
								Values:   []string{"true"},
							},
						},
					},
				},
			},
		},
	}
	testFleetAgentResourceReq := &corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("1"),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse("1Gi"),
		},
	}

	tests := []struct {
		name    string
		cluster *v3.Cluster
	}{
		{
			name: "test-default",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-default",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{},
				},
			},
		},
		{
			name: "test-agent-customization",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agent-customization",
				},
				Spec: v3.ClusterSpec{
					ClusterSpecBase: v3.ClusterSpecBase{
						ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							AppendTolerations:            testClusterAgentToleration,
							OverrideAffinity:             testClusterAgentAffinity,
							OverrideResourceRequirements: testClusterAgentResourceReq,
						},
						FleetAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
							AppendTolerations:            testFleetAgentToleration,
							OverrideAffinity:             testFleetAgentAffinity,
							OverrideResourceRequirements: testFleetAgentResourceReq,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clusterAgentToleration := GetClusterAgentTolerations(tt.cluster)
			clusterAgentAffinity, clusterErr := GetClusterAgentAffinity(tt.cluster)
			clusterAgentResourceRequirements := GetClusterAgentResourceRequirements(tt.cluster)

			fleetAgentToleration := GetFleetAgentTolerations(tt.cluster)
			fleetAgentAffinity, fleetErr := GetFleetAgentAffinity(tt.cluster)
			fleetAgentResourceRequirements := GetFleetAgentResourceRequirements(tt.cluster)

			switch tt.name {
			case "test-default":
				// cluster agent
				assert.Nil(t, clusterAgentToleration)
				defaultClusterAgentAffinity, err := unmarshalAffinity(settings.ClusterAgentDefaultAffinity.Get())
				if err != nil {
					assert.FailNow(t, "failed to unmarshal node affinity: %w", err)
				}
				assert.Equal(t, defaultClusterAgentAffinity, clusterAgentAffinity)
				assert.Nil(t, clusterErr)
				assert.Nil(t, clusterAgentResourceRequirements)

				// fleet agent
				assert.Nil(t, fleetAgentToleration)
				defaultFleetAgentAffinity, err := unmarshalAffinity(settings.FleetAgentDefaultAffinity.Get())
				if err != nil {
					assert.FailNow(t, "failed to unmarshal node affinity: %w", err)
				}
				assert.Equal(t, defaultFleetAgentAffinity, fleetAgentAffinity)
				assert.Nil(t, fleetErr)
				assert.Nil(t, fleetAgentResourceRequirements)
			case "test-agent-customization":
				// cluster agent
				assert.Equal(t, testClusterAgentToleration, clusterAgentToleration)
				assert.Equal(t, testClusterAgentAffinity, clusterAgentAffinity)
				assert.Nil(t, clusterErr)
				assert.Equal(t, testClusterAgentResourceReq, clusterAgentResourceRequirements)

				// fleet agent
				assert.Equal(t, testFleetAgentToleration, fleetAgentToleration)
				assert.Equal(t, testFleetAgentAffinity, fleetAgentAffinity)
				assert.Nil(t, fleetErr)
				assert.Equal(t, testFleetAgentResourceReq, fleetAgentResourceRequirements)
			}
		})
	}

	// Simulate a user setting default affinity as an invalid str
	settings.ClusterAgentDefaultAffinity.Set("test-invalid-affinity")
	settings.FleetAgentDefaultAffinity.Set("test-invalid-affinity")

	// Run tests again and verify that when the cluster agent or fleet agent default affinity is pulled it returns
	// nil and an error.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clusterAgentAffinity, clusterErr := GetClusterAgentAffinity(tt.cluster)
			fleetAgentAffinity, fleetErr := GetFleetAgentAffinity(tt.cluster)

			switch tt.name {
			case "test-default":
				// cluster agent
				assert.Nil(t, clusterAgentAffinity)
				assert.ErrorContains(t, clusterErr, "failed to unmarshal node affinity")

				// fleet agent
				assert.Nil(t, fleetAgentAffinity)
				assert.ErrorContains(t, fleetErr, "failed to unmarshal node affinity")
			case "test-agent-customization":
				// cluster agent
				assert.Equal(t, testClusterAgentAffinity, clusterAgentAffinity)
				assert.Nil(t, clusterErr)

				// fleet agent
				assert.Equal(t, testFleetAgentAffinity, fleetAgentAffinity)
				assert.Nil(t, fleetErr)
			}
		})
	}
}
