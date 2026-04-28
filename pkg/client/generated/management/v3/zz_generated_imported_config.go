package client

const (
	ImportedConfigType                            = "importedConfig"
	ImportedConfigFieldKubeConfig                 = "kubeConfig"
	ImportedConfigFieldPrivateRegistryPullSecrets = "privateRegistryPullSecret"
	ImportedConfigFieldPrivateRegistryURL         = "privateRegistryURL"
)

type ImportedConfig struct {
	KubeConfig                 string   `json:"kubeConfig,omitempty" yaml:"kubeConfig,omitempty"`
	PrivateRegistryPullSecrets []string `json:"privateRegistryPullSecret,omitempty" yaml:"privateRegistryPullSecret,omitempty"`
	PrivateRegistryURL         string   `json:"privateRegistryURL,omitempty" yaml:"privateRegistryURL,omitempty"`
}
