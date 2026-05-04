package cluster

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	v1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	kcorev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/credentialprovider"
)

// ConvertToDockerConfigJson converts various types of secrets into a proper .dockerconfigjson format. Specifically, rke.cattle.io/auth-config, kubernetes.io/basic-auth,
// and kubernetes.io/dockerconfigjson secrets are supported. This is required as the Rancher UI may specify non-dockerconfigjson secrets on the management cluster.
func ConvertToDockerConfigJson(registryHost string, secret *kcorev1.Secret) ([]byte, error) {
	switch secret.Type {
	case v1.AuthConfigSecretType:
		if secret.Data == nil {
			return nil, fmt.Errorf("data is nil in 'rke.cattle.io/auth-config' secret")
		}
		auth, ok := secret.Data["auth"]
		if !ok {
			return nil, fmt.Errorf("'auth' key not found in 'rke.cattle.io/auth-config' secret")
		}
		username, password, found := strings.Cut(string(auth), ":")
		if !found {
			return nil, fmt.Errorf("'auth' value in 'rke.cattle.io/auth-config' is not in username:password format")
		}
		return BuildDockerConfigJson(registryHost, username, password)
	case kcorev1.SecretTypeBasicAuth:
		// basic auth simply has a username and password key
		if secret.Data == nil {
			return nil, fmt.Errorf("data is nil in 'kubernetes.io/basic-auth' secret")
		}
		username, ok := secret.Data["username"]
		if !ok {
			return nil, fmt.Errorf("secret kubernetes.io/basic-auth has no 'username' field")
		}
		password, ok := secret.Data["password"]
		if !ok {
			return nil, fmt.Errorf("secret kubernetes.io/basic-auth has no 'password' field")
		}
		return BuildDockerConfigJson(registryHost, string(username), string(password))
	case kcorev1.SecretTypeDockerConfigJson:
		if secret.Data == nil {
			return nil, fmt.Errorf("data is nil in 'kubernetes.io/dockerconfigjson' secret")
		}
		cfg, ok := secret.Data[kcorev1.DockerConfigJsonKey]
		if !ok {
			return nil, fmt.Errorf("secret 'kubernetes.io/dockerconfigjson' has no '.dockerconfigjson' field")
		}
		return cfg, nil
	default:
		return nil, fmt.Errorf("unsupported secret type: %s", secret.Type)
	}
}

func BuildDockerConfigJson(registryHostname, username, password string) ([]byte, error) {
	authConfig := credentialprovider.DockerConfigJSON{
		Auths: credentialprovider.DockerConfig{
			registryHostname: credentialprovider.DockerConfigEntry{
				Username: username,
				Password: password,
			},
		},
	}
	return json.Marshal(authConfig)
}

// UnwrapDockerConfigJson takes secret data containing a .dockerconfigjson key and unwraps it, returning the username, password,
// and auth information for the specified hostname.
func UnwrapDockerConfigJson(registryHostname string, configJson map[string][]byte) (username string, password string, auth string, err error) {
	credJson, ok := configJson[kcorev1.DockerConfigJsonKey]
	if !ok {
		return "", "", "", fmt.Errorf(".dockerconfigjson not found in secret")
	}

	var cred credentialprovider.DockerConfigJSON
	err = json.Unmarshal(credJson, &cred)
	if err != nil {
		return "", "", "", err
	}

	entry, ok := cred.Auths[registryHostname]
	if !ok {
		return "", "", "", fmt.Errorf("registry hostname not found in secret")
	}

	auth = fmt.Sprintf("%s:%s", entry.Username, entry.Password)
	return entry.Username, entry.Password, base64.StdEncoding.EncodeToString([]byte(auth)), nil
}
