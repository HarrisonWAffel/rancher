package meta

import (
	"context"
	"fmt"
	"strings"

	ctrlv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

type CommonArgs struct {
	Auth              authorizer.Authorizer
	UserCache         ctrlv3.UserCache
	SecretCache       v1.SecretCache
	CloudCredentialID string
}

func GetCloudCredential(ctx context.Context, args CommonArgs) (*corev1.Secret, error) {
	userInfo, ok := request.UserFrom(ctx)
	if !ok {
		return &corev1.Secret{}, fmt.Errorf("missing user info")
	}

	namespace, credentialID, found := strings.Cut(args.CloudCredentialID, ":")
	if !found {
		return &corev1.Secret{}, fmt.Errorf("invalid cloud credential ID format")
	}

	decision, _, err := args.Auth.Authorize(ctx, &authorizer.AttributesRecord{
		User:            userInfo,
		Verb:            "get",
		Resource:        "secrets",
		APIVersion:      "v1",
		Name:            credentialID,
		Namespace:       namespace,
		ResourceRequest: true,
	})
	if err != nil {
		return &corev1.Secret{}, err
	}

	if decision == authorizer.DecisionDeny {
		return &corev1.Secret{}, fmt.Errorf("user does not have access to specified cloud credential or it does not exist")
	}

	secret, err := args.SecretCache.Get(namespace, credentialID)
	if err != nil {
		return &corev1.Secret{}, err
	}

	return secret, nil
}
