package nodedriver

import (
	"context"

	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/multiclustermanager/whitelist"
	"github.com/rancher/rancher/pkg/types/config"
	"k8s.io/apimachinery/pkg/runtime"
)

func Register(ctx context.Context, management *config.ScaledContext) {
	management.Management.NodeDrivers("").AddHandler(ctx, "whitelist-proxy", sync)
}

func sync(key string, nodeDriver *v3.NodeDriver) (runtime.Object, error) {
	if key == "" || nodeDriver == nil {
		return nil, nil
	}
	if nodeDriver.DeletionTimestamp != nil {
		whitelist.Proxy.RmSource(string(nodeDriver.UID))
		return nil, nil
	}

	whitelist.Proxy.RmSource(string(nodeDriver.UID))
	for _, d := range nodeDriver.Spec.WhitelistDomains {
		whitelist.Proxy.Add(d, string(nodeDriver.UID))
	}
	return nil, nil
}
