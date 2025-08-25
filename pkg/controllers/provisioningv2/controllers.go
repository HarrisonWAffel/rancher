package provisioningv2

import (
	"context"

	"github.com/rancher/rancher/pkg/controllers/provisioningv2/cluster"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/fleetcluster"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/fleetworkspace"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/harvestercleanup"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/machineconfigcleanup"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/managedchart"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/provisioningcluster"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/provisioninglog"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/secret"
	"github.com/rancher/rancher/pkg/features"
	"github.com/rancher/rancher/pkg/provisioningv2/kubeconfig"
	"github.com/rancher/rancher/pkg/wrangler"
)

func Register(ctx context.Context, clients *wrangler.CAPIContext, kubeconfigManager *kubeconfig.Manager) {
	cluster.Register(ctx, clients, kubeconfigManager)
	if features.MCM.Enabled() {
		secret.Register(ctx, clients.Context)
	}
	provisioningcluster.Register(ctx, clients)
	provisioninglog.Register(ctx, clients.Context)
	machineconfigcleanup.Register(ctx, clients.Context)

	if features.Fleet.Enabled() {
		managedchart.Register(ctx, clients.Context)
		fleetcluster.Register(ctx, clients.Context)
		fleetworkspace.Register(ctx, clients.Context)
	}

	if features.Harvester.Enabled() {
		harvestercleanup.Register(ctx, clients)
	}
}
