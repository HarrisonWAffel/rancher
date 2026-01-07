package httpproxy

import (
	"context"

	ui "github.com/rancher/rancher/pkg/apis/ui.cattle.io/v1"
	uiv1 "github.com/rancher/rancher/pkg/generated/controllers/ui.cattle.io/v1"
	"github.com/rancher/rancher/pkg/wrangler"
	"github.com/sirupsen/logrus"
)

type proxyManager struct {
	client        uiv1.ProxyEndpointClient
	cache         uiv1.ProxyEndpointCache
	dynamicCAPool *DynamicCAPool
}

func Register(ctx context.Context, wCtx *wrangler.Context) {
	// Create shared dynamic CA pool
	dynamicCAPool := NewDynamicCAPool()

	pm := proxyManager{
		client:        wCtx.UI.ProxyEndpoint(),
		cache:         wCtx.UI.ProxyEndpoint().Cache(),
		dynamicCAPool: dynamicCAPool,
	}

	wCtx.UI.ProxyEndpoint().OnChange(ctx, "onMeta", pm.onMetaChange)
	wCtx.UI.ProxyEndpoint().OnRemove(ctx, "removeMeta", pm.onRemove)

}

// onMeta watches metaproxy CRs and adjusts the dynamic certificate pool based off of the most recent
// CA certificate data.
func (p *proxyManager) onMetaChange(_ string, metaProxy *ui.ProxyEndpoint) (*ui.ProxyEndpoint, error) {
	if metaProxy == nil {
		return nil, nil
	}

	if len(metaProxy.Spec.Certificates) != 0 {
		p.dynamicCAPool.AddCA(metaProxy.ObjectMeta.Name, []byte(metaProxy.Spec.Certificates))
	}

	return metaProxy, nil
}

func (p *proxyManager) onRemove(_ string, metaProxy *ui.ProxyEndpoint) (*ui.ProxyEndpoint, error) {
	if metaProxy == nil {
		return nil, nil
	}

	if len(metaProxy.Spec.Certificates) != 0 {
		// Remove the CA certificates from the pool when ProxyEndpoint is deleted.
		// This ensures we no longer trust these CAs for new connections.
		p.dynamicCAPool.RemoveCA(metaProxy.ObjectMeta.Name)
		logrus.Infof("Removed CA certificates for domain: %s", metaProxy.Spec.UrlPattern)
	}

	return metaProxy, nil
}
