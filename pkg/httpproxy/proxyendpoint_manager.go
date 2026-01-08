package httpproxy

import (
	"context"

	ui "github.com/rancher/rancher/pkg/apis/ui.cattle.io/v1"
	uiv1 "github.com/rancher/rancher/pkg/generated/controllers/ui.cattle.io/v1"
	"github.com/rancher/rancher/pkg/wrangler"
)

type proxyManager struct {
	client        uiv1.ProxyEndpointCollectionClient
	cache         uiv1.ProxyEndpointCollectionCache
	dynamicCAPool *DynamicCAPool
}

func Register(ctx context.Context, wCtx *wrangler.Context) {
	// Create shared dynamic CA pool
	dynamicCAPool := NewDynamicCAPool()

	pm := proxyManager{
		client:        wCtx.UI.ProxyEndpointCollection(),
		cache:         wCtx.UI.ProxyEndpointCollection().Cache(),
		dynamicCAPool: dynamicCAPool,
	}

	wCtx.UI.ProxyEndpointCollection().OnChange(ctx, "onMeta", pm.onMetaChange)
}

// onMeta watches metaproxy CRs and adjusts the dynamic certificate pool based off of the most recent
// CA certificate data.
func (p *proxyManager) onMetaChange(_ string, metaProxy *ui.ProxyEndpointCollection) (*ui.ProxyEndpointCollection, error) {
	if metaProxy == nil {
		return nil, nil
	}

	if metaProxy.ObjectMeta.DeletionTimestamp != nil {
		p.dynamicCAPool.RemoveCA(metaProxy.ObjectMeta.Name)
		return nil, nil
	}

	for _, e := range metaProxy.Spec.Endpoints {
		for _, endpoint := range e.Endpoints {
			p.dynamicCAPool.AppendCA(metaProxy.ObjectMeta.Name, []byte(endpoint.Certificates))
		}
	}

	return metaProxy, nil
}
