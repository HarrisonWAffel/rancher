package whitelist

import (
	"context"
	"strings"
	"sync"

	apimgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	controllersv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/settings"
	"github.com/sirupsen/logrus"
)

var (
	Proxy = ProxyAcceptList{
		RWMutex:          sync.RWMutex{},
		accept:           map[string]map[string]struct{}{},
		envSettingGetter: settings.WhitelistDomain.Get,
	}
)

type ProxyAcceptList struct {
	sync.RWMutex
	// accept is a mapping between allowed domains
	// and any references to that domain from
	// ProxyEndpoints CRs, Node Driver CRs, and Kontainer drivers.
	accept           map[string]map[string]struct{}
	started          bool
	envSettingGetter func() string
}

// Start registers the onChange and onRemove handlers responsible for watching ProxyEndpoint CRs and updating the
// in-memory domain allow list.
func (p *ProxyAcceptList) Start(ctx context.Context, proxyEndpoint controllersv3.ProxyEndpointController) {
	if p.started {
		return
	}
	p.started = true
	proxyEndpoint.OnRemove(ctx, "proxy-accept-list-remover", p.onRemoveEndpoint)
	proxyEndpoint.OnChange(ctx, "proxy-accept-list-adder", p.onChangeEndpoint)
}

func (p *ProxyAcceptList) onRemoveEndpoint(_ string, pe *apimgmtv3.ProxyEndpoint) (*apimgmtv3.ProxyEndpoint, error) {
	if pe == nil || pe.Spec.Routes == nil {
		return pe, nil
	}
	for _, route := range pe.Spec.Routes {
		p.Rm(route.Domain, string(pe.UID))
	}
	return pe, nil
}

func (p *ProxyAcceptList) onChangeEndpoint(_ string, pe *apimgmtv3.ProxyEndpoint) (*apimgmtv3.ProxyEndpoint, error) {
	if pe == nil || pe.Spec.Routes == nil || pe.ObjectMeta.DeletionTimestamp != nil {
		return pe, nil
	}
	for _, route := range pe.Spec.Routes {
		p.Add(route.Domain, string(pe.UID))
	}
	return pe, nil
}

// Get returns all domains in the accept list, including those
// defined in the CATTLE_WHITELIST_DOMAIN setting.
func (p *ProxyAcceptList) Get() []string {
	p.RLock()
	defer p.RUnlock()
	envValues := p.envSettingGetter()
	var r []string
	if envValues != "" {
		r = strings.Split(envValues, ",")
	}
	for k := range p.accept {
		r = append(r, k)
	}
	return r
}

// Add adds a domain to the accept list. The source parameter
// is used to track what is adding the domain (e.g., NodeDriver name).
// If source is an empty string, it defaults to "NodeDriver".
func (p *ProxyAcceptList) Add(key, source string) {
	p.Lock()
	defer p.Unlock()
	if source == "" {
		source = "NodeDriver"
	}
	_, ok := p.accept[key]
	if !ok {
		p.accept[key] = map[string]struct{}{
			source: {},
		}
		return
	}
	p.accept[key][source] = struct{}{}
}

// Rm removes a domain from the accept list for the given source.
// A domain will only be removed entirely if there are no more sources
// referencing it.
func (p *ProxyAcceptList) Rm(key, source string) {
	if key == "" || source == "" {
		return
	}
	p.Lock()
	defer p.Unlock()

	// get all the sources for this domain
	// (Node Drivers, ProxyEndpoints, etc)
	sources, ok := p.accept[key]
	if !ok {
		logrus.Info("domain not found in proxy accept list: ", key)
		return
	}

	_, present := sources[source]
	if !present {
		return
	}
	delete(sources, source)

	// if there are no more sources for this domain, remove the domain entry
	if len(sources) == 0 {
		delete(p.accept, key)
		return
	}
}
