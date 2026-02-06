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
	p.Lock()
	if p.started {
		return
	}
	p.started = true
	p.Unlock()
	proxyEndpoint.OnRemove(ctx, "proxy-accept-list-remover", p.onRemoveEndpoint)
	proxyEndpoint.OnChange(ctx, "proxy-accept-list-adder", p.onChangeEndpoint)
}

func (p *ProxyAcceptList) onRemoveEndpoint(_ string, pe *apimgmtv3.ProxyEndpoint) (*apimgmtv3.ProxyEndpoint, error) {
	if pe == nil || pe.Spec.Routes == nil {
		return pe, nil
	}
	p.RmSource(string(pe.UID))
	return pe, nil
}

func (p *ProxyAcceptList) onChangeEndpoint(_ string, pe *apimgmtv3.ProxyEndpoint) (*apimgmtv3.ProxyEndpoint, error) {
	if pe == nil || pe.Spec.Routes == nil || pe.ObjectMeta.DeletionTimestamp != nil {
		return pe, nil
	}
	// clear any previous entries for this ProxyEndpoint before adding the new ones.
	// This ensures that if a domain is removed from the ProxyEndpoint's spec, it will be removed from the accept list.
	p.RmSource(string(pe.UID))
	// re-adding all the domains for this ProxyEndpoint, including any that were not changed.
	// This is simpler and faster than trying to diff and only add/remove the changes.
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
		logrus.Debugf("domain not found in proxy accept list: %s", key)
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

// RmSource removes the provided source from all domains it is associated with.
// If any domain has no more sources after this removal, that domain will be
// removed from the accept list entirely.
func (p *ProxyAcceptList) RmSource(source string) {
	if source == "" {
		return
	}
	p.Lock()
	defer p.Unlock()
	for key, src := range p.accept {
		delete(src, source)
		if len(src) == 0 {
			delete(p.accept, key)
		}
	}
}
