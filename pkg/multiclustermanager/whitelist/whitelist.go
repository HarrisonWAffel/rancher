package whitelist

import (
	"strings"
	"sync"

	"github.com/rancher/rancher/pkg/settings"
)

var (
	Proxy = ProxyAcceptList{
		RWMutex: sync.RWMutex{},
		accept:  map[string]struct{}{},
	}
)

type ProxyAcceptList struct {
	sync.RWMutex
	accept map[string]struct{}
}

func (p *ProxyAcceptList) Get() []string {
	p.RLock()
	defer p.RUnlock()
	v := settings.WhitelistDomain.Get()
	r := strings.Split(v, ",")
	for k := range p.accept {
		r = append(r, k)
	}
	return r
}

func (p *ProxyAcceptList) Contains(key string) bool {
	p.Lock()
	defer p.Unlock()
	_, ok := p.accept[key]
	return ok
}

func (p *ProxyAcceptList) Add(key string) {
	p.Lock()
	defer p.Unlock()
	p.accept[key] = struct{}{}
}

func (p *ProxyAcceptList) Set(key string) {
	p.Lock()
	defer p.Unlock()
	p.accept[key] = struct{}{}
}

func (p *ProxyAcceptList) Rm(key string) {
	p.Lock()
	defer p.Unlock()
	delete(p.accept, key)
}
