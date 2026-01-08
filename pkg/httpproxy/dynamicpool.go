package httpproxy

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"
)

// DynamicCAPool manages a set of CA certificates that can be updated at runtime.
// It uses atomic.Pointer for lock-free reads of the cert pool, while mutations
// are protected by a mutex. This allows concurrent TLS handshakes to safely
// access the latest CA certificates without blocking each other.
type DynamicCAPool struct {
	mu    sync.Mutex
	pool  atomic.Pointer[x509.CertPool] // Lock-free reads for TLS handshakes
	certs map[string][]byte
}

func NewDynamicCAPool() *DynamicCAPool {
	d := &DynamicCAPool{
		certs: make(map[string][]byte),
	}
	// Initialize with system cert pool as base
	if systemPool, err := x509.SystemCertPool(); err == nil {
		d.pool.Store(systemPool)
	} else {
		d.pool.Store(x509.NewCertPool())
	}
	return d
}

// AddCA adds CA certificates for a given identifier (typically a domain).
func (d *DynamicCAPool) AddCA(id string, pemData []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.certs[id] = pemData
	d.rebuildPoolLocked()
}

func (d *DynamicCAPool) AppendCA(id string, pemData []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.certs[id]; !ok {
		d.certs[id] = pemData
	} else {
		d.certs[id] = append(d.certs[id], pemData...)
	}
	d.rebuildPoolLocked()
}

// RemoveCA removes CA certificates for a given identifier.
// The pool is rebuilt atomically without the removed CAs.
func (d *DynamicCAPool) RemoveCA(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.certs, id)
	d.rebuildPoolLocked()
}

// rebuildPoolLocked creates a new cert pool with all current certificates.
// Must be called with mu held. The new pool is stored atomically, ensuring
// lock-free visibility to readers without data races.
func (d *DynamicCAPool) rebuildPoolLocked() {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}

	for _, pem := range d.certs {
		pool.AppendCertsFromPEM(pem)
	}

	d.pool.Store(pool)
}

// GetTLSConfig returns a tls.Config with the current CA pool.
// This is called on every TLS dial, and reads the pool atomically
// without locks, ensuring we always use the latest CA certificates
// without blocking concurrent connections.
func (d *DynamicCAPool) GetTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs: d.pool.Load(),
	}
}
