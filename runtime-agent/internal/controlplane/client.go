// Package controlplane is the agent's only transport to the control plane:
// mutual TLS with hot-reloaded client certificates.
//
// The agent sits inline on customer LLM traffic; its credential to the control
// plane must be a rotating certificate, not a long-lived API key. Server
// identity is pinned to the platform CA (not the system trust store), and the
// client certificate is re-read on a timer so cert-manager rotation needs no
// process restart.
package controlplane

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// reloadInterval is how often the client re-reads its certificate from disk.
const reloadInterval = 5 * time.Minute

type certReloader struct {
	mu       sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func newCertReloader(certPath, keyPath string) (*certReloader, error) {
	r := &certReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	// cert-manager (or the agent installer's cron) rewrites the files; we
	// re-read on a timer so rotation needs no process restart.
	go func() {
		t := time.NewTicker(reloadInterval)
		defer t.Stop()
		for range t.C {
			_ = r.reload() // keep serving the old cert on transient errors
		}
	}()
	return r, nil
}

func (r *certReloader) reload() error {
	c, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("reload client cert: %w", err)
	}
	r.mu.Lock()
	r.cert = &c
	r.mu.Unlock()
	return nil
}

func (r *certReloader) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// NewHTTPClient returns the only HTTP client the agent may use to reach the
// control plane. TLS 1.3 minimum; server identity is pinned to the platform CA
// (caPath), not the system trust store. The client certificate (certPath,
// keyPath) is hot-reloaded for rotation.
func NewHTTPClient(caPath, certPath, keyPath string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA bundle %q contains no certificates", caPath)
	}
	reloader, err := newCertReloader(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:           tls.VersionTLS13,
				RootCAs:              pool,
				GetClientCertificate: reloader.getClientCertificate,
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
		},
	}, nil
}
