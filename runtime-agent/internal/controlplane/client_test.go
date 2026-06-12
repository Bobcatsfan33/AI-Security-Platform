package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// certs are generated in-test (written to t.TempDir()) so no private key is ever
// committed to the repo.

func newKeyCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, isCA bool, ips []net.IP) (*x509.Certificate, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		IPAddresses:           ips,
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return cert, key, certPEM, keyPEM
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// platformPKI generates a CA + an agent client cert, written to t.TempDir().
func platformPKI(t *testing.T) (caPath, certPath, keyPath string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	caCert, caPriv, caPEM, _ := newKeyCert(t, "Test Platform CA", nil, nil, true, nil)
	_, _, agentCertPEM, agentKeyPEM := newKeyCert(t, "test-agent", caCert, caPriv, false, nil)
	caPath = writeFile(t, dir, "platform-ca.pem", caPEM)
	certPath = writeFile(t, dir, "agent.crt", agentCertPEM)
	keyPath = writeFile(t, dir, "agent.key", agentKeyPEM)
	return caPath, certPath, keyPath, caCert, caPriv
}

func TestClientRefusesServerWithoutPlatformCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	caPath, certPath, keyPath, _, _ := platformPKI(t)
	c, err := NewHTTPClient(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("agent accepted a server not signed by the platform CA")
	}
}

func TestClientAcceptsServerSignedByPlatformCA(t *testing.T) {
	caPath, certPath, keyPath, ca, caKey := platformPKI(t)

	// A server cert signed by the same platform CA, valid for 127.0.0.1.
	_, _, srvCertPEM, srvKeyPEM := newKeyCert(t, "control-plane", ca, caKey, false, []net.IP{net.ParseIP("127.0.0.1")})
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}}
	srv.StartTLS()
	defer srv.Close()

	c, err := NewHTTPClient(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("agent rejected a server signed by the platform CA: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMinimumTLS13(t *testing.T) {
	caPath, certPath, keyPath, _, _ := platformPKI(t)
	c, err := NewHTTPClient(caPath, certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("transport is not *http.Transport")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("control-plane transport must require TLS 1.3")
	}
}

func TestCertReloaderPicksUpRotation(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _, _ := newKeyCert(t, "Test Platform CA", nil, nil, true, nil)

	c1, _, cert1PEM, key1PEM := newKeyCert(t, "agent-v1", caCert, caKey, false, nil)
	certPath := writeFile(t, dir, "agent.crt", cert1PEM)
	keyPath := writeFile(t, dir, "agent.key", key1PEM)

	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.getClientCertificate(nil)
	if got.Leaf == nil {
		// Leaf isn't populated by LoadX509KeyPair; parse to compare serials.
		parsed, _ := x509.ParseCertificate(got.Certificate[0])
		got.Leaf = parsed
	}
	if got.Leaf.SerialNumber.Cmp(c1.SerialNumber) != 0 {
		t.Fatal("reloader did not load the initial certificate")
	}

	// Rotate the files on disk, then reload (the production path does this on a
	// timer).
	c2, _, cert2PEM, key2PEM := newKeyCert(t, "agent-v2", caCert, caKey, false, nil)
	writeFile(t, dir, "agent.crt", cert2PEM)
	writeFile(t, dir, "agent.key", key2PEM)
	if err := r.reload(); err != nil {
		t.Fatal(err)
	}
	rotated, _ := r.getClientCertificate(nil)
	parsed, _ := x509.ParseCertificate(rotated.Certificate[0])
	if parsed.SerialNumber.Cmp(c2.SerialNumber) != 0 {
		t.Fatal("reloader did not pick up the rotated certificate")
	}
}

func TestMissingCABundleIsRejected(t *testing.T) {
	_, certPath, keyPath, _, _ := platformPKI(t)
	if _, err := NewHTTPClient(filepath.Join(t.TempDir(), "nope.pem"), certPath, keyPath); err == nil {
		t.Fatal("expected error for a missing CA bundle")
	}
}
