package controlplane

import (
	"os"
	"sync"
	"testing"
	"time"
)

// TestCertReloaderRotationUnderConcurrentHandshakes extends
// TestCertReloaderPicksUpRotation (which rotates sequentially) to the mid-
// traffic case: in production the TLS stack calls getClientCertificate on every
// handshake WHILE the reload timer swaps the cert. This drives both concurrently
// under -race, proving the RWMutex-guarded swap has no data race and that a
// handshake never observes a nil or torn certificate mid-rotation.
func TestCertReloaderRotationUnderConcurrentHandshakes(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey, _, _ := newKeyCert(t, "Test Platform CA", nil, nil, true, nil)
	_, _, cert1PEM, key1PEM := newKeyCert(t, "agent-v1", caCert, caKey, false, nil)
	_, _, cert2PEM, key2PEM := newKeyCert(t, "agent-v2", caCert, caKey, false, nil)
	certPath := writeFile(t, dir, "agent.crt", cert1PEM)
	keyPath := writeFile(t, dir, "agent.key", key1PEM)

	r, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Rotator: swap the files between v1/v2 and reload. Only this goroutine
	// writes the files (os.WriteFile, not the t.Fatal-using writeFile helper),
	// so there is no file-write race; reload errors on a transient partial read
	// are ignored exactly as production does (keep serving the old cert).
	wg.Add(1)
	go func() {
		defer wg.Done()
		v2 := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			cp, kp := cert1PEM, key1PEM
			if v2 {
				cp, kp = cert2PEM, key2PEM
			}
			_ = os.WriteFile(certPath, cp, 0o600)
			_ = os.WriteFile(keyPath, kp, 0o600)
			_ = r.reload()
			v2 = !v2
		}
	}()

	// Handshakers: the hot-path read the TLS stack performs.
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 500 {
				cert, err := r.getClientCertificate(nil)
				if err != nil || cert == nil || len(cert.Certificate) == 0 {
					t.Errorf("handshake got an invalid cert mid-rotation: err=%v cert=%v", err, cert)
					return
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
