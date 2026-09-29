package inspection

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMITMCAExplicitInitAndNoRuntimeFallback(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, err := LoadMITMCA(certPath, keyPath); err == nil {
		t.Fatal("runtime silently generated a missing CA")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("runtime created key during load: %v", err)
	}
	ca, err := InitMITMCA(certPath, keyPath)
	if err != nil || len(ca.FingerprintSHA256()) != 64 {
		t.Fatalf("explicit init failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		stat, err := os.Stat(keyPath)
		if err != nil || stat.Mode().Perm() != 0600 {
			t.Fatalf("private key mode = %v, %v", stat, err)
		}
	}
	loaded, err := LoadMITMCA(certPath, keyPath)
	if err != nil || loaded.FingerprintSHA256() != ca.FingerprintSHA256() {
		t.Fatalf("CA load/fingerprint drift: %v", err)
	}
	if _, err := InitMITMCA(certPath, keyPath); err == nil {
		t.Fatal("init overwrote existing CA")
	}
	cert, err := ca.CertificateFor("APP.EXAMPLE.")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "app.example" || leaf.SerialNumber.Sign() == 0 || leaf.NotAfter.Sub(leaf.NotBefore) > 8*24*time.Hour {
		t.Fatalf("unexpected leaf identity/lifetime: %+v", leaf)
	}
	if err := leaf.CheckSignatureFrom(loaded.cert); err != nil {
		t.Fatalf("leaf is not signed by provisioned CA: %v", err)
	}
	ipCert, err := ca.CertificateFor("192.0.2.10")
	if err != nil || len(ipCert.Leaf.IPAddresses) != 1 || ipCert.Leaf.IPAddresses[0].String() != "192.0.2.10" || len(ipCert.Leaf.DNSNames) != 0 {
		t.Fatalf("IP SAN was not preserved: %+v %v", ipCert.Leaf, err)
	}
	if _, err := ca.CertificateFor(""); err == nil {
		t.Fatal("missing SNI silently received fallback certificate")
	}
}

func TestMITMCABoundedLRUTTLAndConcurrentDedup(t *testing.T) {
	dir := t.TempDir()
	ca, err := InitMITMCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.ConfigureLeafCache(2, time.Minute); err != nil {
		t.Fatal(err)
	}
	a1, _ := ca.CertificateFor("a.example")
	_, _ = ca.CertificateFor("b.example")
	a2, _ := ca.CertificateFor("a.example") // refresh LRU
	if a1.Leaf.SerialNumber.Cmp(a2.Leaf.SerialNumber) != 0 {
		t.Fatal("cache hit regenerated a leaf")
	}
	_, _ = ca.CertificateFor("c.example") // evicts b
	if len(ca.cache) != 2 || ca.cache["b.example"] != nil {
		t.Fatalf("LRU capacity/eviction failed: %d", len(ca.cache))
	}
	b2, err := ca.CertificateFor("b.example")
	if err != nil || b2.Leaf == nil || len(ca.cache) != 2 {
		t.Fatalf("evicted leaf was not regenerated within capacity: %v", err)
	}
	base := time.Now()
	ca.now = func() time.Time { return base }
	first, err := ca.CertificateFor("ttl.example")
	if err != nil {
		t.Fatal(err)
	}
	ca.now = func() time.Time { return base.Add(61 * time.Second) }
	second, err := ca.CertificateFor("ttl.example")
	if err != nil || first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatalf("TTL did not expire leaf: %v", err)
	}
	// Restore real time before concurrent access; all misses for one hostname
	// are serialized under the same bounded cache lock.
	ca.now = time.Now
	var wg sync.WaitGroup
	serials := make(chan string, 24)
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			leaf, err := ca.CertificateFor("concurrent.example")
			if err != nil {
				serials <- "error"
				return
			}
			serials <- leaf.Leaf.SerialNumber.String()
		}()
	}
	wg.Wait()
	close(serials)
	serial := ""
	for current := range serials {
		if serial == "" {
			serial = current
		}
		if current != serial || current == "error" {
			t.Fatalf("concurrent leaf generation was duplicated: %q vs %q", current, serial)
		}
	}
}

func TestMITMCARejectsUnsafeArtifacts(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, err := InitMITMCA(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadMITMCA(certPath, keyPath); err == nil {
			t.Fatal("world-readable CA key was accepted")
		}
		if err := os.Chmod(keyPath, 0600); err != nil {
			t.Fatal(err)
		}
	}
	otherDir := t.TempDir()
	_, err := InitMITMCA(filepath.Join(otherDir, "other.crt"), filepath.Join(otherDir, "other.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMITMCA(certPath, filepath.Join(otherDir, "other.key")); err == nil {
		t.Fatal("mismatched CA key/certificate were accepted")
	}
}
