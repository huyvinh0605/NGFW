package inspection

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	defaultLeafCacheEntries = 1024
	defaultLeafCacheTTL     = 24 * time.Hour
)

type cachedLeaf struct {
	host      string
	cert      tls.Certificate
	expiresAt time.Time
}

type MITMCA struct {
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	fingerprint string
	mu          sync.Mutex
	cache       map[string]*list.Element
	lru         *list.List
	maxEntries  int
	ttl         time.Duration
	now         func() time.Time
}

// InitMITMCA is an explicit provisioning operation. Runtime LoadMITMCA never
// creates a CA when artifacts are absent or invalid.
func InitMITMCA(certPath, keyPath string) (*MITMCA, error) {
	if err := validateCAPaths(certPath, keyPath); err != nil {
		return nil, err
	}
	if err := ensurePrivateKeyDirectory(filepath.Dir(keyPath)); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return nil, err
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Lstat(path); err == nil {
			return nil, fmt.Errorf("CA artifact already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "NGFW Lab Inspection CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeNewArtifact(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := writeNewArtifact(certPath, certPEM, 0644); err != nil {
		_ = os.Remove(keyPath) // only the key just created with O_EXCL
		return nil, err
	}
	return LoadMITMCA(certPath, keyPath)
}

// LoadMITMCA verifies the pre-provisioned CA and refuses insecure key paths.
// No fallback CA or certificate is generated in this runtime path.
func LoadMITMCA(certPath, keyPath string) (*MITMCA, error) {
	if err := validateCAPaths(certPath, keyPath); err != nil {
		return nil, err
	}
	if err := checkPrivateKeyDirectory(filepath.Dir(keyPath)); err != nil {
		return nil, err
	}
	if err := checkRegularArtifact(keyPath, true); err != nil {
		return nil, err
	}
	if err := checkRegularArtifact(certPath, false); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read MITM CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read MITM CA key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid MITM CA PEM artifacts")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("MITM CA certificate/key mismatch or not a signing CA")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("MITM CA certificate is not currently valid")
	}
	hash := sha256.Sum256(cert.Raw)
	return &MITMCA{
		cert: cert, key: key, fingerprint: hex.EncodeToString(hash[:]),
		cache: make(map[string]*list.Element), lru: list.New(),
		maxEntries: defaultLeafCacheEntries, ttl: defaultLeafCacheTTL, now: time.Now,
	}, nil
}

func (ca *MITMCA) FingerprintSHA256() string {
	if ca == nil {
		return ""
	}
	return ca.fingerprint
}

func (ca *MITMCA) ConfigureLeafCache(entries int, ttl time.Duration) error {
	if ca == nil || entries < 1 || entries > 4096 || ttl < time.Minute || ttl > 24*time.Hour {
		return errors.New("invalid leaf certificate cache limits")
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.maxEntries, ca.ttl = entries, ttl
	ca.cache = make(map[string]*list.Element)
	ca.lru.Init()
	return nil
}

// CertificateFor serializes cache misses under one short mutex. This also
// deduplicates concurrent generation for the same target without an unbounded
// per-host goroutine or inflight map.
func (ca *MITMCA) CertificateFor(host string) (tls.Certificate, error) {
	if ca == nil || ca.cert == nil || ca.key == nil {
		return tls.Certificate{}, errors.New("TLS_CA_UNAVAILABLE")
	}
	host, ip, err := normalizeLeafHost(host)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	now := ca.now()
	if now.Before(ca.cert.NotBefore) || !now.Before(ca.cert.NotAfter) {
		return tls.Certificate{}, errors.New("TLS_CA_UNAVAILABLE")
	}
	if element := ca.cache[host]; element != nil {
		entry := element.Value.(cachedLeaf)
		if now.Before(entry.expiresAt) {
			ca.lru.MoveToFront(element)
			return entry.cert, nil
		}
		ca.removeLeaf(element)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	validUntil := now.Add(7 * 24 * time.Hour)
	if validUntil.After(ca.cert.NotAfter) {
		validUntil = ca.cert.NotAfter
	}
	if !validUntil.After(now) {
		return tls.Certificate{}, errors.New("TLS_CA_UNAVAILABLE")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Minute), NotAfter: validUntil,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}
	for len(ca.cache) >= ca.maxEntries {
		ca.removeLeaf(ca.lru.Back())
	}
	ca.cache[host] = ca.lru.PushFront(cachedLeaf{host: host, cert: cert, expiresAt: now.Add(ca.ttl)})
	return cert, nil
}

func (ca *MITMCA) removeLeaf(element *list.Element) {
	if element == nil {
		return
	}
	delete(ca.cache, element.Value.(cachedLeaf).host)
	ca.lru.Remove(element)
}

func (ca *MITMCA) TLSConfig(nextProtos []string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: append([]string(nil), nextProtos...), GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := ca.CertificateFor(hello.ServerName)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		serial, err := rand.Int(rand.Reader, limit)
		if err != nil || serial.Sign() != 0 {
			return serial, err
		}
	}
}

func normalizeLeafHost(raw string) (string, net.IP, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 {
		return "", nil, errors.New("TLS_SNI_UNAVAILABLE")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), ip, nil
	}
	if !strings.Contains(host, ".") {
		return "", nil, errors.New("TLS_SNI_UNAVAILABLE")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", nil, errors.New("TLS_SNI_UNAVAILABLE")
		}
		for _, char := range label {
			if char != '-' && !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') {
				return "", nil, errors.New("TLS_SNI_UNAVAILABLE")
			}
		}
	}
	return host, nil, nil
}

func validateCAPaths(certPath, keyPath string) error {
	if !filepath.IsAbs(certPath) || !filepath.IsAbs(keyPath) || filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return errors.New("CA certificate and key require distinct absolute paths")
	}
	return nil
}

func ensurePrivateKeyDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	return checkPrivateKeyDirectory(directory)
}

func checkPrivateKeyDirectory(directory string) error {
	stat, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && stat.Mode().Perm()&0077 != 0 {
		return errors.New("CA key directory must be a private 0700 directory")
	}
	return nil
}

func checkRegularArtifact(path string, private bool) error {
	stat, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() || stat.Mode()&os.ModeSymlink != 0 {
		return errors.New("CA artifact must be a regular file, not a symlink")
	}
	if private && runtime.GOOS != "windows" && stat.Mode().Perm()&0077 != 0 {
		return errors.New("CA private key must not be group/world accessible")
	}
	return nil
}

func writeNewArtifact(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(content)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(writeErr, closeErr)
	}
	return nil
}
