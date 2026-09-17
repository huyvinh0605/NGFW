package inspection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type MITMCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	cache map[string]tls.Certificate
}

func LoadMITMCA(certPath, keyPath string, create bool) (*MITMCA, error) {
	data, certErr := os.ReadFile(certPath)
	keyData, keyErr := os.ReadFile(keyPath)
	if (certErr != nil || keyErr != nil) && !create {
		return nil, fmt.Errorf("read MITM CA: %w", certErr)
	}
	if certErr == nil && keyErr == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid CA certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		keyBlock, _ := pem.Decode(keyData)
		if keyBlock == nil {
			return nil, fmt.Errorf("invalid CA key")
		}
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		return &MITMCA{cert: cert, key: key, cache: map[string]tls.Certificate{}}, nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "NGFW Lab Inspection CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return nil, err
	}
	return &MITMCA{cert: cert, key: key, cache: map[string]tls.Certificate{}}, nil
}
func (ca *MITMCA) CertificateFor(host string) (tls.Certificate, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "ngfw.invalid"
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if c, ok := ca.cache[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{host}}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.DNSNames = nil
		tmpl.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: tmpl}
	_ = keyDER
	ca.cache[host] = cert
	return cert, nil
}
func (ca *MITMCA) TLSConfig(nextProtos []string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: nextProtos, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, err := ca.CertificateFor(hello.ServerName)
		return &c, err
	}}
}
