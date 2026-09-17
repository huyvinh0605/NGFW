package inspection

import (
	"crypto/x509"
	"os"
	"testing"
)

func TestMITMCAIssuesCertificate(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadMITMCA(dir+"/ca.crt", dir+"/ca.key", true)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.CertificateFor("app.example")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "app.example" {
		t.Fatalf("unexpected names: %v", leaf.DNSNames)
	}
	if _, err := os.Stat(dir + "/ca.key"); err != nil {
		t.Fatal(err)
	}
}
