package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCACommandRequiresExplicitInit(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	t.Setenv("NGFW_PROXY_CA_CERT", certPath)
	t.Setenv("NGFW_PROXY_CA_KEY", keyPath)
	if err := runCACommand([]string{"fingerprint"}); err == nil {
		t.Fatal("fingerprint command generated missing CA")
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("CA key was created without init: %v", err)
	}
	if err := runCACommand([]string{"init"}); err != nil {
		t.Fatal(err)
	}
	if err := runCACommand([]string{"fingerprint"}); err != nil {
		t.Fatal(err)
	}
	if err := runCACommand([]string{"init"}); err == nil {
		t.Fatal("CA init silently replaced existing trust anchor")
	}
	if err := runCACommand([]string{"unknown"}); err == nil {
		t.Fatal("unknown CA subcommand accepted")
	}
}
