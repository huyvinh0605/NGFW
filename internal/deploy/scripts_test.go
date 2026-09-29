package deploy_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLinuxShellScriptsParse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash syntax is verified on the Ubuntu target; Windows bash aliases may require WSL")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	root := repositoryRoot(t)
	paths := []string{
		"scripts/install-linux.sh",
		"scripts/start-suricata-sensor.sh",
		"scripts/rotate-suricata-logs.sh",
		"scripts/verify-m3-linux.sh",
		"tests/integration/m3/probe-capabilities.sh",
		"tests/integration/m3/replay-suricata.sh",
	}
	args := []string{"-n"}
	for _, path := range paths {
		args = append(args, filepath.Join(root, filepath.FromSlash(path)))
	}
	if output, err := exec.Command(bash, args...).CombinedOutput(); err != nil {
		t.Fatalf("bash -n failed: %v\n%s", err, output)
	}
}

func TestSensorLauncherRejectsUnknownModeBeforeMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("launcher targets Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	root := repositoryRoot(t)
	command := exec.Command(bash, filepath.Join(root, "scripts", "start-suricata-sensor.sh"), "invalid")
	command.Env = append(os.Environ(), "NGFW_INSPECTION_ROOT="+t.TempDir())
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("invalid sensor mode succeeded")
	}
	if !strings.Contains(string(output), "ids|ips") {
		t.Fatalf("launcher returned no actionable usage: %s", output)
	}
}

func TestSensorLauncherUsesLiveCaptureModeAndNotPCAPSocketMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("launcher targets Linux")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	root := repositoryRoot(t)
	work := t.TempDir()
	configRoot := filepath.Join(work, "config")
	runtimeRoot := filepath.Join(work, "runtime")
	if err := os.MkdirAll(configRoot, 0755); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ids", "ips"} {
		if err := os.WriteFile(filepath.Join(configRoot, mode+".yaml"), []byte("%YAML 1.1\n---\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	fake := filepath.Join(work, "suricata-fake")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$NGFW_ARG_CAPTURE\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode string
		want []string
	}{{"ids", []string{"--nflog=100"}}, {"ips", []string{"-q", "100"}}} {
		capture := filepath.Join(work, test.mode+"-args.txt")
		command := exec.Command(bash, filepath.Join(root, "scripts", "start-suricata-sensor.sh"), test.mode)
		command.Env = append(os.Environ(),
			"NGFW_SURICATA_BINARY="+fake,
			"NGFW_INSPECTION_CONFIG_ROOT="+configRoot,
			"NGFW_INSPECTION_ROOT="+runtimeRoot,
			"NGFW_ARG_CAPTURE="+capture,
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s launcher: %v\n%s", test.mode, err, output)
		}
		payload, err := os.ReadFile(capture)
		if err != nil {
			t.Fatal(err)
		}
		args := strings.Fields(string(payload))
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--unix-socket") {
			t.Fatalf("%s launcher selected Suricata PCAP socket runmode: %s", test.mode, joined)
		}
		for _, expected := range test.want {
			if !strings.Contains(argsAsLines(payload), expected) {
				t.Fatalf("%s launcher missing %q: %s", test.mode, expected, joined)
			}
		}
	}
}

func argsAsLines(payload []byte) string { return "\n" + strings.TrimSpace(string(payload)) + "\n" }

func TestM3DeploymentContractsAreExplicitAndLeastPrivilege(t *testing.T) {
	root := repositoryRoot(t)
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	apiUnit := read("deploy/ngfw-api.service")
	if strings.Contains(apiUnit, "CAP_NET_ADMIN") || strings.Contains(apiUnit, "ngfw-inspect") {
		t.Fatalf("management API gained dataplane/sensor privilege:\n%s", apiUnit)
	}
	for _, path := range []string{"deploy/ngfw-suricata-ids.service", "deploy/ngfw-suricata-ips.service"} {
		unit := read(path)
		for _, expected := range []string{"User=ngfw-inspect", "NoNewPrivileges=true", "ProtectSystem=strict", "ReadOnlyPaths=/etc/ngfw/inspection", "CapabilityBoundingSet=CAP_NET_ADMIN"} {
			if !strings.Contains(unit, expected) {
				t.Fatalf("%s missing %q", path, expected)
			}
		}
		if strings.Contains(unit, "/var/lib/ngfw/management") || strings.Contains(unit, "/run/ngfw/engine.sock") {
			t.Fatalf("%s can access management/engine-owned state", path)
		}
	}
	ids := read("deploy/inspection/ids.yaml")
	ips := read("deploy/inspection/ips.yaml")
	if !strings.Contains(ids, "group: 100") || !strings.Contains(ids, "stream:\n  inline: no") {
		t.Fatal("IDS config does not select NFLOG group 100 in passive mode")
	}
	for _, expected := range []string{"fail-open: yes", "stream:\n  inline: yes", "filename: /var/lib/ngfw/inspection/ips/control.sock"} {
		if !strings.Contains(ips, expected) {
			t.Fatalf("IPS config missing %q", expected)
		}
	}
	installer := read("scripts/install-linux.sh")
	if strings.Contains(installer, "ngfw-proxy.service") {
		t.Fatal("M3 installer must not install or start the later HTTP/TLS proxy")
	}
	for _, expected := range []string{"--with-inspection", "suricata -T", "replay-m3-suricata.sh", "m3-marker-http.py", "install -o root -g root -m 0755 scripts/verify-m3-linux.sh"} {
		if !strings.Contains(installer, expected) {
			t.Fatalf("installer missing %q", expected)
		}
	}
	retention := read("scripts/rotate-suricata-logs.sh")
	for _, expected := range []string{"33554432", "268435456", "retention_days=${NGFW_INSPECTION_RETENTION_DAYS:-1}", "rotation_grace_seconds=${NGFW_EVE_ROTATION_GRACE_SECONDS:-120}"} {
		if !strings.Contains(retention, expected) {
			t.Fatalf("retention script missing %q", expected)
		}
	}
}
