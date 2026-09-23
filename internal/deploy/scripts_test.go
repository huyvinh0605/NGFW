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
