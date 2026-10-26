//go:build linux

package deploy_test

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Exercise real DAC/ACL checks as the unprivileged sensor, including reinstall.
// Run on the appliance with sudo go test ./internal/deploy -run InspectionAccess.
func TestInspectionAccessAcrossReinstall(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to test sensor filesystem access")
	}
	for _, name := range []string{"bash", "setfacl", "getfacl", "runuser"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s unavailable", name)
		}
	}
	sensor, err := user.Lookup("ngfw-inspect")
	if err != nil {
		t.Skip("install the dedicated sensor account first")
	}
	uid, _ := strconv.Atoi(sensor.Uid)
	gid, _ := strconv.Atoi(sensor.Gid)
	root, err := os.MkdirTemp("/tmp", "ngfw-inspection-access-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"etc", "var", "var/lib"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"etc/ngfw", "var/lib/ngfw", "etc/ngfw/inspection", "var/lib/ngfw/inspection", "var/lib/ngfw/management", "var/lib/ngfw/ca"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0750); err != nil {
			t.Fatal(err)
		}
	}
	// Config is root-owned/readable by the sensor group; runtime is sensor-owned.
	for _, path := range []string{"etc/ngfw/inspection", "var/lib/ngfw/inspection"} {
		if err := os.Chown(filepath.Join(root, path), 0, gid); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"ids", "ips"} {
		config := filepath.Join(root, "etc/ngfw/inspection", mode+".yaml")
		if err := os.WriteFile(config, []byte("test config\n"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(config, 0, gid); err != nil {
			t.Fatal(err)
		}
		runtime := filepath.Join(root, "var/lib/ngfw/inspection", mode)
		if err := os.Mkdir(runtime, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(runtime, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(root, "etc/ngfw/ngfw.env")
	if err := os.WriteFile(secret, []byte("private fixture\n"), 0640); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"etc/ngfw", "var/lib/ngfw"} {
		if output, err := exec.Command("setfacl", "-m", "u:65534:--x", filepath.Join(root, path)).CombinedOutput(); err != nil {
			t.Fatalf("existing traversal ACL: %v %s", err, output)
		}
	}
	probe := func(flag, path string) bool {
		return exec.Command("runuser", "-u", "ngfw-inspect", "--", "test", flag, filepath.Join(root, path)).Run() == nil
	}
	if probe("-r", "etc/ngfw/inspection/ids.yaml") {
		t.Fatal("fixture does not reproduce inaccessible parent")
	}
	script := filepath.Join(repositoryRoot(t), "scripts/configure-inspection-access.sh")
	var previous string
	for i := 0; i < 2; i++ {
		for _, path := range []string{"etc/ngfw", "var/lib/ngfw"} {
			if err := os.Chmod(filepath.Join(root, path), 0750); err != nil {
				t.Fatal(err)
			}
		}
		if output, err := exec.Command("bash", script, "--root", root).CombinedOutput(); err != nil {
			t.Fatalf("access reconciliation: %v\n%s", err, output)
		}
		if !probe("-r", "etc/ngfw/inspection/ids.yaml") || !probe("-w", "var/lib/ngfw/inspection/ids") ||
			probe("-r", "etc/ngfw") || probe("-w", "etc/ngfw") || probe("-r", "etc/ngfw/ngfw.env") || probe("-x", "var/lib/ngfw/management") {
			t.Fatal("sensor access boundary is wrong")
		}
		acl, err := exec.Command("getfacl", "-cp", filepath.Join(root, "etc/ngfw"), filepath.Join(root, "var/lib/ngfw")).Output()
		if err != nil {
			t.Fatal(err)
		}
		// Use numeric output so an existing independent account grant is checked
		// even when UID 65534 has a different name on the target distribution.
		numeric, err := exec.Command("getfacl", "-cpn", filepath.Join(root, "etc/ngfw"), filepath.Join(root, "var/lib/ngfw")).Output()
		if err != nil || !strings.Contains(string(numeric), "user:65534:--x") {
			t.Fatalf("another service's ACL was lost: %v %s", err, numeric)
		}
		if !strings.Contains(string(acl), "user:ngfw-inspect:--x") || i > 0 && string(acl) != previous {
			t.Fatalf("reinstall changed the ACL: %s", acl)
		}
		previous = string(acl)
	}
	// An unsafe pre-existing token mode must stop the installer, not be ignored.
	if err := os.Chmod(secret, 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", script, "--root", root).CombinedOutput(); err == nil || !strings.Contains(string(output), "privileged file") {
		t.Fatalf("unsafe secret permission accepted: %v %s", err, output)
	}
}
