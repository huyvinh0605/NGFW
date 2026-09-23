package sensor

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type recoveryCall struct {
	name string
	args []string
}

type fakeRecoveryRunner struct {
	calls []recoveryCall
	fail  int
}

func (f *fakeRecoveryRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recoveryCall{name: name, args: append([]string(nil), args...)})
	if f.fail == len(f.calls) {
		return []byte("failed"), errors.New("command failed")
	}
	if len(args) > 0 && args[0] == "is-active" {
		return []byte("active\n"), nil
	}
	return nil, nil
}

func TestRecoverSensorUsesOnlyFixedUnitAndReadback(t *testing.T) {
	runner := &fakeRecoveryRunner{}
	if err := recoverSensorWithRunner(context.Background(), "ips", runner); err != nil {
		t.Fatal(err)
	}
	want := []recoveryCall{{name: "systemctl", args: []string{"restart", "ngfw-suricata-ips.service"}}, {name: "systemctl", args: []string{"is-active", "ngfw-suricata-ips.service"}}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%#v want=%#v", runner.calls, want)
	}
	if err := recoverSensorWithRunner(context.Background(), "../../evil.service", runner); err == nil {
		t.Fatal("arbitrary service name was accepted")
	}
}

func TestRecoverSensorReturnsRestartFailureWithoutFalseReadback(t *testing.T) {
	runner := &fakeRecoveryRunner{fail: 1}
	if err := recoverSensorWithRunner(context.Background(), "ids", runner); err == nil {
		t.Fatal("restart failure was hidden")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unexpected calls after restart failure: %#v", runner.calls)
	}
}
