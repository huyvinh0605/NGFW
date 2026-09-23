package sensor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// RecoveryRunner exists so recovery behavior can be tested without invoking
// systemd. Arguments are always selected by this package, never by EVE or an
// API request.
type RecoveryRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type commandRecoveryRunner struct{}

func (commandRecoveryRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

var sensorUnits = map[string]string{
	"ids": "ngfw-suricata-ids.service",
	"ips": "ngfw-suricata-ips.service",
}

// RecoverSensor performs one bounded restart and readback for a fixed sensor
// unit. It intentionally has no arbitrary unit or command parameter.
func RecoverSensor(ctx context.Context, sensorID string) error {
	return recoverSensorWithRunner(ctx, sensorID, commandRecoveryRunner{})
}

func recoverSensorWithRunner(ctx context.Context, sensorID string, runner RecoveryRunner) error {
	unit, ok := sensorUnits[sensorID]
	if !ok {
		return fmt.Errorf("unsupported inspection sensor %q", sensorID)
	}
	if runner == nil {
		return errors.New("sensor recovery runner is unavailable")
	}
	recoveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if output, err := runner.Run(recoveryCtx, "systemctl", "restart", unit); err != nil {
		return fmt.Errorf("restart %s: %w: %s", unit, err, strings.TrimSpace(string(output)))
	}
	output, err := runner.Run(recoveryCtx, "systemctl", "is-active", unit)
	if err != nil {
		return fmt.Errorf("verify %s: %w: %s", unit, err, strings.TrimSpace(string(output)))
	}
	if strings.TrimSpace(string(output)) != "active" {
		return fmt.Errorf("verify %s: state is %q", unit, strings.TrimSpace(string(output)))
	}
	return nil
}
