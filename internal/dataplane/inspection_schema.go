package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const InspectionSchemaVersion = 1

func InspectionSchemaScript() string {
	return `table inet ngfw_inspection {
  comment "owner=ngfw-engine schema=1"
  set app_denied_v4 { typeof ct zone . ct id . ct original ip saddr . ct original proto-src . ct original ip daddr . ct original proto-dst . meta l4proto; flags timeout; timeout 60s; }
  set ips_ready { type nf_proto . inet_proto; flags timeout; timeout 3s; }
  chain guard { type filter hook forward priority -15; policy accept; meta l4proto { tcp, udp } ct zone . ct id . ct original ip saddr . ct original proto-src . ct original ip daddr . ct original proto-dst . meta l4proto @app_denied_v4 counter drop; }
  chain inspect { type filter hook forward priority 10; policy accept; }
  chain select_original { }
  chain select_reply { }
}
`
}

func (n *NftRunner) EnsureInspectionSchema(ctx context.Context) error {
	if n == nil {
		return errors.New("nft runner is unavailable")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, err := n.ensureInspectionSchemaLockedState(ctx)
	return err
}

func (n *NftRunner) ensureInspectionSchemaLocked(ctx context.Context) error {
	_, err := n.ensureInspectionSchemaLockedState(ctx)
	return err
}

func (n *NftRunner) ensureInspectionSchemaLockedState(ctx context.Context) (bool, error) {
	exists, err := n.tableExists(ctx, "ngfw_inspection")
	if err != nil {
		return false, err
	}
	if !exists {
		script := InspectionSchemaScript()
		if out, err := n.runInput(ctx, script, "-c", "-f", "-"); err != nil {
			return false, fmt.Errorf("nft inspection schema validation failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		if out, err := n.runInput(ctx, script, "-f", "-"); err != nil {
			return false, fmt.Errorf("nft inspection schema apply failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return true, nil
	}
	out, err := n.run(ctx, "list", "table", "inet", "ngfw_inspection")
	if err != nil {
		return false, err
	}
	text := string(out)
	for _, required := range []string{"schema=1", "app_denied_v4", "ips_ready", "chain guard", "chain inspect"} {
		if !strings.Contains(text, required) {
			return false, fmt.Errorf("existing ngfw_inspection table has incompatible schema: missing %s", required)
		}
	}
	return false, nil
}

func (n *NftRunner) ApplyInspectionMutation(ctx context.Context, script string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.ensureInspectionSchemaLocked(ctx); err != nil {
		return err
	}
	if out, err := n.runInput(ctx, script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft inspection mutation validation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := n.runInput(ctx, script, "-f", "-"); err != nil {
		return fmt.Errorf("nft inspection mutation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *NftRunner) ClearInspectionRuntimeState(ctx context.Context) error {
	return n.ApplyInspectionMutation(ctx, "flush set inet ngfw_inspection app_denied_v4\nflush set inet ngfw_inspection ips_ready\n")
}

func (n *NftRunner) InspectionSetContains(ctx context.Context, setName, needle string) (bool, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if setName != "app_denied_v4" && setName != "ips_ready" {
		return false, fmt.Errorf("unsupported inspection set %q", setName)
	}
	if strings.ContainsAny(needle, "{}\n\r;") || strings.TrimSpace(needle) == "" {
		return false, errors.New("invalid inspection set element")
	}
	script := fmt.Sprintf("get element inet ngfw_inspection %s { %s }\n", setName, needle)
	out, err := n.runInput(ctx, script, "-f", "-")
	if err != nil {
		message := strings.ToLower(string(out) + " " + err.Error())
		if strings.Contains(message, "no such file") || strings.Contains(message, "not found") || strings.Contains(message, "element does not exist") {
			return false, nil
		}
		return false, fmt.Errorf("read inspection set %s: %w: %s", setName, err, strings.TrimSpace(string(out)))
	}
	return true, nil
}
