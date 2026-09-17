package dataplane

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// NftRunner is a privileged Linux adapter. It checks the complete ruleset,
// applies it as one nft transaction, and reads the managed table back.
type NftRunner struct {
	Binary      string
	mu          sync.RWMutex
	lastRuleset string
}

func NewNftRunner(binary string) *NftRunner {
	if binary == "" {
		binary = "nft"
	}
	return &NftRunner{Binary: binary}
}

func (n *NftRunner) ApplyRuleset(ctx context.Context, ruleset string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	runtimeScript, policyRuleset := splitRuntimeTable(ruleset)
	runtimeCreated := false
	if runtimeScript != "" {
		exists, err := n.tableExists(ctx, "ngfw_runtime")
		if err != nil {
			return err
		}
		if !exists {
			if out, applyErr := n.runInput(ctx, runtimeScript, "-c", "-f", "-"); applyErr != nil {
				return fmt.Errorf("nft runtime guard validation failed: %w: %s", applyErr, strings.TrimSpace(string(out)))
			}
			if out, applyErr := n.runInput(ctx, runtimeScript, "-f", "-"); applyErr != nil {
				return fmt.Errorf("nft runtime guard apply failed: %w: %s", applyErr, strings.TrimSpace(string(out)))
			}
			runtimeCreated = true
		}
	}
	createdTable, err := n.ensureTable(ctx)
	if err != nil {
		return err
	}
	cleanup := func(cause error) error {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var cleanupErrors []error
		if createdTable {
			if out, deleteErr := n.run(cleanupContext, "delete", "table", "inet", "ngfw"); deleteErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove newly created nft table: %w: %s", deleteErr, strings.TrimSpace(string(out))))
			}
		}
		if runtimeCreated {
			if out, deleteErr := n.run(cleanupContext, "delete", "table", "inet", "ngfw_runtime"); deleteErr != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove newly created runtime table: %w: %s", deleteErr, strings.TrimSpace(string(out))))
			}
		}
		return errors.Join(append([]error{cause}, cleanupErrors...)...)
	}
	if out, err := n.runInput(ctx, policyRuleset, "-c", "-f", "-"); err != nil {
		return cleanup(fmt.Errorf("nft validation failed: %w: %s", err, strings.TrimSpace(string(out))))
	}
	if out, err := n.runInput(ctx, policyRuleset, "-f", "-"); err != nil {
		return cleanup(fmt.Errorf("nft apply failed: %w: %s", err, strings.TrimSpace(string(out))))
	}
	if out, err := n.run(ctx, "list", "table", "inet", "ngfw"); err != nil {
		return cleanup(fmt.Errorf("nft verification failed: %w: %s", err, strings.TrimSpace(string(out))))
	}
	n.lastRuleset = ruleset
	return nil
}

func (n *NftRunner) ensureTable(ctx context.Context) (bool, error) {
	return n.ensureTableNamed(ctx, "ngfw")
}

func (n *NftRunner) ensureTableNamed(ctx context.Context, name string) (bool, error) {
	out, err := n.run(ctx, "list", "table", "inet", name)
	if err == nil {
		return false, nil
	}
	message := strings.ToLower(string(out))
	if !strings.Contains(message, "no such file") && !strings.Contains(message, "not found") {
		return false, fmt.Errorf("inspect nft table: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err = n.run(ctx, "add", "table", "inet", name); err != nil {
		return false, fmt.Errorf("create nft table: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

func (n *NftRunner) tableExists(ctx context.Context, name string) (bool, error) {
	out, err := n.run(ctx, "list", "table", "inet", name)
	if err == nil {
		return true, nil
	}
	message := strings.ToLower(string(out))
	if strings.Contains(message, "no such file") || strings.Contains(message, "not found") {
		return false, nil
	}
	return false, fmt.Errorf("inspect nft table %s: %w: %s", name, err, strings.TrimSpace(string(out)))
}

func splitRuntimeTable(ruleset string) (runtime, policy string) {
	start := strings.Index(ruleset, "table inet ngfw_runtime {")
	if start < 0 {
		return "", ruleset
	}
	open := strings.Index(ruleset[start:], "{") + start
	depth, end := 0, -1
	for index := open; index < len(ruleset); index++ {
		switch ruleset[index] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = index + 1
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return "", ruleset
	}
	runtime = ruleset[start:end]
	policy = strings.TrimSpace(ruleset[:start]+"\n"+ruleset[end:]) + "\n"
	return runtime, policy
}

func (n *NftRunner) run(ctx context.Context, args ...string) ([]byte, error) {
	return n.runInput(ctx, "", args...)
}

func (n *NftRunner) runInput(ctx context.Context, input string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, n.Binary, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	return cmd.CombinedOutput()
}

func (n *NftRunner) LastRuleset() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.lastRuleset
}

func (n *NftRunner) ApplyRuntimeMutation(ctx context.Context, script string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, err := n.tableExists(ctx, "ngfw_runtime"); err != nil {
		return err
	}
	if out, err := n.runInput(ctx, script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft runtime mutation validation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := n.runInput(ctx, script, "-f", "-"); err != nil {
		return fmt.Errorf("nft runtime mutation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ClearRevokedSessions removes engine-local conntrack revoke fences during a
// fresh engine start. A revoke set stores kernel conntrack IDs, which are not
// globally unique across restart and may be reused by a later flow. Source
// blocks remain in the runtime table with their kernel timeout; only the
// identity-scoped set that cannot be safely rehydrated is cleared.
func (n *NftRunner) ClearRevokedSessions(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if exists, err := n.tableExists(ctx, "ngfw_runtime"); err != nil {
		return err
	} else if !exists {
		return errors.New("runtime guard table is not present")
	}
	script := "flush set inet ngfw_runtime revoked_ctids\n"
	if out, err := n.runInput(ctx, script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft revoke-set reset validation failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := n.runInput(ctx, script, "-f", "-"); err != nil {
		return fmt.Errorf("nft revoke-set reset failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
