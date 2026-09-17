package dataplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
)

type NetworkStateReconciler interface {
	Reconcile(context.Context, domain.Config, domain.Config) error
}

type RulesetApplier interface {
	ApplyRuleset(context.Context, string) error
}

// Controller is the only component allowed to coordinate privileged M1
// dataplane changes. Calls are serialized so an API rollback cannot race an
// in-progress apply.
type Controller struct {
	mu                    sync.Mutex
	network               NetworkStateReconciler
	rules                 RulesetApplier
	forwarding            ForwardingEnsurer
	statePath             string
	journalPath           string
	current               domain.Config
	hasCurrent            bool
	recoveryPending       bool
	recoveryPrevious      domain.Config
	recoveryPreviousKnown bool
}

func NewController(network NetworkStateReconciler, rules RulesetApplier, forwarding ForwardingEnsurer, statePath string) (*Controller, error) {
	if network == nil || rules == nil || forwarding == nil {
		return nil, errors.New("dataplane controller requires network, nftables and forwarding adapters")
	}
	if statePath == "" {
		statePath = filepath.Join("state", "dataplane-applied.json")
	}
	controller := &Controller{network: network, rules: rules, forwarding: forwarding, statePath: statePath, journalPath: statePath + ".activation"}
	current, exists, err := loadAppliedState(statePath)
	if err != nil {
		return nil, err
	}
	controller.current = current
	controller.hasCurrent = exists
	activation, pending, err := loadActivationState(controller.journalPath)
	if err != nil {
		return nil, err
	}
	if pending {
		// A crash may have occurred after any subset of network operations.
		// Treat the attempted target as the reconciliation source so startup
		// removes all state that could have been introduced by that attempt.
		controller.current = activation.Desired
		controller.hasCurrent = true
		controller.recoveryPending = true
		controller.recoveryPrevious = activation.Previous
		controller.recoveryPreviousKnown = activation.PreviousKnown
	}
	return controller, nil
}

func (c *Controller) Apply(ctx context.Context, desired domain.Config) error {
	return c.apply(ctx, desired, CompileRuleset)
}

// ApplyM2 activates the policy compiler with a guarded cache and the separate
// runtime guard table. The caller supplies an epoch/zone mapping that is
// durable at the engine layer; the controller only applies the prepared
// snapshot and performs the same compensating rollback as M1.
func (c *Controller) ApplyM2(ctx context.Context, desired domain.Config, options M2CompileOptions) error {
	return c.apply(ctx, desired, func(config domain.Config) (string, error) { return CompileM2Ruleset(config, options) })
}

func (c *Controller) apply(ctx context.Context, desired domain.Config, compiler func(domain.Config) (string, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if validationErrors := (config.Validator{}).Validate(desired); len(validationErrors) > 0 {
		return fmt.Errorf("invalid dataplane configuration: %s", strings.Join(validationErrors, "; "))
	}
	desiredRules, err := compiler(desired)
	if err != nil {
		return err
	}
	source := c.current
	rollback := c.current
	rollbackKnown := c.hasCurrent
	if c.recoveryPending {
		rollback = c.recoveryPrevious
		rollbackKnown = c.recoveryPreviousKnown
	}
	var oldRules string
	previousRulesConfig := rollback
	if !rollbackKnown {
		// No durable previous snapshot means there is no known policy to
		// restore. Remove the attempted table with a fail-closed baseline.
		previousRulesConfig = domain.Config{DefaultDeny: true}
	}
	oldRules, err = compiler(previousRulesConfig)
	if err != nil {
		return fmt.Errorf("compile previous dataplane snapshot: %w", err)
	}
	if err := c.forwarding.Ensure(ctx); err != nil {
		return fmt.Errorf("ensure IPv4 forwarding: %w", err)
	}
	if !c.recoveryPending {
		activation := activationState{Previous: rollback, PreviousKnown: rollbackKnown, Desired: desired, StartedAt: time.Now().UTC()}
		if err := saveActivationState(c.journalPath, activation); err != nil {
			return fmt.Errorf("persist activation journal: %w", err)
		}
	}
	if err := c.network.Reconcile(ctx, source, desired); err != nil {
		return c.restoreAfterFailure(source, desired, rollback, rollbackKnown, oldRules, fmt.Errorf("reconcile network: %w", err))
	}
	if err := c.rules.ApplyRuleset(ctx, desiredRules); err != nil {
		return c.restoreAfterFailure(source, desired, rollback, rollbackKnown, oldRules, fmt.Errorf("apply nftables: %w", err))
	}
	if err := saveAppliedState(c.statePath, desired); err != nil {
		return c.restoreAfterFailure(source, desired, rollback, rollbackKnown, oldRules, fmt.Errorf("persist applied dataplane snapshot: %w", err))
	}
	c.current = desired
	c.hasCurrent = true
	c.recoveryPending = false
	c.recoveryPrevious = domain.Config{}
	c.recoveryPreviousKnown = false
	if err := os.Remove(c.journalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove completed activation journal: %w", err)
	}
	return nil
}

func (c *Controller) restoreAfterFailure(source, attempted, rollback domain.Config, rollbackKnown bool, oldRules string, cause error) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var rollbackErrors []error
	if oldRules != "" {
		if err := c.rules.ApplyRuleset(rollbackCtx, oldRules); err != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("restore previous nftables snapshot: %w", err))
		}
	}
	if err := c.network.Reconcile(rollbackCtx, attempted, rollback); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("restore previous network snapshot: %w", err))
	}
	if err := c.network.Reconcile(rollbackCtx, source, rollback); err != nil {
		rollbackErrors = append(rollbackErrors, fmt.Errorf("remove source leftovers while restoring network snapshot: %w", err))
	}
	if len(rollbackErrors) == 0 {
		if rollbackKnown {
			if err := saveAppliedState(c.statePath, rollback); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("persist restored dataplane snapshot: %w", err))
			}
		} else if err := os.Remove(c.statePath); err != nil && !os.IsNotExist(err) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("remove uncommitted dataplane snapshot: %w", err))
		}
	}
	if len(rollbackErrors) == 0 {
		if err := os.Remove(c.journalPath); err != nil && !os.IsNotExist(err) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("remove rolled-back activation journal: %w", err))
		}
	}
	if len(rollbackErrors) == 0 {
		c.current = rollback
		c.hasCurrent = rollbackKnown
		c.recoveryPending = false
		c.recoveryPrevious = domain.Config{}
		c.recoveryPreviousKnown = false
		return cause
	}
	// Preserve the attempted snapshot as the next reconciliation source. A
	// later retry or process restart can then remove every possibly partial
	// address, route and VLAN from this failed activation.
	c.current = source
	c.hasCurrent = true
	c.recoveryPending = true
	c.recoveryPrevious = rollback
	c.recoveryPreviousKnown = rollbackKnown
	return errors.Join(append([]error{cause}, rollbackErrors...)...)
}

func (c *Controller) RecoveryPending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recoveryPending
}

type appliedState struct {
	Config    domain.Config `json:"config"`
	Checksum  string        `json:"checksum"`
	AppliedAt time.Time     `json:"applied_at"`
}

type activationState struct {
	Previous      domain.Config `json:"previous"`
	PreviousKnown bool          `json:"previous_known"`
	Desired       domain.Config `json:"desired"`
	StartedAt     time.Time     `json:"started_at"`
	Checksum      string        `json:"checksum"`
}

func loadAppliedState(path string) (domain.Config, bool, error) {
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return domain.Config{}, false, nil
	}
	if err != nil {
		return domain.Config{}, false, fmt.Errorf("read applied dataplane snapshot: %w", err)
	}
	var state appliedState
	if err := json.Unmarshal(payload, &state); err != nil {
		return domain.Config{}, false, fmt.Errorf("decode applied dataplane snapshot: %w", err)
	}
	checksum, err := configChecksum(state.Config)
	if err != nil {
		return domain.Config{}, false, err
	}
	if state.Checksum == "" || state.Checksum != checksum {
		return domain.Config{}, false, errors.New("applied dataplane snapshot checksum mismatch")
	}
	return state.Config, true, nil
}

func saveAppliedState(path string, value domain.Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	checksum, err := configChecksum(value)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(appliedState{Config: value, Checksum: checksum, AppliedAt: time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, payload, 0640)
}

func loadActivationState(path string) (activationState, bool, error) {
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return activationState{}, false, nil
	}
	if err != nil {
		return activationState{}, false, fmt.Errorf("read activation journal: %w", err)
	}
	var state activationState
	if err := json.Unmarshal(payload, &state); err != nil {
		return activationState{}, false, fmt.Errorf("decode activation journal: %w", err)
	}
	checksum := state.Checksum
	state.Checksum = ""
	expected, err := activationChecksum(state)
	if err != nil {
		return activationState{}, false, err
	}
	state.Checksum = checksum
	if checksum == "" || checksum != expected {
		return activationState{}, false, errors.New("activation journal checksum mismatch")
	}
	return state, true, nil
}

func saveActivationState(path string, state activationState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	state.Checksum = ""
	checksum, err := activationChecksum(state)
	if err != nil {
		return err
	}
	state.Checksum = checksum
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, payload, 0640)
}

func activationChecksum(state activationState) (string, error) {
	state.Checksum = ""
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func configChecksum(value domain.Config) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
