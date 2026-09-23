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

type RulesetBundleApplier interface {
	ApplyBundle(context.Context, RulesetBundle) error
}

type InspectionRuntimeCleaner interface {
	ClearInspectionRuntimeState(context.Context) error
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
	recoveryOptions       M2CompileOptions
	recoveryGeneration    uint64
	recoveryUsesM3        bool
	currentM2Options      M2CompileOptions
	currentGeneration     uint64
	currentUsesM3         bool
	currentSnapshot       *ActivationSnapshot
	recoverySnapshot      *ActivationSnapshot
	prepared              bool
}

func NewController(network NetworkStateReconciler, rules RulesetApplier, forwarding ForwardingEnsurer, statePath string) (*Controller, error) {
	if network == nil || rules == nil || forwarding == nil {
		return nil, errors.New("dataplane controller requires network, nftables and forwarding adapters")
	}
	if statePath == "" {
		statePath = filepath.Join("state", "dataplane-applied.json")
	}
	controller := &Controller{network: network, rules: rules, forwarding: forwarding, statePath: statePath, journalPath: statePath + ".activation"}
	applied, exists, err := loadAppliedSnapshot(statePath)
	if err != nil {
		return nil, err
	}
	controller.current = applied.Config
	controller.hasCurrent = exists
	if applied.Options != nil {
		controller.currentM2Options = applied.Options.Clone()
		controller.currentGeneration = applied.Generation
		controller.currentUsesM3 = applied.UsesM3
	}
	if applied.Snapshot != nil {
		snapshot := cloneActivationSnapshot(*applied.Snapshot)
		controller.currentSnapshot = &snapshot
		controller.currentM2Options = snapshot.M2Options.Clone()
		controller.currentGeneration = snapshot.Generation
		controller.currentUsesM3 = snapshot.UsesM3
	}
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
		if activation.PreviousOptions != nil {
			controller.recoveryOptions = activation.PreviousOptions.Clone()
		}
		controller.recoveryGeneration = activation.PreviousGeneration
		controller.recoveryUsesM3 = activation.PreviousUsesM3
		if activation.PreviousSnapshot != nil {
			snapshot := cloneActivationSnapshot(*activation.PreviousSnapshot)
			controller.recoverySnapshot = &snapshot
			controller.recoveryOptions = snapshot.M2Options.Clone()
			controller.recoveryGeneration = snapshot.Generation
			controller.recoveryUsesM3 = snapshot.UsesM3
		}
		if activation.DesiredOptions != nil {
			controller.currentM2Options = activation.DesiredOptions.Clone()
		}
		controller.currentGeneration = activation.DesiredGeneration
		controller.currentUsesM3 = activation.DesiredUsesM3
		if activation.DesiredSnapshot != nil {
			snapshot := cloneActivationSnapshot(*activation.DesiredSnapshot)
			controller.currentSnapshot = &snapshot
			controller.currentM2Options = snapshot.M2Options.Clone()
			controller.currentGeneration = snapshot.Generation
			controller.currentUsesM3 = snapshot.UsesM3
		}
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
	err := c.apply(ctx, desired, func(config domain.Config) (string, error) { return CompileM2Ruleset(config, options) })
	if err == nil {
		c.mu.Lock()
		c.currentM2Options = options
		c.currentUsesM3 = false
		c.mu.Unlock()
	}
	return err
}

// ApplyM3 applies M1/M2 policy and M3 static inspection selection in one nft
// transaction after ensuring the two dynamic schemas. Network rollback and
// dynamic-set preservation use the same journal discipline as M1/M2.
func (c *Controller) ApplyM3(ctx context.Context, desired domain.Config, options M2CompileOptions, generation uint64) error {
	if !domain.UsesM3(desired) {
		return errors.New("ApplyM3 requires an inspection-enabled configuration")
	}
	snapshot, _, _, err := PrepareM3Activation(desired, generation, options)
	if err != nil {
		return err
	}
	return c.ApplySnapshot(ctx, snapshot)
}

// ApplyRuntime activates the complete M1/M2/M3 kernel program. It is also
// used for an inspection-OFF configuration so a previous M3 selector is
// atomically replaced with an empty inspection chain rather than being left
// active after a downgrade or rollback.
func (c *Controller) ApplyRuntime(ctx context.Context, desired domain.Config, options M2CompileOptions, generation uint64) error {
	snapshot, _, _, err := PrepareM3Activation(desired, generation, options)
	if err != nil {
		return err
	}
	if domain.UsesM3(desired) {
		return c.ApplySnapshot(ctx, snapshot)
	}
	// A fresh M1/M2 appliance keeps the proven M2 compiler/apply path and does
	// not require an M3-capable nft schema. A downgrade from M3 uses the bundle
	// once so the old inspection selectors are atomically emptied.
	c.mu.Lock()
	needsInspectionCleanup := c.currentUsesM3 || (c.recoveryPending && (c.recoveryUsesM3 || c.currentUsesM3))
	c.mu.Unlock()
	if needsInspectionCleanup {
		return c.ApplySnapshot(ctx, snapshot)
	}
	if err := c.ApplyM2(ctx, desired, options); err != nil {
		return err
	}
	if err := saveAppliedRuntimeSnapshot(c.statePath, snapshot); err != nil {
		return fmt.Errorf("persist M2 runtime activation metadata: %w", err)
	}
	c.mu.Lock()
	c.currentGeneration = generation
	c.currentM2Options = options.Clone()
	c.currentUsesM3 = false
	copy := cloneActivationSnapshot(snapshot)
	c.currentSnapshot = &copy
	c.mu.Unlock()
	return nil
}

// ApplySnapshot applies an already compiled and hash-bound activation target.
// Callers may safely persist or transport the snapshot before mutation; this
// method verifies it again and never substitutes options from another target.
func (c *Controller) ApplySnapshot(ctx context.Context, target ActivationSnapshot) error {
	return c.applySnapshot(ctx, target, false)
}

// ApplySnapshotPrepared retains the checksummed activation journal after the
// kernel and applied snapshot are updated.  The engine commit coordinator must
// call FinalizeActivation only after Running, the in-memory generation, and
// the inspection lifecycle have all reached this same snapshot.
func (c *Controller) ApplySnapshotPrepared(ctx context.Context, target ActivationSnapshot) error {
	return c.applySnapshot(ctx, target, true)
}

func (c *Controller) applySnapshot(ctx context.Context, target ActivationSnapshot, retainJournal bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	target = cloneActivationSnapshot(target)
	desired := target.Config
	options := target.M2Options.Clone()
	generation := target.Generation
	desiredUsesM3 := target.UsesM3
	if validationErrors := (config.Validator{}).Validate(desired); len(validationErrors) > 0 {
		return fmt.Errorf("invalid dataplane configuration: %s", strings.Join(validationErrors, "; "))
	}
	if desiredUsesM3 != domain.UsesM3(desired) {
		return errors.New("activation snapshot M3 mode does not match configuration")
	}
	desiredBundle, err := CompileActivationSnapshot(target)
	if err != nil {
		return err
	}
	applier, ok := c.rules.(RulesetBundleApplier)
	if !ok {
		return errors.New("configured nft adapter does not support M3 ruleset bundles")
	}
	source := c.current
	rollback := c.current
	rollbackKnown := c.hasCurrent
	if c.recoveryPending {
		rollback = c.recoveryPrevious
		rollbackKnown = c.recoveryPreviousKnown
	}
	rollbackConfig := rollback
	if !rollbackKnown {
		rollbackConfig = domain.Config{DefaultDeny: true}
	}
	rollbackOptions := c.currentM2Options
	rollbackGeneration := c.currentGeneration
	rollbackUsesM3 := c.currentUsesM3
	if c.recoveryPending {
		rollbackOptions = c.recoveryOptions
		rollbackGeneration = c.recoveryGeneration
		rollbackUsesM3 = c.recoveryUsesM3
	}
	if rollbackOptions.ZoneSlots == nil {
		rollbackOptions = options
	}
	var previousSnapshot ActivationSnapshot
	if c.recoveryPending && c.recoverySnapshot != nil {
		previousSnapshot = cloneActivationSnapshot(*c.recoverySnapshot)
	} else if !c.recoveryPending && c.currentSnapshot != nil {
		previousSnapshot = cloneActivationSnapshot(*c.currentSnapshot)
	} else {
		var prepareErr error
		previousSnapshot, _, _, prepareErr = PrepareM3Activation(rollbackConfig, rollbackGeneration, rollbackOptions)
		if prepareErr != nil {
			return fmt.Errorf("prepare previous M3 dataplane snapshot: %w", prepareErr)
		}
		// Legacy state had no compiler metadata.  Never borrow the target
		// epoch/zone slots: a no-cache snapshot is slower but cannot trust an
		// old conntrack mark under a different generation.
		if c.currentSnapshot == nil && c.recoverySnapshot == nil && rollbackOptions.ZoneSlots == nil {
			previousSnapshot, _, _, prepareErr = PrepareM3Activation(rollbackConfig, rollbackGeneration, M2CompileOptions{})
			if prepareErr != nil {
				return fmt.Errorf("prepare safe legacy rollback snapshot: %w", prepareErr)
			}
		}
	}
	oldBundle, compileErr := CompileActivationSnapshot(previousSnapshot)
	if compileErr != nil {
		return fmt.Errorf("compile previous M3 dataplane snapshot: %w", compileErr)
	}
	if err := c.forwarding.Ensure(ctx); err != nil {
		return fmt.Errorf("ensure IPv4 forwarding: %w", err)
	}
	if !c.recoveryPending {
		previousOptions := rollbackOptions.Clone()
		desiredOptions := options.Clone()
		previousSnapshotCopy := cloneActivationSnapshot(previousSnapshot)
		desiredSnapshotCopy := cloneActivationSnapshot(target)
		activation := activationState{Schema: 3, Previous: rollback, PreviousKnown: rollbackKnown, PreviousOptions: &previousOptions, PreviousGeneration: rollbackGeneration, PreviousUsesM3: rollbackUsesM3, PreviousSnapshot: &previousSnapshotCopy, Desired: desired, DesiredOptions: &desiredOptions, DesiredGeneration: generation, DesiredUsesM3: desiredUsesM3, DesiredSnapshot: &desiredSnapshotCopy, StartedAt: time.Now().UTC()}
		if err := saveActivationState(c.journalPath, activation); err != nil {
			return fmt.Errorf("persist activation journal: %w", err)
		}
	}
	if err := c.network.Reconcile(ctx, source, desired); err != nil {
		return c.restoreM3AfterFailure(applier, source, target, rollback, rollbackKnown, previousSnapshot, oldBundle, fmt.Errorf("reconcile network: %w", err))
	}
	if err := applier.ApplyBundle(ctx, desiredBundle); err != nil {
		return c.restoreM3AfterFailure(applier, source, target, rollback, rollbackKnown, previousSnapshot, oldBundle, fmt.Errorf("apply M3 nftables: %w", err))
	}
	if !desiredUsesM3 {
		cleaner, ok := c.rules.(InspectionRuntimeCleaner)
		if !ok {
			return c.restoreM3AfterFailure(applier, source, target, rollback, rollbackKnown, previousSnapshot, oldBundle, errors.New("configured nft adapter cannot clear M3 runtime guards"))
		}
		if err := cleaner.ClearInspectionRuntimeState(ctx); err != nil {
			return c.restoreM3AfterFailure(applier, source, target, rollback, rollbackKnown, previousSnapshot, oldBundle, fmt.Errorf("clear disabled M3 runtime guards: %w", err))
		}
	}
	if err := saveAppliedRuntimeSnapshot(c.statePath, target); err != nil {
		return c.restoreM3AfterFailure(applier, source, target, rollback, rollbackKnown, previousSnapshot, oldBundle, fmt.Errorf("persist applied dataplane snapshot: %w", err))
	}
	c.current = desired
	c.hasCurrent = true
	c.recoveryPending = false
	c.recoveryPrevious = domain.Config{}
	c.recoveryPreviousKnown = false
	c.currentM2Options = options.Clone()
	c.currentGeneration = generation
	c.currentUsesM3 = desiredUsesM3
	currentSnapshot := cloneActivationSnapshot(target)
	c.currentSnapshot = &currentSnapshot
	c.recoverySnapshot = nil
	c.prepared = retainJournal
	if !retainJournal {
		if err := os.Remove(c.journalPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove completed activation journal: %w", err)
		}
	}
	return nil
}

// ApplyRuntimePrepared is the M3 commit path.  A never-M3 inspection-OFF
// appliance deliberately keeps the established M2 apply path and has no M3
// journal to finalize.
func (c *Controller) ApplyRuntimePrepared(ctx context.Context, desired domain.Config, options M2CompileOptions, generation uint64) error {
	// Compensation inside the same live activation must use the journaled
	// previous compiler inputs exactly.  Startup recovery intentionally does
	// not enter this branch; it receives fresh options/epoch from the engine.
	c.mu.Lock()
	prepared := c.prepared
	c.mu.Unlock()
	if prepared {
		if activation, pending, loadErr := loadActivationState(c.journalPath); loadErr != nil {
			return loadErr
		} else if pending && activation.PreviousSnapshot != nil && activation.PreviousSnapshot.Generation == generation {
			expectedHash, hashErr := configChecksum(desired)
			if hashErr != nil {
				return hashErr
			}
			previousHash, hashErr := configChecksum(activation.PreviousSnapshot.Config)
			if hashErr != nil {
				return hashErr
			}
			if expectedHash == previousHash {
				return c.ApplySnapshotPrepared(ctx, *activation.PreviousSnapshot)
			}
		}
	}
	snapshot, _, _, err := PrepareM3Activation(desired, generation, options)
	if err != nil {
		return err
	}
	c.mu.Lock()
	needsM3Bundle := snapshot.UsesM3 || c.currentUsesM3 || c.currentSnapshot != nil && c.currentSnapshot.UsesM3 || c.recoveryPending && (c.recoveryUsesM3 || c.currentUsesM3)
	c.mu.Unlock()
	if !needsM3Bundle {
		return c.ApplyRuntime(ctx, desired, options, generation)
	}
	return c.ApplySnapshotPrepared(ctx, snapshot)
}

// VerifyActivation checks the persisted compiler identity and kernel objects
// without changing them.
func (c *Controller) VerifyActivation(ctx context.Context, snapshot ActivationSnapshot) error {
	bundle, err := CompileActivationSnapshot(snapshot)
	if err != nil {
		return err
	}
	verifier, ok := c.rules.(interface {
		VerifyBundle(context.Context, RulesetBundle) error
	})
	if !ok {
		return errors.New("configured nft adapter cannot verify activation")
	}
	return verifier.VerifyBundle(ctx, bundle)
}

// FinalizeActivation removes a retained activation journal only when the
// durable applied snapshot exactly matches the authoritative Running target.
// A mismatch preserves recovery evidence for the next engine startup.
func (c *Controller) FinalizeActivation(ctx context.Context, expected domain.Config, generation uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.prepared {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.currentSnapshot == nil || c.currentSnapshot.Generation != generation {
		return errors.New("prepared activation generation does not match running generation")
	}
	expectedHash, err := configChecksum(expected)
	if err != nil {
		return err
	}
	currentHash, err := configChecksum(c.currentSnapshot.Config)
	if err != nil {
		return err
	}
	if currentHash != expectedHash {
		return errors.New("prepared activation config does not match running config")
	}
	applied, exists, err := loadAppliedSnapshot(c.statePath)
	if err != nil {
		return err
	}
	if !exists || applied.Snapshot == nil || applied.Snapshot.ArtifactHash != c.currentSnapshot.ArtifactHash {
		return errors.New("durable activation snapshot does not match prepared target")
	}
	if err := os.Remove(c.journalPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("finalize activation journal: %w", err)
	}
	c.prepared = false
	return nil
}

func compileRollbackBundle(value domain.Config, options M2CompileOptions, generation uint64, useM3 bool) (RulesetBundle, error) {
	if useM3 || domain.UsesM3(value) {
		_, _, bundle, err := CompileM3(value, generation, options)
		return bundle, err
	}
	m2, err := CompileM2Ruleset(value, options)
	if err != nil {
		return RulesetBundle{}, err
	}
	runtime, policy := splitRuntimeTable(m2)
	empty, _ := RenderInspectionRules(InspectionPlan{}, value)
	return RulesetBundle{RuntimeSchema: runtime, InspectionSchema: InspectionSchemaScript(), PolicyTransaction: policy + "\n" + empty}, nil
}

func (c *Controller) restoreM3AfterFailure(applier RulesetBundleApplier, source domain.Config, attempted ActivationSnapshot, rollback domain.Config, rollbackKnown bool, previous ActivationSnapshot, old RulesetBundle, cause error) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var errs []error
	if err := applier.ApplyBundle(rollbackCtx, old); err != nil {
		errs = append(errs, fmt.Errorf("restore previous M3 nftables snapshot: %w", err))
	}
	if err := c.network.Reconcile(rollbackCtx, attempted.Config, rollback); err != nil {
		errs = append(errs, fmt.Errorf("restore previous network snapshot: %w", err))
	}
	if err := c.network.Reconcile(rollbackCtx, source, rollback); err != nil {
		errs = append(errs, fmt.Errorf("remove source leftovers while restoring network snapshot: %w", err))
	}
	if len(errs) == 0 {
		if rollbackKnown {
			if err := saveAppliedRuntimeSnapshot(c.statePath, previous); err != nil {
				errs = append(errs, err)
			}
		} else if err := os.Remove(c.statePath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		_ = os.Remove(c.journalPath)
		c.prepared = false
		c.current = rollback
		c.hasCurrent = rollbackKnown
		c.currentSnapshot = nil
		c.recoveryPending = false
		c.recoveryPrevious = domain.Config{}
		c.recoveryPreviousKnown = false
		c.recoveryOptions = M2CompileOptions{}
		c.recoveryGeneration = 0
		c.recoveryUsesM3 = false
		c.recoverySnapshot = nil
		c.currentM2Options = previous.M2Options.Clone()
		c.currentGeneration = previous.Generation
		c.currentUsesM3 = previous.UsesM3
		if rollbackKnown {
			snapshot := cloneActivationSnapshot(previous)
			c.currentSnapshot = &snapshot
		} else {
			c.currentSnapshot = nil
		}
		return cause
	}
	c.current = attempted.Config
	c.hasCurrent = true
	c.recoveryPending = true
	c.recoveryPrevious = rollback
	c.recoveryPreviousKnown = rollbackKnown
	c.recoveryOptions = previous.M2Options.Clone()
	c.recoveryGeneration = previous.Generation
	c.recoveryUsesM3 = previous.UsesM3
	recoverySnapshot := cloneActivationSnapshot(previous)
	c.recoverySnapshot = &recoverySnapshot
	c.currentM2Options = attempted.M2Options.Clone()
	c.currentGeneration = attempted.Generation
	c.currentUsesM3 = attempted.UsesM3
	currentSnapshot := cloneActivationSnapshot(attempted)
	c.currentSnapshot = &currentSnapshot
	c.prepared = false
	return errors.Join(append([]error{cause}, errs...)...)
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
	c.currentSnapshot = nil
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
		c.currentSnapshot = nil
		c.recoveryPending = false
		c.recoveryPrevious = domain.Config{}
		c.recoveryPreviousKnown = false
		return cause
	}
	// Preserve the attempted snapshot as the next reconciliation source. A
	// later retry or process restart can then remove every possibly partial
	// address, route and VLAN from this failed activation.
	c.current = attempted
	c.hasCurrent = true
	c.currentSnapshot = nil
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
	Config           domain.Config       `json:"config"`
	Checksum         string              `json:"checksum"`
	AppliedAt        time.Time           `json:"applied_at"`
	Options          *M2CompileOptions   `json:"options,omitempty"`
	Generation       uint64              `json:"generation,omitempty"`
	UsesM3           bool                `json:"uses_m3,omitempty"`
	MetadataChecksum string              `json:"metadata_checksum,omitempty"`
	Snapshot         *ActivationSnapshot `json:"activation_snapshot,omitempty"`
}

type activationState struct {
	Schema             int                 `json:"schema,omitempty"`
	Previous           domain.Config       `json:"previous"`
	PreviousKnown      bool                `json:"previous_known"`
	PreviousOptions    *M2CompileOptions   `json:"previous_options,omitempty"`
	PreviousGeneration uint64              `json:"previous_generation,omitempty"`
	PreviousUsesM3     bool                `json:"previous_uses_m3,omitempty"`
	PreviousSnapshot   *ActivationSnapshot `json:"previous_snapshot,omitempty"`
	Desired            domain.Config       `json:"desired"`
	DesiredOptions     *M2CompileOptions   `json:"desired_options,omitempty"`
	DesiredGeneration  uint64              `json:"desired_generation,omitempty"`
	DesiredUsesM3      bool                `json:"desired_uses_m3,omitempty"`
	DesiredSnapshot    *ActivationSnapshot `json:"desired_snapshot,omitempty"`
	StartedAt          time.Time           `json:"started_at"`
	Checksum           string              `json:"checksum"`
}

func loadAppliedState(path string) (domain.Config, bool, error) {
	state, exists, err := loadAppliedSnapshot(path)
	return state.Config, exists, err
}

func loadAppliedSnapshot(path string) (appliedState, bool, error) {
	payload, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return appliedState{}, false, nil
	}
	if err != nil {
		return appliedState{}, false, fmt.Errorf("read applied dataplane snapshot: %w", err)
	}
	var state appliedState
	if err := json.Unmarshal(payload, &state); err != nil {
		return appliedState{}, false, fmt.Errorf("decode applied dataplane snapshot: %w", err)
	}
	checksum, err := configChecksum(state.Config)
	if err != nil {
		return appliedState{}, false, err
	}
	if state.Checksum == "" || state.Checksum != checksum {
		return appliedState{}, false, errors.New("applied dataplane snapshot checksum mismatch")
	}
	if state.Options != nil {
		expected, err := runtimeMetadataChecksum(state.Options.Clone(), state.Generation, state.UsesM3)
		if err != nil || state.MetadataChecksum == "" || state.MetadataChecksum != expected {
			return appliedState{}, false, errors.New("applied dataplane runtime metadata checksum mismatch")
		}
		cloned := state.Options.Clone()
		state.Options = &cloned
	}
	if state.Snapshot != nil {
		if _, err := CompileActivationSnapshot(*state.Snapshot); err != nil {
			return appliedState{}, false, fmt.Errorf("invalid applied activation snapshot: %w", err)
		}
		if state.Snapshot.ArtifactHash == "" || state.Snapshot.Config.DefaultDeny != state.Config.DefaultDeny {
			return appliedState{}, false, errors.New("applied activation snapshot/config mismatch")
		}
		configHash, hashErr := configChecksum(state.Snapshot.Config)
		if hashErr != nil || configHash != checksum {
			return appliedState{}, false, errors.New("applied activation snapshot/config checksum mismatch")
		}
		copy := cloneActivationSnapshot(*state.Snapshot)
		state.Snapshot = &copy
	}
	return state, true, nil
}

func saveAppliedState(path string, value domain.Config) error {
	return saveAppliedSnapshot(path, appliedState{Config: value})
}

func saveAppliedRuntimeState(path string, value domain.Config, options M2CompileOptions, generation uint64, usesM3 bool) error {
	snapshot, _, _, err := PrepareM3Activation(value, generation, options)
	if err != nil {
		return err
	}
	if snapshot.UsesM3 != usesM3 {
		return errors.New("runtime activation M3 mode mismatch")
	}
	return saveAppliedRuntimeSnapshot(path, snapshot)
}

func saveAppliedRuntimeSnapshot(path string, snapshot ActivationSnapshot) error {
	if _, err := CompileActivationSnapshot(snapshot); err != nil {
		return err
	}
	cloned := snapshot.M2Options.Clone()
	metadata, err := runtimeMetadataChecksum(cloned, snapshot.Generation, snapshot.UsesM3)
	if err != nil {
		return err
	}
	copy := cloneActivationSnapshot(snapshot)
	return saveAppliedSnapshot(path, appliedState{Config: snapshot.Config, Options: &cloned, Generation: snapshot.Generation, UsesM3: snapshot.UsesM3, MetadataChecksum: metadata, Snapshot: &copy})
}

func saveAppliedSnapshot(path string, state appliedState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	checksum, err := configChecksum(state.Config)
	if err != nil {
		return err
	}
	state.Checksum = checksum
	state.AppliedAt = time.Now().UTC()
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, payload, 0640)
}

func runtimeMetadataChecksum(options M2CompileOptions, generation uint64, usesM3 bool) (string, error) {
	payload, err := json.Marshal(struct {
		Options    M2CompileOptions `json:"options"`
		Generation uint64           `json:"generation"`
		UsesM3     bool             `json:"uses_m3"`
	}{options.Clone(), generation, usesM3})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
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
	if state.PreviousSnapshot != nil {
		if _, err := CompileActivationSnapshot(*state.PreviousSnapshot); err != nil {
			return activationState{}, false, fmt.Errorf("invalid previous activation snapshot: %w", err)
		}
		copy := cloneActivationSnapshot(*state.PreviousSnapshot)
		state.PreviousSnapshot = &copy
	}
	if state.DesiredSnapshot != nil {
		if _, err := CompileActivationSnapshot(*state.DesiredSnapshot); err != nil {
			return activationState{}, false, fmt.Errorf("invalid desired activation snapshot: %w", err)
		}
		copy := cloneActivationSnapshot(*state.DesiredSnapshot)
		state.DesiredSnapshot = &copy
	}
	return state, true, nil
}

func saveActivationState(path string, state activationState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if state.PreviousSnapshot != nil {
		if _, err := CompileActivationSnapshot(*state.PreviousSnapshot); err != nil {
			return fmt.Errorf("persist previous activation snapshot: %w", err)
		}
	}
	if state.DesiredSnapshot != nil {
		if _, err := CompileActivationSnapshot(*state.DesiredSnapshot); err != nil {
			return fmt.Errorf("persist desired activation snapshot: %w", err)
		}
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
