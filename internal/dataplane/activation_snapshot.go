package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

const ActivationSnapshotSchema = 1

// ActivationSnapshot is the immutable compiler input and output identity for
// one Linux dataplane generation.  Keeping the previous snapshot in the
// activation journal prevents rollback from accidentally compiling the old
// Config with the target generation's epoch, zone slots, or inspection plan.
type ActivationSnapshot struct {
	Schema            int              `json:"schema"`
	Config            domain.Config    `json:"config"`
	Generation        uint64           `json:"generation"`
	M2Options         M2CompileOptions `json:"m2_options"`
	InspectionPlan    InspectionPlan   `json:"inspection_plan"`
	UsesM3            bool             `json:"uses_m3"`
	ArtifactHash      string           `json:"artifact_hash"`
	StaticRulesetHash string           `json:"static_ruleset_hash"`
}

// PrepareM3Activation compiles all policy and inspection selection state
// before any kernel mutation.  It is valid for an inspection-OFF target too;
// the resulting empty inspection chain is what removes a previous M3 selector.
func PrepareM3Activation(value domain.Config, generation uint64, options M2CompileOptions) (ActivationSnapshot, connectivity.Program, RulesetBundle, error) {
	program, err := connectivity.CompileForCapabilities(value, generation, connectivity.Capabilities{Inspection: true})
	if err != nil {
		return ActivationSnapshot{}, connectivity.Program{}, RulesetBundle{}, err
	}
	plan, err := CompileInspectionPlan(value, program)
	if err != nil {
		return ActivationSnapshot{}, connectivity.Program{}, RulesetBundle{}, err
	}
	usesM3 := domain.UsesM3(value)
	var bundle RulesetBundle
	if usesM3 {
		bundle, err = CompileM3Bundle(value, options, plan)
	} else {
		bundle, err = compileRollbackBundle(value, options, generation, false)
	}
	if err != nil {
		return ActivationSnapshot{}, connectivity.Program{}, RulesetBundle{}, err
	}
	configCopy, err := cloneActivationConfig(value)
	if err != nil {
		return ActivationSnapshot{}, connectivity.Program{}, RulesetBundle{}, err
	}
	snapshot := ActivationSnapshot{
		Schema:         ActivationSnapshotSchema,
		Config:         configCopy,
		Generation:     generation,
		M2Options:      options.Clone(),
		InspectionPlan: cloneInspectionPlan(plan),
		UsesM3:         usesM3,
	}
	snapshot.ArtifactHash, err = activationArtifactHash(snapshot)
	if err != nil {
		return ActivationSnapshot{}, connectivity.Program{}, RulesetBundle{}, err
	}
	snapshot.StaticRulesetHash, err = rulesetBundleHash(bundle)
	if err != nil {
		return ActivationSnapshot{}, connectivity.Program{}, RulesetBundle{}, err
	}
	return snapshot, program, bundle, nil
}

// CompileActivationSnapshot verifies both persisted hashes and returns the
// exact static bundle represented by the snapshot.  A corrupt/stale journal is
// rejected before network or nftables state is touched.
func CompileActivationSnapshot(snapshot ActivationSnapshot) (RulesetBundle, error) {
	if snapshot.Schema != ActivationSnapshotSchema {
		return RulesetBundle{}, fmt.Errorf("unsupported activation snapshot schema %d", snapshot.Schema)
	}
	expectedArtifact, err := activationArtifactHash(snapshot)
	if err != nil {
		return RulesetBundle{}, err
	}
	if snapshot.ArtifactHash == "" || snapshot.ArtifactHash != expectedArtifact {
		return RulesetBundle{}, errors.New("activation snapshot artifact hash mismatch")
	}
	var bundle RulesetBundle
	if snapshot.UsesM3 {
		bundle, err = CompileM3Bundle(snapshot.Config, snapshot.M2Options, snapshot.InspectionPlan)
	} else {
		bundle, err = compileRollbackBundle(snapshot.Config, snapshot.M2Options, snapshot.Generation, false)
	}
	if err != nil {
		return RulesetBundle{}, err
	}
	expectedRules, err := rulesetBundleHash(bundle)
	if err != nil {
		return RulesetBundle{}, err
	}
	if snapshot.StaticRulesetHash == "" || snapshot.StaticRulesetHash != expectedRules {
		return RulesetBundle{}, errors.New("activation snapshot static ruleset hash mismatch")
	}
	return bundle, nil
}

func cloneActivationSnapshot(value ActivationSnapshot) ActivationSnapshot {
	if configCopy, err := cloneActivationConfig(value.Config); err == nil {
		value.Config = configCopy
	}
	value.M2Options = value.M2Options.Clone()
	value.InspectionPlan = cloneInspectionPlan(value.InspectionPlan)
	return value
}

func cloneActivationConfig(value domain.Config) (domain.Config, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return domain.Config{}, err
	}
	var result domain.Config
	if err := json.Unmarshal(payload, &result); err != nil {
		return domain.Config{}, err
	}
	return result, nil
}

func cloneInspectionPlan(value InspectionPlan) InspectionPlan {
	result := value
	result.Rules = append([]InspectionRule(nil), value.Rules...)
	for i := range result.Rules {
		result.Rules[i].Policy = cloneSecurityPolicy(value.Rules[i].Policy)
		selection := value.Rules[i].Selection
		selection.AllowedApps = append([]string(nil), selection.AllowedApps...)
		result.Rules[i].Selection = selection
	}
	return result
}

func cloneSecurityPolicy(value domain.SecurityPolicy) domain.SecurityPolicy {
	value.SourceZones = append([]string(nil), value.SourceZones...)
	value.DestinationZones = append([]string(nil), value.DestinationZones...)
	value.SourceAddresses = append([]string(nil), value.SourceAddresses...)
	value.DestinationAddresses = append([]string(nil), value.DestinationAddresses...)
	value.Services = append([]string(nil), value.Services...)
	value.Applications = append([]string(nil), value.Applications...)
	return value
}

func activationArtifactHash(snapshot ActivationSnapshot) (string, error) {
	copy := cloneActivationSnapshot(snapshot)
	copy.ArtifactHash = ""
	copy.StaticRulesetHash = ""
	payload, err := json.Marshal(copy)
	if err != nil {
		return "", err
	}
	return sha256Hex(payload), nil
}

func rulesetBundleHash(bundle RulesetBundle) (string, error) {
	payload, err := json.Marshal(bundle)
	if err != nil {
		return "", err
	}
	return sha256Hex(payload), nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
