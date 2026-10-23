package dataplane

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type RulesetBundle struct {
	RuntimeSchema     string   `json:"runtime_schema"`
	InspectionSchema  string   `json:"inspection_schema"`
	PolicyTransaction string   `json:"policy_transaction"`
	ExpectedObjects   []string `json:"expected_objects"`
	ProxySchema       string   `json:"proxy_schema,omitempty"`
}

func (n *NftRunner) ApplyBundle(ctx context.Context, bundle RulesetBundle) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	runtimeCreated, policyCreated, inspectionCreated, proxyCreated := false, false, false, false
	cleanup := func(cause error) error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupErrors := []error{cause}
		for _, table := range []struct {
			name    string
			created bool
		}{{"ngfw_proxy", proxyCreated}, {"ngfw_inspection", inspectionCreated}, {"ngfw", policyCreated}, {"ngfw_runtime", runtimeCreated}} {
			if !table.created {
				continue
			}
			if out, err := n.run(cleanupCtx, "delete", "table", "inet", table.name); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove newly-created nft table %s: %w: %s", table.name, err, strings.TrimSpace(string(out))))
			}
		}
		return errors.Join(cleanupErrors...)
	}
	if bundle.RuntimeSchema != "" {
		exists, err := n.tableExists(ctx, "ngfw_runtime")
		if err != nil {
			return err
		}
		if !exists {
			if out, err := n.runInput(ctx, bundle.RuntimeSchema, "-c", "-f", "-"); err != nil {
				return fmt.Errorf("nft runtime schema validation failed: %w: %s", err, strings.TrimSpace(string(out)))
			}
			if out, err := n.runInput(ctx, bundle.RuntimeSchema, "-f", "-"); err != nil {
				return fmt.Errorf("nft runtime schema apply failed: %w: %s", err, strings.TrimSpace(string(out)))
			}
			runtimeCreated = true
		}
	}
	var err error
	if policyCreated, err = n.ensureTableNamed(ctx, "ngfw"); err != nil {
		return cleanup(err)
	}
	if bundle.InspectionSchema != "" {
		inspectionCreated, err = n.ensureInspectionSchemaLockedState(ctx)
		if err != nil {
			return cleanup(err)
		}
	}
	if bundle.ProxySchema != "" {
		proxyCreated, err = n.ensureProxySchemaLocked(ctx)
		if err != nil {
			return cleanup(err)
		}
	} else if exists, inspectErr := n.tableExists(ctx, "ngfw_proxy"); inspectErr != nil {
		return cleanup(inspectErr)
	} else if exists {
		if err := n.verifyProxyOwnershipLocked(ctx); err != nil {
			return cleanup(err)
		}
		// Schema-1 compensation must withdraw newer M4 hooks too.
		bundle.PolicyTransaction += "\ndelete table inet ngfw_proxy\n" + ProxySchemaScript() + renderM4RuntimeGuards(domain.Config{}, false)
	}
	if out, err := n.runInput(ctx, bundle.PolicyTransaction, "-c", "-f", "-"); err != nil {
		return cleanup(fmt.Errorf("nft M3 transaction validation failed: %w: %s", err, strings.TrimSpace(string(out))))
	}
	if out, err := n.runInput(ctx, bundle.PolicyTransaction, "-f", "-"); err != nil {
		return cleanup(fmt.Errorf("nft M3 transaction apply failed: %w: %s", err, strings.TrimSpace(string(out))))
	}
	if bundle.ProxySchema != "" {
		state, err := n.readM4StaticState(ctx)
		if err != nil {
			return err
		}
		n.m4StaticState = state
	} else {
		n.m4StaticState = ""
	}
	if err := n.verifyBundleLocked(ctx, bundle); err != nil {
		// Once the policy transaction was accepted, deleting only newly-created
		// schemas cannot restore a pre-existing policy table. The controller owns
		// full snapshot restoration, so retain schemas here and return the exact
		// verification error for that rollback path.
		return err
	}
	n.lastRuleset = bundle.PolicyTransaction
	return nil
}

func (n *NftRunner) VerifyBundle(ctx context.Context, bundle RulesetBundle) error {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.verifyBundleLocked(ctx, bundle)
}

func (n *NftRunner) verifyBundleLocked(ctx context.Context, bundle RulesetBundle) error {
	objects := bundle.ExpectedObjects
	if len(objects) == 0 {
		objects = []string{"inet/ngfw", "inet/ngfw_runtime", "inet/ngfw_inspection"}
	}
	for _, object := range objects {
		parts := strings.Split(object, "/")
		if len(parts) != 2 || parts[0] != "inet" || (parts[1] != "ngfw" && parts[1] != "ngfw_runtime" && parts[1] != "ngfw_inspection" && parts[1] != "ngfw_proxy") {
			return fmt.Errorf("unsupported nft verification object %q", object)
		}
		if out, err := n.run(ctx, "list", "table", parts[0], parts[1]); err != nil {
			return fmt.Errorf("verify nft table %s: %w: %s", object, err, strings.TrimSpace(string(out)))
		}
	}
	for _, object := range [][]string{{"chain", "inet", "ngfw", "forward"}, {"set", "inet", "ngfw_runtime", "source_blocks"}, {"set", "inet", "ngfw_runtime", "revoked_ctids"}, {"chain", "inet", "ngfw_inspection", "guard"}, {"chain", "inet", "ngfw_inspection", "inspect"}, {"set", "inet", "ngfw_inspection", "app_denied_v4"}, {"set", "inet", "ngfw_inspection", "ips_ready"}} {
		out, err := n.run(ctx, append([]string{"list"}, object...)...)
		if err != nil {
			return fmt.Errorf("verify nft %s %s/%s/%s: %w: %s", object[0], object[1], object[2], object[3], err, strings.TrimSpace(string(out)))
		}
	}
	if bundle.ProxySchema != "" {
		state, err := n.readM4StaticState(ctx)
		if err != nil {
			return err
		}
		if n.m4StaticState == "" || state != n.m4StaticState {
			return errors.New("M4 nft selector/guard state differs from verified activation")
		}
	}
	return nil
}
