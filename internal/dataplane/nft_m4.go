package dataplane

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

func (n *NftRunner) verifyProxyOwnershipLocked(ctx context.Context) error {
	out, err := n.run(ctx, "list", "table", "inet", "ngfw_proxy")
	if err != nil {
		return fmt.Errorf("read proxy table ownership: %w", err)
	}
	if !strings.Contains(string(out), `comment "owner=ngfw-engine schema=1"`) {
		return fmt.Errorf("refuse to replace ngfw_proxy without the expected owner/schema")
	}
	return nil
}

func (n *NftRunner) ensureProxySchemaLocked(ctx context.Context) (bool, error) {
	exists, err := n.tableExists(ctx, "ngfw_proxy")
	if err != nil {
		return false, err
	}
	if exists {
		return false, n.verifyProxyOwnershipLocked(ctx)
	}
	if out, err := n.runInput(ctx, ProxySchemaScript(), "-f", "-"); err != nil {
		return false, fmt.Errorf("create proxy schema: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return true, nil
}

// Static objects are compared without mutable counters or kernel handles.
// Dynamic guard sets stay outside this observation and retain their elements.
func (n *NftRunner) readM4StaticState(ctx context.Context) (string, error) {
	var result strings.Builder
	for _, object := range [][]string{{"table", "inet", "ngfw_proxy"}, {"chain", "inet", "ngfw_runtime", "m4_guard"}, {"chain", "inet", "ngfw_inspection", "m4_guard"}} {
		out, err := n.run(ctx, append([]string{"-j", "list"}, object...)...)
		if err != nil {
			return "", fmt.Errorf("verify M4 static object: %w", err)
		}
		canonical, err := normalizeM4JSON(out)
		if err != nil {
			return "", err
		}
		result.WriteString(canonical)
	}
	return result.String(), nil
}

func normalizeM4JSON(raw []byte) (string, error) {
	var root struct {
		NFT []map[string]any `json:"nftables"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&root); err != nil {
		return "", fmt.Errorf("decode M4 kernel state: %w", err)
	}
	if len(root.NFT) == 0 {
		return "", fmt.Errorf("empty M4 kernel state")
	}
	var clean func(any)
	clean = func(node any) {
		switch node := node.(type) {
		case map[string]any:
			delete(node, "handle")
			if _, ok := node["counter"]; ok {
				node["counter"] = nil
			}
			for _, child := range node {
				clean(child)
			}
		case []any:
			for _, child := range node {
				clean(child)
			}
		}
	}
	kept := make([]map[string]any, 0, len(root.NFT))
	for _, object := range root.NFT {
		if _, meta := object["metainfo"]; meta {
			continue
		}
		clean(object)
		kept = append(kept, object)
	}
	payload, err := json.Marshal(kept)
	return string(payload), err
}
