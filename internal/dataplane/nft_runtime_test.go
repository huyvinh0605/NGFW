package dataplane

import (
	"strings"
	"testing"
)

func TestSplitRuntimeTablePreservesPolicyAndNestedBraces(t *testing.T) {
	ruleset := "table inet ngfw_runtime {\n  set revoked_ctids { typeof ct id; }\n  chain forward_guard { type filter hook forward priority -20; policy accept; }\n}\nflush table inet ngfw\ntable inet ngfw { chain forward { type filter hook forward priority 0; policy drop; } }\n"
	runtime, policy := splitRuntimeTable(ruleset)
	if !strings.HasPrefix(runtime, "table inet ngfw_runtime {") || strings.Contains(policy, "ngfw_runtime") {
		t.Fatalf("runtime=%q policy=%q", runtime, policy)
	}
	if !strings.Contains(policy, "flush table inet ngfw") || !strings.Contains(policy, "table inet ngfw {") {
		t.Fatalf("policy table was not preserved: %q", policy)
	}
}

func TestSplitRuntimeTableWithoutRuntimeIsNoop(t *testing.T) {
	input := "flush table inet ngfw\ntable inet ngfw {}\n"
	runtime, policy := splitRuntimeTable(input)
	if runtime != "" || policy != input {
		t.Fatalf("runtime=%q policy=%q", runtime, policy)
	}
}
