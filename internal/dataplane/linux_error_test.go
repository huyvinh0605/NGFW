package dataplane

import "testing"

func TestIPObjectAbsenceClassification(t *testing.T) {
	for _, test := range []struct {
		output string
		want   bool
	}{
		{"RTNETLINK answers: No such process", true},
		{"Error: ipv4: Address not found.", true},
		{"Cannot find device \"eth0\"", true},
		{"Error: Nexthop has invalid gateway.", false},
	} {
		if got := isIPObjectNotFound(test.output); got != test.want {
			t.Errorf("isIPObjectNotFound(%q)=%v, want %v", test.output, got, test.want)
		}
	}
}
