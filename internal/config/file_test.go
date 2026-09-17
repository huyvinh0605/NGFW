package config

import "testing"

func TestLabExampleLoads(t *testing.T) {
	for _, path := range []string{"../../configs/examples/lab.json", "../../configs/examples/m1-vlan.json", "../../configs/examples/m2-lab.json"} {
		if _, err := LoadFile(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}
