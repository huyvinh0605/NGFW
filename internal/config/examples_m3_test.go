package config

import (
	"path/filepath"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestM3ExampleConfigurationsLoadAndValidate(t *testing.T) {
	for _, name := range []string{"m3-ids-lab.json", "m3-ips-lab.json"} {
		t.Run(name, func(t *testing.T) {
			value, err := LoadFile(filepath.Join("..", "..", "configs", "examples", name))
			if err != nil {
				t.Fatal(err)
			}
			if errs := (Validator{}).Validate(value); len(errs) != 0 {
				t.Fatalf("invalid example: %v", errs)
			}
			if !domain.UsesM3(value) {
				t.Fatal("M3 example did not activate M3 semantics")
			}
		})
	}
}
