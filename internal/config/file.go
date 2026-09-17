package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kltngfw/ngfw/internal/domain"
)

func LoadFile(path string) (domain.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.Config{}, err
	}
	var c domain.Config
	if err := json.Unmarshal(data, &c); err != nil {
		return domain.Config{}, fmt.Errorf("decode config %s: %w", path, err)
	}
	if errs := (Validator{}).Validate(c); len(errs) > 0 {
		return domain.Config{}, fmt.Errorf("invalid config %s: %v", path, errs)
	}
	return c, nil
}
