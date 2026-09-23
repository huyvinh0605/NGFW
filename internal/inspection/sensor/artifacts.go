package sensor

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// ValidateActivationArtifacts verifies the immutable, installer-managed
// sensor files required by the target modes.  Runtime liveness is deliberately
// not required here: M3 supports fail-open activation with an unavailable
// sensor, but never activation against missing or modified artifacts.
func ValidateActivationArtifacts(manifestPath, managedRoot string, requested map[domain.InspectionMode]bool, allowedRulesets map[string]struct{}) (SensorManifest, error) {
	return validateActivationArtifacts(manifestPath, managedRoot, requested, allowedRulesets, validateTrustedArtifact)
}

func validateActivationArtifacts(manifestPath, managedRoot string, requested map[domain.InspectionMode]bool, allowedRulesets map[string]struct{}, trust func(string) error) (SensorManifest, error) {
	manifest, err := LoadManifest(manifestPath, managedRoot)
	if err != nil {
		return SensorManifest{}, err
	}
	if trust == nil {
		return SensorManifest{}, errors.New("artifact trust validator is required")
	}
	if err := trust(manifestPath); err != nil {
		return SensorManifest{}, fmt.Errorf("untrusted sensor manifest: %w", err)
	}
	configRoot := filepath.Dir(manifestPath)
	for _, mode := range []domain.InspectionMode{domain.InspectionModeIDS, domain.InspectionModeIPS} {
		if !requested[mode] {
			continue
		}
		id := strings.ToLower(string(mode))
		definition, ok := manifest.Sensor(id)
		if !ok || definition.Mode != mode {
			return SensorManifest{}, fmt.Errorf("manifest has no %s sensor definition", mode)
		}
		if _, ok := allowedRulesets[definition.RulesetID]; !ok {
			return SensorManifest{}, fmt.Errorf("sensor %s references unregistered ruleset %q", id, definition.RulesetID)
		}
		paths := []string{
			filepath.Join(configRoot, id+".yaml"),
			filepath.Join(configRoot, "rules", "app-discovery.rules"),
			filepath.Join(configRoot, "rules", id+"-demo.rules"),
		}
		for _, path := range paths {
			if err := trust(path); err != nil {
				return SensorManifest{}, fmt.Errorf("untrusted %s artifact %s: %w", id, path, err)
			}
		}
		hash, err := CompositeSHA256Sum(paths)
		if err != nil {
			return SensorManifest{}, err
		}
		if definition.ConfigHash == "" || definition.ConfigHash != hash {
			return SensorManifest{}, fmt.Errorf("sensor %s artifact hash mismatch", id)
		}
	}
	return manifest, nil
}

// CompositeSHA256Sum matches `sha256sum file... | sha256sum` as used by the
// installer.  Paths are part of the registered identity, so relocating an
// unmanaged artifact cannot silently satisfy the manifest.
func CompositeSHA256Sum(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", errors.New("artifact list is empty")
	}
	outer := sha256.New()
	writer := bufio.NewWriter(outer)
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open inspection artifact %s: %w", path, err)
		}
		inner := sha256.New()
		_, copyErr := io.Copy(inner, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", fmt.Errorf("hash inspection artifact %s: %w", path, copyErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close inspection artifact %s: %w", path, closeErr)
		}
		_, _ = fmt.Fprintf(writer, "%s  %s\n", hex.EncodeToString(inner.Sum(nil)), path)
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
}

func validateTrustedArtifact(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("must be a regular file")
	}
	if info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("must not be group/world writable (mode %04o)", info.Mode().Perm())
	}
	return validateRootOwner(info)
}
