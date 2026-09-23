package main

import (
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestRequestedInspectionModesOnlyIncludesEnabledReferencedProfiles(t *testing.T) {
	value := domain.Config{
		Inspection: &domain.InspectionConfig{Enabled: true},
		Profiles: []domain.SecurityProfile{
			{ID: "ids", Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIDS}},
			{ID: "ips-unused", Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIPS}},
		},
		Policies: []domain.SecurityPolicy{
			{ID: "active", Enabled: true, SecurityProfileID: "ids"},
			{ID: "disabled", Enabled: false, SecurityProfileID: "ips-unused"},
		},
	}
	modes := requestedInspectionModes(value)
	if !modes[domain.InspectionModeIDS] || modes[domain.InspectionModeIPS] || runningUsesIPS(value) {
		t.Fatalf("unexpected requested modes: %#v", modes)
	}
	value.Inspection.Enabled = false
	if modes := requestedInspectionModes(value); len(modes) != 0 {
		t.Fatalf("disabled inspection requested sensors: %#v", modes)
	}
}
