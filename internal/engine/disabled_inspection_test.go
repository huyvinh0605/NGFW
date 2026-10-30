package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

func TestDisabledInspectionHasEmptyReadableEventStream(t *testing.T) {
	runtime := NewRuntime(nil, connectivity.Program{}, 1, session.RuntimeLimits{})
	service := NewRuntimeServiceAdapter(runtime, nil, nil)
	first, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{})
	if err != nil || first.Items == nil || len(first.Items) != 0 || first.StreamID == "" || first.HasMore || first.Gap {
		t.Fatalf("disabled M3 must have a readable empty page, got %#v, %v", first, err)
	}
	next, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{StreamID: first.StreamID})
	if err != nil || next.StreamID != first.StreamID || next.Gap || next.NextSequence != 0 || !strings.HasSuffix(next.NextCursor, ":0") {
		t.Fatalf("disabled stream is not stable/idle: %#v, %v", next, err)
	}
	reset, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{StreamID: "old-enabled-stream", AfterSequence: 99})
	if err != nil || !reset.Gap || reset.NextSequence != 0 || len(reset.Items) != 0 {
		t.Fatalf("old stream cursor must reset explicitly: %#v, %v", reset, err)
	}
	if _, err := service.GetSecurityEvent(context.Background(), "missing"); !errors.Is(err, domain.ErrSecurityEventNotFound) {
		t.Fatalf("disabled event lookup must be NOT_FOUND, got %v", err)
	}
	missing := NewRuntimeServiceAdapter(nil, nil, nil)
	if _, err := missing.ListSecurityEvents(context.Background(), domain.SecurityQuery{}); err == nil {
		t.Fatal("missing engine must remain unavailable")
	}
	coordinator := NewInspectionRuntime(runtime, domain.DefaultInspectionLimits(), nil)
	runtime.SetInspectionRuntime(coordinator)
	_, _, err = coordinator.SecurityEvents().Add(domain.ThreatEvent{EventID: "actual-store-event"})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{StreamID: first.StreamID})
	if err != nil || len(active.Items) != 1 || !active.Gap || active.StreamID == first.StreamID {
		t.Fatalf("enabled source did not use its real store: %#v, %v", active, err)
	}
	runtime.SetInspectionRuntime(nil)
	stopped, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{StreamID: active.StreamID})
	if err != nil || len(stopped.Items) != 0 || !stopped.Gap {
		t.Fatalf("disable cutover did not reset the old cursor: %#v, %v", stopped, err)
	}
	if err := runtime.Activate(connectivity.Program{}, 2, "configuration changed"); err != nil {
		t.Fatal(err)
	}
	changed, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{StreamID: first.StreamID})
	if err != nil || !changed.ResetRequired || changed.StreamID == first.StreamID {
		t.Fatalf("disabled generation did not reset an old cursor: %#v, %v", changed, err)
	}
	value := config.Defaults()
	value.Inspection = &domain.InspectionConfig{Enabled: true}
	manager, err := config.NewManager(t.TempDir(), value)
	if err != nil {
		t.Fatal(err)
	}
	service.Config = manager
	if _, err := service.ListSecurityEvents(context.Background(), domain.SecurityQuery{}); err == nil {
		t.Fatal("configured inspection with a missing coordinator must remain unavailable")
	}
	if _, err := service.GetSecurityEvent(context.Background(), "missing"); err == nil || errors.Is(err, domain.ErrSecurityEventNotFound) {
		t.Fatalf("missing configured inspector was hidden as not-found: %v", err)
	}
}
