package engine

import (
	"context"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/session"
)

type fencedRefreshSource struct {
	conntrack.Source
	get func(context.Context, conntrack.Identity) (conntrack.Record, error)
}

func (s fencedRefreshSource) Get(ctx context.Context, identity conntrack.Identity) (conntrack.Record, error) {
	return s.get(ctx, identity)
}

func TestInspectionRefreshRejectsReusedIdentityAndConcurrentClose(t *testing.T) {
	for _, closeDuringGet := range []bool{false, true} {
		runtime := NewRuntime(nil, connectivity.Program{Generation: 1}, 1, session.RuntimeLimits{})
		record := runtimeRecord(901)
		value, _, err := runtime.Store.Apply(record, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		runtime.Source = fencedRefreshSource{get: func(context.Context, conntrack.Identity) (conntrack.Record, error) {
			if closeDuringGet {
				runtime.Store.Close(record.Identity, "concurrent destroy", time.Now())
			} else {
				record.Identity.ID++
			}
			record.Presence.CountersOriginal = true
			record.PacketsOriginal = 999
			return record, nil
		}}
		runtime.RefreshSessionCounters(context.Background(), value)
		current, exists := runtime.Store.Get(value.SessionID)
		if closeDuringGet && exists || !closeDuringGet && (!exists || current.PacketsOriginal == 999) {
			t.Fatal("late/mismatched kernel Get changed the current incarnation")
		}
	}
}
