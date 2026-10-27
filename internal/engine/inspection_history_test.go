package engine

import (
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/session"
)

func TestInspectionAttachmentAppliesHistoryTTLAndOffRestoresM2Limits(t *testing.T) {
	runtime := NewRuntime(nil, m3RuntimeProgram(t), 1, session.RuntimeLimits{MaxClosed: 8, ClosedTTL: time.Minute})
	limits := domain.DefaultInspectionLimits()
	limits.RecentSessionTTLSeconds = 1
	limits.RecentSessions = 2
	runtime.SetInspectionRuntime(NewInspectionRuntime(runtime, limits, nil))
	now := time.Now().UTC()
	for index := uint32(1); index <= 2; index++ {
		value, _, err := runtime.Store.Apply(runtimeRecord(index), now)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := runtime.Store.Close(value.Identity, "closed", now); !ok {
			t.Fatal("close failed")
		}
		if index == 2 {
			runtime.SetInspectionRuntime(nil)
		}
		runtime.Store.PruneClosed(now.Add(2 * time.Second))
		want := uint64(1)
		if runtime.Store.Stats().HistoryExpired != want {
			t.Fatal("inspection TTL or OFF restoration was not propagated to canonical history")
		}
	}
}
