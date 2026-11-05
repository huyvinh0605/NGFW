package session

import (
	"errors"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func TestRuntimeResolveIdentitySeparatesReusedTupleAndScope(t *testing.T) {
	s := NewRuntimeStore(RuntimeLimits{MaxSessions: 8})
	first := testRecord()
	old, _, err := s.Apply(first, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.Identity.ID++
	second.Identity.KernelStart++
	second.KernelStart = first.KernelStart.Add(time.Second)
	current, _, err := s.Apply(second, time.Now())
	if err != nil || current.SessionID == old.SessionID {
		t.Fatalf("reused tuple merged incarnations: %+v %v", current, err)
	}
	for _, identity := range []domain.ConntrackIdentity{first.Identity, second.Identity} {
		value, err := s.ResolveIdentity(identity)
		if err != nil || value.Identity != identity {
			t.Fatalf("exact incarnation lookup: %+v %v", value, err)
		}
	}
	for _, mutate := range []func(*domain.ConntrackIdentity){
		func(i *domain.ConntrackIdentity) { i.ID += 100 },
		func(i *domain.ConntrackIdentity) { i.KernelStart += 100 },
		func(i *domain.ConntrackIdentity) { i.Zone++ },
		func(i *domain.ConntrackIdentity) { i.NetworkNS = "other" },
		func(i *domain.ConntrackIdentity) { i.BootID = "other" },
	} {
		identity := second.Identity
		mutate(&identity)
		if _, err := s.ResolveIdentity(identity); !errors.Is(err, ErrSessionMissing) {
			t.Fatalf("conflicting identity resolved: %+v %v", identity, err)
		}
	}
}
