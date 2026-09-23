package correlation

import (
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
)

type SessionLookup interface {
	ResolveCandidates(flow.Key, time.Time, int) ([]domain.RuntimeSession, bool)
}

type BindingKey struct {
	SensorID    string
	SensorEpoch string
	FlowID      uint64
}

type binding struct {
	SessionID string
	Identity  domain.ConntrackIdentity
}

type Resolution struct {
	State   domain.CorrelationState
	Session *domain.RuntimeSession
	Reason  string
	Recent  bool
}

type Resolver struct {
	lookup      SessionLookup
	scope       flow.Scope
	mu          sync.Mutex
	bindings    map[BindingKey]binding
	epochs      map[string]string
	maxBindings int
}

func NewResolver(lookup SessionLookup, scope flow.Scope, maxBindings int) *Resolver {
	if maxBindings <= 0 {
		maxBindings = 10000
	}
	return &Resolver{lookup: lookup, scope: scope, bindings: make(map[BindingKey]binding), epochs: make(map[string]string), maxBindings: maxBindings}
}

func (r *Resolver) Resolve(obs inspection.Observation) Resolution {
	if r == nil || r.lookup == nil {
		return Resolution{State: domain.CorrelationUncorrelated, Reason: "session lookup unavailable"}
	}
	if obs.ObservedAt == nil {
		return Resolution{State: domain.CorrelationUncorrelated, Reason: "observed timestamp unavailable"}
	}
	if obs.Source.SensorID != "" && obs.Source.SensorEpoch != "" {
		r.observeEpoch(obs.Source.SensorID, obs.Source.SensorEpoch)
	}
	key := BindingKey{SensorID: obs.Source.SensorID, SensorEpoch: obs.Source.SensorEpoch, FlowID: obs.FlowID}
	if obs.HasFlowID {
		r.mu.Lock()
		known, exists := r.bindings[key]
		r.mu.Unlock()
		if exists {
			for _, tuple := range observationKeys(r.scope, obs) {
				items, truncated := r.lookup.ResolveCandidates(tuple, *obs.ObservedAt, 8)
				if truncated {
					return Resolution{State: domain.CorrelationAmbiguous, Reason: "candidate limit exceeded"}
				}
				for _, item := range items {
					if item.SessionID == known.SessionID && strongIdentity(item.Identity) && sameIncarnation(item.Identity, known.Identity) {
						copy := item.Clone()
						return Resolution{State: domain.CorrelationCorrelated, Session: &copy, Recent: item.State == domain.SessionClosed, Reason: "sensor flow binding"}
					}
				}
			}
		}
	}
	keys := observationKeys(r.scope, obs)
	if len(keys) == 0 {
		return Resolution{State: domain.CorrelationUncorrelated, Reason: "tuple unavailable"}
	}
	candidates := map[string]domain.RuntimeSession{}
	for _, tuple := range keys {
		items, truncated := r.lookup.ResolveCandidates(tuple, *obs.ObservedAt, 8)
		if truncated {
			return Resolution{State: domain.CorrelationAmbiguous, Reason: "candidate limit exceeded"}
		}
		for _, item := range items {
			if strongIdentity(item.Identity) {
				candidates[item.SessionID] = item
			}
		}
	}
	if len(candidates) == 0 {
		return Resolution{State: domain.CorrelationUncorrelated, Reason: "no strong session tuple match"}
	}
	if len(candidates) != 1 {
		return Resolution{State: domain.CorrelationAmbiguous, Reason: "multiple session tuple matches"}
	}
	var selected domain.RuntimeSession
	for _, item := range candidates {
		selected = item
	}
	if obs.HasFlowID {
		r.remember(key, binding{SessionID: selected.SessionID, Identity: selected.Identity})
	}
	copy := selected.Clone()
	return Resolution{State: domain.CorrelationCorrelated, Session: &copy, Recent: selected.State == domain.SessionClosed, Reason: "tuple alias matched"}
}

func (r *Resolver) observeEpoch(sensorID, epoch string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if previous := r.epochs[sensorID]; previous != "" && previous != epoch {
		for key := range r.bindings {
			if key.SensorID == sensorID && key.SensorEpoch != epoch {
				delete(r.bindings, key)
			}
		}
	}
	r.epochs[sensorID] = epoch
}

func (r *Resolver) remember(key BindingKey, value binding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bindings) >= r.maxBindings {
		for existing := range r.bindings {
			delete(r.bindings, existing)
			break
		}
	}
	r.bindings[key] = value
}

func (r *Resolver) ResetEpoch(sensorID, epoch string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.bindings {
		if key.SensorID == sensorID && key.SensorEpoch != epoch {
			delete(r.bindings, key)
		}
	}
	r.epochs[sensorID] = epoch
}

func observationKeys(scope flow.Scope, obs inspection.Observation) []flow.Key {
	seen := map[flow.Key]struct{}{}
	result := make([]flow.Key, 0, 2)
	for _, tuple := range []*domain.Tuple{obs.Tuple, obs.FlowTuple} {
		if tuple == nil || !tuple.Valid() {
			continue
		}
		key := flow.Key{Scope: scope, Tuple: *tuple}
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, key)
		}
	}
	return result
}

func sameIncarnation(a, b domain.ConntrackIdentity) bool {
	if a.ID != 0 && b.ID != 0 && a.ID != b.ID {
		return false
	}
	if a.KernelStart != 0 && b.KernelStart != 0 && a.KernelStart != b.KernelStart {
		return false
	}
	return a.BootID == b.BootID && a.NetworkNS == b.NetworkNS && a.Zone == b.Zone && a.Original == b.Original
}

func strongIdentity(value domain.ConntrackIdentity) bool {
	return value.ID != 0 && value.KernelStart != 0 && value.Original.Valid()
}
