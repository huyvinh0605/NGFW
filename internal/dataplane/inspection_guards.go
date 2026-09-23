package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type InspectionNft interface {
	ApplyInspectionMutation(context.Context, string) error
	InspectionSetContains(context.Context, string, string) (bool, error)
}

type InspectionGuardKey struct {
	ConntrackZone uint16
	ConntrackID   uint32
	Original      domain.Tuple
}

func BuildInspectionGuardKey(identity domain.ConntrackIdentity) (InspectionGuardKey, error) {
	if identity.ID == 0 {
		return InspectionGuardKey{}, errors.New("application guard requires conntrack ID")
	}
	tuple := identity.Original
	if !tuple.Valid() || tuple.Family != domain.FamilyIPv4 {
		return InspectionGuardKey{}, errors.New("application guard requires valid IPv4 original tuple")
	}
	if tuple.Protocol != 6 && tuple.Protocol != 17 {
		return InspectionGuardKey{}, errors.New("application guard supports TCP or UDP")
	}
	return InspectionGuardKey{ConntrackZone: identity.Zone, ConntrackID: identity.ID, Original: tuple}, nil
}

func (k InspectionGuardKey) element() string {
	protocol := "tcp"
	if k.Original.Protocol == 17 {
		protocol = "udp"
	}
	return fmt.Sprintf("%d . %d . %s . %d . %s . %d . %s", k.ConntrackZone, k.ConntrackID, k.Original.SrcIP, k.Original.SrcPort, k.Original.DstIP, k.Original.DstPort, protocol)
}

type InspectionGuardManager struct {
	nft      InspectionNft
	mu       sync.Mutex
	mutation sync.Mutex
	owned    map[InspectionGuardKey]struct{}
	max      int
}

func NewInspectionGuardManager(nft InspectionNft, max int) *InspectionGuardManager {
	if max <= 0 {
		max = 10000
	}
	return &InspectionGuardManager{nft: nft, owned: map[InspectionGuardKey]struct{}{}, max: max}
}

func (g *InspectionGuardManager) InstallAppGuard(ctx context.Context, key InspectionGuardKey, ttl time.Duration) error {
	if g == nil {
		return errors.New("inspection guard manager unavailable")
	}
	g.mutation.Lock()
	defer g.mutation.Unlock()
	return g.installAppGuardLocked(ctx, key, ttl)
}

func (g *InspectionGuardManager) installAppGuardLocked(ctx context.Context, key InspectionGuardKey, ttl time.Duration) error {
	if g == nil || g.nft == nil {
		return errors.New("inspection nft adapter unavailable")
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	g.mu.Lock()
	if _, ok := g.owned[key]; !ok && len(g.owned) >= g.max {
		g.mu.Unlock()
		return errors.New("application guard capacity reached")
	}
	g.mu.Unlock()
	element := key.element()
	script := fmt.Sprintf("add element inet ngfw_inspection app_denied_v4 { %s timeout %s }\n", element, nftDuration(ttl))
	if err := g.nft.ApplyInspectionMutation(ctx, script); err != nil {
		// add is idempotent at the contract boundary: an exact readback proves
		// that a concurrent/replayed install already achieved the requested key.
		present, readErr := g.nft.InspectionSetContains(ctx, "app_denied_v4", element)
		if readErr != nil || !present {
			return err
		}
	}
	present, err := g.nft.InspectionSetContains(ctx, "app_denied_v4", element)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("application guard readback failed")
	}
	g.mu.Lock()
	g.owned[key] = struct{}{}
	g.mu.Unlock()
	return nil
}
func (g *InspectionGuardManager) RemoveAppGuard(ctx context.Context, key InspectionGuardKey) error {
	if g == nil {
		return errors.New("inspection guard manager unavailable")
	}
	g.mutation.Lock()
	defer g.mutation.Unlock()
	if g == nil || g.nft == nil {
		return errors.New("inspection nft adapter unavailable")
	}
	script := fmt.Sprintf("delete element inet ngfw_inspection app_denied_v4 { %s }\n", key.element())
	if err := g.nft.ApplyInspectionMutation(ctx, script); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such file") {
		return err
	}
	g.mu.Lock()
	delete(g.owned, key)
	g.mu.Unlock()
	return nil
}
func (g *InspectionGuardManager) RenewAppGuard(ctx context.Context, key InspectionGuardKey, ttl time.Duration) error {
	if g == nil {
		return errors.New("inspection guard manager unavailable")
	}
	g.mutation.Lock()
	defer g.mutation.Unlock()
	if g == nil || g.nft == nil {
		return errors.New("inspection nft adapter unavailable")
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	element := key.element()
	// Element timeout is immutable when the userspace `add element` command
	// sees an existing key. Delete+add in one nft batch refreshes it atomically,
	// so packets never observe an intermediate missing guard.
	script := fmt.Sprintf("delete element inet ngfw_inspection app_denied_v4 { %s }\nadd element inet ngfw_inspection app_denied_v4 { %s timeout %s }\n", element, element, nftDuration(ttl))
	if err := g.nft.ApplyInspectionMutation(ctx, script); err != nil {
		// The element may have expired just before renewal. A normal install is
		// safe because the coordinator already revalidated the exact session.
		return g.installAppGuardLocked(ctx, key, ttl)
	}
	present, err := g.nft.InspectionSetContains(ctx, "app_denied_v4", element)
	if err != nil {
		return err
	}
	if !present {
		return errors.New("application guard renewal readback failed")
	}
	return nil
}
func (g *InspectionGuardManager) ClearOwned(ctx context.Context) error {
	g.mu.Lock()
	keys := make([]InspectionGuardKey, 0, len(g.owned))
	for key := range g.owned {
		keys = append(keys, key)
	}
	g.mu.Unlock()
	var result error
	for _, key := range keys {
		if err := g.RemoveAppGuard(ctx, key); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (g *InspectionGuardManager) ExecuteInspectionIntent(ctx context.Context, intent domain.InspectionIntent) (domain.EnforcementResult, error) {
	result := domain.EnforcementResult{Mechanism: domain.EnforcementNFTSessionGuard, Scope: domain.EnforcementScopeSession, RequestedAction: intent.RequestedAction, Status: domain.EnforcementPending, Reason: intent.Reason, OperationID: intent.OperationID}
	key, err := BuildInspectionGuardKey(intent.Identity)
	if err != nil {
		result.Status = domain.EnforcementUnavailable
		result.Reason = err.Error()
		return result, err
	}
	switch intent.Kind {
	case domain.IntentInstallAppGuard:
		err = g.InstallAppGuard(ctx, key, time.Minute)
	case domain.IntentRenewAppGuard:
		err = g.RenewAppGuard(ctx, key, time.Minute)
	case domain.IntentRemoveAppGuard:
		err = g.RemoveAppGuard(ctx, key)
	default:
		err = errors.New("unsupported inspection intent")
	}
	if err != nil {
		result.Status = domain.EnforcementFailed
		result.Reason = err.Error()
		return result, err
	}
	now := time.Now().UTC()
	result.Status = domain.EnforcementApplied
	result.ObservedAt = &now
	return result, nil
}

func RenewIPSLease(ctx context.Context, nft InspectionNft, ttl time.Duration) error {
	if nft == nil {
		return errors.New("inspection nft adapter unavailable")
	}
	if ttl <= 0 {
		ttl = 3 * time.Second
	}
	duration := nftDuration(ttl)
	// `add element` does not reset the expiry of an existing timeout element.
	// This set is owned solely by the lease manager, so an atomic flush+add is
	// the exact heartbeat representation required by fail-open queue selection.
	script := "flush set inet ngfw_inspection ips_ready\nadd element inet ngfw_inspection ips_ready { ipv4 . tcp timeout " + duration + ", ipv4 . udp timeout " + duration + " }\n"
	return nft.ApplyInspectionMutation(ctx, script)
}
func StopIPSLease(ctx context.Context, nft InspectionNft) error {
	if nft == nil {
		return nil
	}
	return nft.ApplyInspectionMutation(ctx, "flush set inet ngfw_inspection ips_ready\n")
}

type LeaseState struct {
	Active      bool       `json:"active"`
	LastRenewal *time.Time `json:"last_renewal,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}
type IPSLeaseManager struct {
	nft           InspectionNft
	interval, ttl time.Duration
	mu            sync.RWMutex
	state         LeaseState
}

func NewIPSLeaseManager(nft InspectionNft) *IPSLeaseManager {
	return &IPSLeaseManager{nft: nft, interval: time.Second, ttl: 3 * time.Second}
}
func (m *IPSLeaseManager) Run(ctx context.Context, live func() bool) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = StopIPSLease(cleanup, m.nft)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.tick(ctx, now, live != nil && live())
		}
	}
}

func (m *IPSLeaseManager) tick(ctx context.Context, now time.Time, live bool) {
	var err error
	if live {
		err = RenewIPSLease(ctx, m.nft, m.ttl)
	} else {
		err = StopIPSLease(ctx, m.nft)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if live && err == nil {
		m.state.Active = true
		now = now.UTC()
		m.state.LastRenewal = &now
		m.state.LastError = ""
		return
	}
	m.state.Active = false
	if err != nil {
		m.state.LastError = err.Error()
	} else {
		m.state.LastError = ""
	}
}
func (m *IPSLeaseManager) State() LeaseState {
	return m.StateAt(time.Now().UTC())
}

func (m *IPSLeaseManager) StateAt(now time.Time) LeaseState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := m.state
	if result.LastRenewal != nil {
		value := *result.LastRenewal
		result.LastRenewal = &value
	}
	if result.Active && (result.LastRenewal == nil || now.After(result.LastRenewal.Add(m.ttl))) {
		result.Active = false
		if result.LastError == "" {
			result.LastError = "IPS lease renewal is stale"
		}
	}
	return result
}

func ParseGuardElement(value string) (InspectionGuardKey, error) {
	parts := strings.Split(value, " . ")
	if len(parts) != 7 {
		return InspectionGuardKey{}, errors.New("invalid guard element")
	}
	zone, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
	if err != nil {
		return InspectionGuardKey{}, err
	}
	id, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
	if err != nil {
		return InspectionGuardKey{}, err
	}
	src, err := netip.ParseAddr(strings.TrimSpace(parts[2]))
	if err != nil {
		return InspectionGuardKey{}, err
	}
	srcPort, err := strconv.ParseUint(strings.TrimSpace(parts[3]), 10, 16)
	if err != nil {
		return InspectionGuardKey{}, err
	}
	dst, err := netip.ParseAddr(strings.TrimSpace(parts[4]))
	if err != nil {
		return InspectionGuardKey{}, err
	}
	dstPort, err := strconv.ParseUint(strings.TrimSpace(parts[5]), 10, 16)
	if err != nil {
		return InspectionGuardKey{}, err
	}
	proto := uint8(6)
	if strings.TrimSpace(parts[6]) == "udp" {
		proto = 17
	}
	return InspectionGuardKey{ConntrackZone: uint16(zone), ConntrackID: uint32(id), Original: domain.Tuple{Family: domain.FamilyIPv4, SrcIP: src, SrcPort: uint16(srcPort), DstIP: dst, DstPort: uint16(dstPort), Protocol: proto}}, nil
}
