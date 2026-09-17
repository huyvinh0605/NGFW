package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

func Defaults() domain.Config {
	return domain.Config{MaxSessions: 50000, MaxEventsQueue: 10000, MaxHTTPBodyInspection: 64 * 1024, MaxHTTPHeaderSize: 32 * 1024, MaxURLLength: 8 * 1024, MaxMLInputLength: 64 * 1024, MLTimeoutMillis: 200, RequestInspectionTimeoutMillis: 2000, DefaultDeny: true}
}

type Validator struct{}

var linuxInterfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

func (Validator) Validate(c domain.Config) []string {
	var errs []string
	ids := map[string]bool{}
	zoneIDs := map[string]bool{}
	profileIDs := map[string]bool{}
	ifaceIDs := map[string]bool{}
	interfacesByID := map[string]domain.Interface{}
	systemIfaces := map[string]string{}
	for _, z := range c.Zones {
		if err := domain.ValidateIdentifier(z.ID); err != nil {
			errs = append(errs, "zone "+err.Error())
		}
		if zoneIDs[z.ID] {
			errs = append(errs, "duplicate zone "+z.ID)
		}
		zoneIDs[z.ID] = true
	}
	for _, i := range c.Interfaces {
		if err := domain.ValidateIdentifier(i.ID); err != nil {
			errs = append(errs, "interface "+err.Error())
		}
		if ifaceIDs[i.ID] {
			errs = append(errs, "duplicate interface "+i.ID)
		}
		ifaceIDs[i.ID] = true
		interfacesByID[i.ID] = i
		if !linuxInterfaceNamePattern.MatchString(i.SystemName) {
			errs = append(errs, fmt.Sprintf("interface %s has invalid Linux system name %q", i.ID, i.SystemName))
		} else {
			if previous, exists := systemIfaces[i.SystemName]; exists {
				errs = append(errs, fmt.Sprintf("system interface %s assigned to %s and %s", i.SystemName, previous, i.ID))
			}
			systemIfaces[i.SystemName] = i.ID
		}
		if i.ZoneID != "" && !zoneIDs[i.ZoneID] {
			errs = append(errs, fmt.Sprintf("interface %s references unknown zone %s", i.ID, i.ZoneID))
		}
		if i.MTU != 0 && (i.MTU < 576 || i.MTU > 65535) {
			errs = append(errs, "invalid MTU on "+i.ID)
		}
		if !i.Mode.Valid() {
			errs = append(errs, fmt.Sprintf("interface %s has invalid mode %q", i.ID, i.Mode))
		}
		for _, address := range i.IPv4Addresses {
			if err := validateAddressFamily(address, false); err != nil {
				errs = append(errs, fmt.Sprintf("interface %s IPv4 address: %v", i.ID, err))
			}
		}
		for _, address := range i.IPv6Addresses {
			if err := validateAddressFamily(address, true); err != nil {
				errs = append(errs, fmt.Sprintf("interface %s IPv6 address: %v", i.ID, err))
			}
		}
	}
	vlanBindings := map[string]string{}
	zoneHasInterface := map[string]bool{}
	for _, i := range c.Interfaces {
		if i.ZoneID != "" {
			zoneHasInterface[i.ZoneID] = true
		}
		if i.Mode == domain.InterfaceVLANSub {
			if i.ParentInterfaceID == "" {
				errs = append(errs, "VLAN interface "+i.ID+" requires parent_interface_id")
			} else if parent, ok := interfacesByID[i.ParentInterfaceID]; !ok {
				errs = append(errs, fmt.Sprintf("VLAN interface %s references unknown parent %s", i.ID, i.ParentInterfaceID))
			} else if parent.Mode != domain.InterfaceVLANParent {
				errs = append(errs, fmt.Sprintf("VLAN interface %s parent %s is not VLAN_PARENT", i.ID, i.ParentInterfaceID))
			} else {
				if i.AdminState && !parent.AdminState {
					errs = append(errs, fmt.Sprintf("VLAN interface %s cannot be up while parent %s is down", i.ID, i.ParentInterfaceID))
				}
				if i.MTU > 0 && parent.MTU > 0 && i.MTU > parent.MTU {
					errs = append(errs, fmt.Sprintf("VLAN interface %s MTU exceeds parent %s MTU", i.ID, i.ParentInterfaceID))
				}
			}
			if i.VLANID < 1 || i.VLANID > 4094 {
				errs = append(errs, fmt.Sprintf("VLAN interface %s has VLAN ID outside 1..4094", i.ID))
			}
			binding := fmt.Sprintf("%s/%d", i.ParentInterfaceID, i.VLANID)
			if prior, ok := vlanBindings[binding]; ok {
				errs = append(errs, fmt.Sprintf("duplicate VLAN binding %s (%s and %s)", binding, prior, i.ID))
			}
			vlanBindings[binding] = i.ID
		} else if i.ParentInterfaceID != "" || i.VLANID != 0 {
			errs = append(errs, fmt.Sprintf("interface %s may use parent_interface_id/vlan_id only in VLAN_SUBINTERFACE mode", i.ID))
		}
		if i.Mode == domain.InterfaceVLANParent && (i.ZoneID != "" || len(i.IPv4Addresses) > 0 || len(i.IPv6Addresses) > 0) {
			errs = append(errs, fmt.Sprintf("VLAN parent %s cannot have a zone or IP addresses", i.ID))
		}
	}
	routeIDs := map[string]bool{}
	for _, r := range c.Routes {
		if err := domain.ValidateIdentifier(r.ID); err != nil {
			errs = append(errs, "route "+err.Error())
		}
		if routeIDs[r.ID] {
			errs = append(errs, "duplicate route "+r.ID)
		}
		routeIDs[r.ID] = true
		if err := domain.ValidateCIDR(r.DestinationCIDR); err != nil {
			errs = append(errs, "route "+r.ID+": "+err.Error())
		}
		if r.Gateway != "" {
			if err := domain.ValidateIP(r.Gateway); err != nil {
				errs = append(errs, "route "+r.ID+": "+err.Error())
			}
		}
		if r.InterfaceID != "" && !ifaceIDs[r.InterfaceID] {
			errs = append(errs, "route "+r.ID+" references unknown interface")
		}
		if r.Enabled && r.InterfaceID == "" && r.Gateway == "" {
			errs = append(errs, "enabled route "+r.ID+" requires interface_id or gateway")
		}
		if r.Metric < 0 {
			errs = append(errs, "route "+r.ID+" has negative metric")
		}
		if err := validateRouteFamily(r); err != nil {
			errs = append(errs, "route "+r.ID+": "+err.Error())
		}
	}
	natIDs := map[string]bool{}
	natPriorities := map[string]string{}
	for _, n := range c.NATRules {
		if err := domain.ValidateIdentifier(n.ID); err != nil {
			errs = append(errs, "nat "+err.Error())
		}
		if natIDs[n.ID] {
			errs = append(errs, "duplicate nat "+n.ID)
		}
		natIDs[n.ID] = true
		natType := strings.ToUpper(n.Type)
		if natType != "SNAT" && natType != "MASQUERADE" && natType != "DNAT" {
			errs = append(errs, fmt.Sprintf("nat %s has invalid type %q", n.ID, n.Type))
		}
		protocol := strings.ToLower(n.Protocol)
		if protocol != "" && protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
			errs = append(errs, fmt.Sprintf("nat %s has invalid protocol %q", n.ID, n.Protocol))
		}
		if (n.OriginalPort != 0 || n.TranslatedPort != 0) && protocol != "tcp" && protocol != "udp" {
			errs = append(errs, "nat "+n.ID+" ports require tcp or udp protocol")
		}
		if n.Enabled {
			if n.Priority < 0 {
				errs = append(errs, "nat "+n.ID+" has negative priority")
			}
			if n.SourceZone == "" || n.DestinationZone == "" {
				errs = append(errs, "enabled nat "+n.ID+" requires source_zone and destination_zone")
			}
			for _, zone := range []string{n.SourceZone, n.DestinationZone} {
				if zone != "" && !zoneHasInterface[zone] {
					errs = append(errs, fmt.Sprintf("enabled nat %s zone %s has no interface", n.ID, zone))
				}
			}
			priorityScope := "postrouting"
			if natType == "DNAT" {
				priorityScope = "prerouting"
			}
			priorityKey := fmt.Sprintf("%s/%d", priorityScope, n.Priority)
			if prior, ok := natPriorities[priorityKey]; ok {
				errs = append(errs, fmt.Sprintf("duplicate NAT priority %d (%s and %s)", n.Priority, prior, n.ID))
			}
			natPriorities[priorityKey] = n.ID
		}
		for _, z := range []string{n.SourceZone, n.DestinationZone} {
			if z != "" && !zoneIDs[z] {
				errs = append(errs, "nat "+n.ID+" references unknown zone "+z)
			}
		}
		if err := domain.ValidatePort(n.OriginalPort, true); err != nil {
			errs = append(errs, "nat "+n.ID+": "+err.Error())
		}
		if err := domain.ValidatePort(n.TranslatedPort, true); err != nil {
			errs = append(errs, "nat "+n.ID+": "+err.Error())
		}
		if n.SourceNetwork != "" {
			if err := validateIPv4CIDR(n.SourceNetwork); err != nil {
				errs = append(errs, "nat "+n.ID+": "+err.Error())
			}
		}
		if n.DestinationNetwork != "" {
			if err := validateIPv4CIDR(n.DestinationNetwork); err != nil {
				errs = append(errs, "nat "+n.ID+": "+err.Error())
			}
		}
		if n.TranslatedAddress != "" {
			if err := validateIPv4(n.TranslatedAddress); err != nil {
				errs = append(errs, "nat "+n.ID+": "+err.Error())
			}
		}
		if natType == "DNAT" && n.TranslatedAddress == "" {
			errs = append(errs, "nat "+n.ID+" DNAT requires translated address")
		} else if natType == "DNAT" && n.DestinationZone != "" && !ipv4BelongsToZone(n.TranslatedAddress, n.DestinationZone, c) {
			errs = append(errs, fmt.Sprintf("nat %s DNAT target is outside destination zone %s", n.ID, n.DestinationZone))
		}
		if natType == "SNAT" && n.TranslatedAddress == "" {
			errs = append(errs, "nat "+n.ID+" SNAT requires translated address")
		}
		if natType == "MASQUERADE" && (n.TranslatedAddress != "" || n.TranslatedPort != 0) {
			errs = append(errs, "nat "+n.ID+" MASQUERADE cannot set translated address or port")
		}
	}
	priorities := map[int]string{}
	natBindings := map[string]string{}
	for _, n := range c.NATRules {
		if !n.Enabled || !strings.EqualFold(n.Type, "DNAT") {
			continue
		}
		binding := strings.Join([]string{n.SourceZone, n.SourceNetwork, n.DestinationNetwork, strings.ToLower(n.Protocol), fmt.Sprint(n.OriginalPort)}, "|")
		if previous, exists := natBindings[binding]; exists {
			errs = append(errs, fmt.Sprintf("conflicting DNAT binding %s (%s and %s)", binding, previous, n.ID))
		}
		natBindings[binding] = n.ID
	}
	for _, p := range c.Policies {
		if err := domain.ValidateIdentifier(p.ID); err != nil {
			errs = append(errs, "policy "+err.Error())
		}
		if ids[p.ID] {
			errs = append(errs, "duplicate object "+p.ID)
		}
		ids[p.ID] = true
		if previous, ok := priorities[p.Priority]; ok {
			errs = append(errs, fmt.Sprintf("duplicate policy priority %d (%s and %s)", p.Priority, previous, p.ID))
		}
		priorities[p.Priority] = p.ID
		if p.Priority < 0 {
			errs = append(errs, "policy "+p.ID+" has negative priority")
		}
		if !p.Action.Valid() {
			errs = append(errs, "policy "+p.ID+" has invalid action")
		} else if p.Enabled && p.Action != domain.DecisionAllow && p.Action != domain.DecisionDrop && p.Action != domain.DecisionReject {
			errs = append(errs, "policy "+p.ID+" uses an action outside the M1 firewall scope")
		}
		if p.MinimumRisk != nil && (*p.MinimumRisk < 0 || *p.MinimumRisk > 100) {
			errs = append(errs, "policy "+p.ID+" has invalid minimum risk")
		}
		if p.MaximumRisk != nil && (*p.MaximumRisk < 0 || *p.MaximumRisk > 100) {
			errs = append(errs, "policy "+p.ID+" has invalid maximum risk")
		}
		for _, z := range append(append([]string{}, p.SourceZones...), p.DestinationZones...) {
			if !zoneIDs[z] {
				errs = append(errs, "policy "+p.ID+" references unknown zone "+z)
			} else if p.Enabled && !zoneHasInterface[z] {
				errs = append(errs, "enabled policy "+p.ID+" zone "+z+" has no interface")
			}
		}
		for _, address := range append(append([]string{}, p.SourceAddresses...), p.DestinationAddresses...) {
			if err := validateIPv4AddressOrCIDR(address); err != nil {
				errs = append(errs, "policy "+p.ID+": "+err.Error())
			}
		}
		for _, service := range p.Services {
			if err := validateM1Service(service); err != nil {
				errs = append(errs, "policy "+p.ID+": "+err.Error())
			}
		}
		if p.SecurityProfileID != "" && !profileIDs[p.SecurityProfileID] { /* checked after profiles are collected */
		}
	}
	for _, p := range c.Profiles {
		if err := domain.ValidateIdentifier(p.ID); err != nil {
			errs = append(errs, "profile "+err.Error())
		}
		if profileIDs[p.ID] {
			errs = append(errs, "duplicate profile "+p.ID)
		}
		profileIDs[p.ID] = true
		if !p.TLSMode.Valid() {
			errs = append(errs, "profile "+p.ID+" has invalid TLS mode")
		}
		if p.MinimumBlockRisk < 0 || p.MinimumBlockRisk > 100 {
			errs = append(errs, "profile "+p.ID+" has invalid block risk")
		}
		if p.InspectionFailureAction != "" && !p.InspectionFailureAction.Valid() {
			errs = append(errs, "profile "+p.ID+" has invalid inspection failure action")
		}
	}
	for _, p := range c.Policies {
		if p.SecurityProfileID != "" && !profileIDs[p.SecurityProfileID] {
			errs = append(errs, "policy "+p.ID+" references unknown profile "+p.SecurityProfileID)
		}
	}
	if c.MaxSessions <= 0 || c.MaxEventsQueue <= 0 || c.MaxHTTPBodyInspection <= 0 || c.MaxHTTPHeaderSize <= 0 || c.MaxURLLength <= 0 || c.MaxMLInputLength <= 0 || c.MLTimeoutMillis <= 0 || c.RequestInspectionTimeoutMillis <= 0 {
		errs = append(errs, "resource limits must be positive")
	}
	return errs
}

func validateAddressFamily(value string, ipv6 bool) error {
	ip, _, err := net.ParseCIDR(value)
	if err != nil {
		return fmt.Errorf("invalid address prefix %q: %w", value, err)
	}
	isIPv6 := ip.To4() == nil
	if isIPv6 != ipv6 {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		return fmt.Errorf("%q is not %s", value, family)
	}
	return nil
}

func validateIPv4CIDR(value string) error {
	ip, _, err := net.ParseCIDR(value)
	if err != nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 CIDR %q", value)
	}
	return nil
}

func validateIPv4(value string) error {
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4 address %q", value)
	}
	return nil
}

func validateIPv4AddressOrCIDR(value string) error {
	if strings.Contains(value, "/") {
		return validateIPv4CIDR(value)
	}
	return validateIPv4(value)
}

func validateM1Service(value string) error {
	parts := strings.Split(value, ":")
	protocol := strings.ToLower(strings.TrimSpace(parts[0]))
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return fmt.Errorf("invalid service %q", value)
	}
	if len(parts) == 1 {
		return nil
	}
	if len(parts) != 2 || protocol == "icmp" {
		return fmt.Errorf("invalid service %q", value)
	}
	portParts := strings.Split(strings.TrimSpace(parts[1]), "-")
	if len(portParts) < 1 || len(portParts) > 2 {
		return fmt.Errorf("invalid service %q", value)
	}
	ports := make([]int, len(portParts))
	for index, raw := range portParts {
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid service %q", value)
		}
		ports[index] = port
	}
	if len(ports) == 2 && ports[0] > ports[1] {
		return fmt.Errorf("invalid service %q", value)
	}
	return nil
}

func ipv4BelongsToZone(address, zone string, value domain.Config) bool {
	target := net.ParseIP(address)
	if target == nil || target.To4() == nil {
		return false
	}
	interfaces := map[string]domain.Interface{}
	bestPrefix := -1
	bestZone := ""
	for _, iface := range value.Interfaces {
		interfaces[iface.ID] = iface
		for _, value := range iface.IPv4Addresses {
			_, network, err := net.ParseCIDR(value)
			if err == nil && network.Contains(target) {
				ones, _ := network.Mask.Size()
				if ones > bestPrefix {
					bestPrefix = ones
					bestZone = iface.ZoneID
				}
			}
		}
	}
	for _, route := range value.Routes {
		if !route.Enabled {
			continue
		}
		_, network, err := net.ParseCIDR(route.DestinationCIDR)
		if err != nil || network.IP.To4() == nil || !network.Contains(target) {
			continue
		}
		ones, _ := network.Mask.Size()
		if ones > bestPrefix {
			bestPrefix = ones
			bestZone = interfaces[route.InterfaceID].ZoneID
		}
	}
	if bestPrefix >= 0 && bestZone == zone {
		return true
	}
	return false
}

func validateRouteFamily(route domain.Route) error {
	_, destination, err := net.ParseCIDR(route.DestinationCIDR)
	if err != nil || route.Gateway == "" {
		return nil
	}
	gateway := net.ParseIP(route.Gateway)
	if gateway == nil {
		return nil
	}
	if (destination.IP.To4() == nil) != (gateway.To4() == nil) {
		return errors.New("gateway and destination use different IP families")
	}
	return nil
}

type Manager struct {
	mu           sync.RWMutex
	activationMu sync.Mutex
	dir          string
	running      domain.Config
	candidate    domain.Config
	version      domain.ConfigVersion
	previous     *domain.Config
	validator    Validator
}

func NewManager(dir string, initial domain.Config) (*Manager, error) {
	if dir == "" {
		dir = "./state"
	}
	if err := os.MkdirAll(dir, 0770); err != nil {
		return nil, err
	}
	m := &Manager{dir: dir, running: cloneConfig(initial), candidate: cloneConfig(initial), validator: Validator{}}
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}
func (m *Manager) Running() domain.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConfig(m.running)
}
func (m *Manager) Candidate() domain.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConfig(m.candidate)
}
func (m *Manager) Version() domain.ConfigVersion {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}
func (m *Manager) SetCandidate(c domain.Config) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.candidate = cloneConfig(c)
	return m.validator.Validate(c)
}

// SyncRunning updates the management-plane snapshot after the privileged
// engine has committed a configuration. The API never writes running.json;
// this keeps its candidate editor aligned with the engine-owned version.
func (m *Manager) SyncRunning(c domain.Config, v domain.ConfigVersion) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldRunning := cloneConfig(m.running)
	oldCandidate := cloneConfig(m.candidate)
	m.running = cloneConfig(c)
	m.version = v
	if oldCandidateJSON, oldRunningJSON := configDigest(oldCandidate), configDigest(oldRunning); oldCandidateJSON == oldRunningJSON {
		m.candidate = cloneConfig(c)
	}
}

func configDigest(c domain.Config) string {
	digest, _ := checksum(c)
	return digest
}
func (m *Manager) ValidateCandidate() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validator.Validate(m.candidate)
}
func (m *Manager) Commit(author, comment string, expected uint64) (domain.ConfigVersion, error) {
	m.activationMu.Lock()
	defer m.activationMu.Unlock()
	m.mu.RLock()
	current := m.version
	candidate := cloneConfig(m.candidate)
	old := cloneConfig(m.running)
	validationErrors := m.validator.Validate(candidate)
	m.mu.RUnlock()
	if expected != current.Version {
		return current, fmt.Errorf("config version conflict: expected %d, running %d", expected, current.Version)
	}
	if len(validationErrors) > 0 {
		return current, fmt.Errorf("invalid candidate: %s", strings.Join(validationErrors, "; "))
	}
	next, nextErr := incrementVersion(current.Version)
	if nextErr != nil {
		return current, nextErr
	}
	checksum, err := checksum(candidate)
	if err != nil {
		return current, err
	}
	v := domain.ConfigVersion{Version: next, Author: author, Timestamp: time.Now().UTC(), Comment: comment, Checksum: checksum}
	if err := m.persist(candidate, v, &old); err != nil {
		return current, err
	}
	m.mu.Lock()
	m.previous = &old
	m.running = cloneConfig(candidate)
	m.version = v
	m.mu.Unlock()
	return v, nil
}

// CommitWithApply activates external state before publishing a new running
// version. If persistence fails after activation, apply must be able to restore
// the old snapshot; this keeps the kernel and management view aligned.
func (m *Manager) CommitWithApply(ctx context.Context, author, comment string, expected uint64, apply func(context.Context, domain.Config) error) (domain.ConfigVersion, error) {
	m.activationMu.Lock()
	defer m.activationMu.Unlock()
	m.mu.RLock()
	current := m.version
	candidate := cloneConfig(m.candidate)
	old := cloneConfig(m.running)
	validationErrors := m.validator.Validate(candidate)
	m.mu.RUnlock()
	if expected != current.Version {
		return current, fmt.Errorf("config version conflict: expected %d, running %d", expected, current.Version)
	}
	if len(validationErrors) > 0 {
		return current, fmt.Errorf("invalid candidate: %s", strings.Join(validationErrors, "; "))
	}
	next, nextErr := incrementVersion(current.Version)
	if nextErr != nil {
		return current, nextErr
	}
	sum, err := checksum(candidate)
	if err != nil {
		return current, err
	}
	if apply != nil {
		if err := apply(ctx, candidate); err != nil {
			return current, restoreApplied(apply, old, fmt.Errorf("activation failed: %w", err))
		}
	}
	v := domain.ConfigVersion{Version: next, Author: author, Timestamp: time.Now().UTC(), Comment: comment, Checksum: sum}
	if err := m.persist(candidate, v, &old); err != nil {
		if apply != nil {
			return current, restoreApplied(apply, old, fmt.Errorf("persist running configuration: %w", err))
		}
		return current, err
	}
	m.mu.Lock()
	m.previous = &old
	m.running = cloneConfig(candidate)
	m.version = v
	m.mu.Unlock()
	return v, nil
}
func (m *Manager) Rollback(author, comment string) (domain.ConfigVersion, error) {
	m.activationMu.Lock()
	defer m.activationMu.Unlock()
	return m.rollbackLocked(context.Background(), author, comment, nil)
}

// RollbackWithApply restores the previous configuration through the same
// privileged activation path used by commit before publishing running.json.
func (m *Manager) RollbackWithApply(ctx context.Context, author, comment string, apply func(context.Context, domain.Config) error) (domain.ConfigVersion, error) {
	m.activationMu.Lock()
	defer m.activationMu.Unlock()
	return m.rollbackLocked(ctx, author, comment, apply)
}

func (m *Manager) rollbackLocked(ctx context.Context, author, comment string, apply func(context.Context, domain.Config) error) (domain.ConfigVersion, error) {
	m.mu.RLock()
	if m.previous == nil {
		current := m.version
		m.mu.RUnlock()
		return current, errors.New("no previous configuration")
	}
	current := m.version
	old := cloneConfig(m.running)
	target := cloneConfig(*m.previous)
	m.mu.RUnlock()
	next, nextErr := incrementVersion(current.Version)
	if nextErr != nil {
		return current, nextErr
	}
	v := domain.ConfigVersion{Version: next, Author: author, Timestamp: time.Now().UTC(), Comment: comment}
	sum, err := checksum(target)
	if err != nil {
		return m.version, err
	}
	v.Checksum = sum
	if apply != nil {
		if err := apply(ctx, target); err != nil {
			return current, restoreApplied(apply, old, fmt.Errorf("rollback activation failed: %w", err))
		}
	}
	if err := m.persist(target, v, &old); err != nil {
		if apply != nil {
			return current, restoreApplied(apply, old, fmt.Errorf("persist rollback configuration: %w", err))
		}
		return current, err
	}
	m.mu.Lock()
	m.running = cloneConfig(target)
	m.candidate = cloneConfig(target)
	m.previous = &old
	m.version = v
	m.mu.Unlock()
	return v, nil
}

func restoreApplied(apply func(context.Context, domain.Config) error, previous domain.Config, cause error) error {
	if apply == nil {
		return cause
	}
	rollbackContext, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := apply(rollbackContext, previous); err != nil {
		return errors.Join(cause, fmt.Errorf("restore previous applied configuration: %w", err))
	}
	return cause
}

func (m *Manager) persist(c domain.Config, v domain.ConfigVersion, previous *domain.Config) error {
	payload, err := json.MarshalIndent(struct {
		Config   domain.Config        `json:"config"`
		Version  domain.ConfigVersion `json:"version"`
		Previous *domain.Config       `json:"previous,omitempty"`
	}{c, v, previous}, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.dir, "running.json.tmp")
	final := filepath.Join(m.dir, "running.json")
	// Running network configuration contains no credentials and is shared
	// read-only with the privileged engine through the ngfw group.
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil && runtime.GOOS != "windows" {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	if directory, err := os.Open(m.dir); err == nil {
		syncErr := directory.Sync()
		_ = directory.Close()
		if syncErr != nil && runtime.GOOS != "windows" {
			return syncErr
		}
	}
	return os.Chmod(final, 0640)
}
func (m *Manager) load() error {
	data, err := os.ReadFile(filepath.Join(m.dir, "running.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var v struct {
		Config   domain.Config        `json:"config"`
		Version  domain.ConfigVersion `json:"version"`
		Previous *domain.Config       `json:"previous,omitempty"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if len(m.validator.Validate(v.Config)) > 0 {
		return errors.New("persisted running configuration is invalid")
	}
	m.running = cloneConfig(v.Config)
	m.candidate = cloneConfig(v.Config)
	m.version = v.Version
	if v.Previous != nil {
		if errs := m.validator.Validate(*v.Previous); len(errs) > 0 {
			return errors.New("persisted previous configuration is invalid")
		}
		previous := cloneConfig(*v.Previous)
		m.previous = &previous
	}
	return nil
}
func checksum(c domain.Config) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func incrementVersion(current uint64) (uint64, error) {
	if current == ^uint64(0) {
		return 0, errors.New("configuration generation exhausted")
	}
	return current + 1, nil
}

func cloneConfig(value domain.Config) domain.Config {
	clone := value
	clone.Interfaces = append([]domain.Interface(nil), value.Interfaces...)
	for index := range clone.Interfaces {
		clone.Interfaces[index].IPv4Addresses = append([]string(nil), value.Interfaces[index].IPv4Addresses...)
		clone.Interfaces[index].IPv6Addresses = append([]string(nil), value.Interfaces[index].IPv6Addresses...)
	}
	clone.Zones = append([]domain.Zone(nil), value.Zones...)
	clone.Routes = append([]domain.Route(nil), value.Routes...)
	clone.NATRules = append([]domain.NATRule(nil), value.NATRules...)
	clone.Policies = append([]domain.SecurityPolicy(nil), value.Policies...)
	for index := range clone.Policies {
		source := value.Policies[index]
		clone.Policies[index].SourceZones = append([]string(nil), source.SourceZones...)
		clone.Policies[index].DestinationZones = append([]string(nil), source.DestinationZones...)
		clone.Policies[index].SourceAddresses = append([]string(nil), source.SourceAddresses...)
		clone.Policies[index].DestinationAddresses = append([]string(nil), source.DestinationAddresses...)
		clone.Policies[index].Services = append([]string(nil), source.Services...)
		clone.Policies[index].Applications = append([]string(nil), source.Applications...)
		if source.MinimumRisk != nil {
			minimum := *source.MinimumRisk
			clone.Policies[index].MinimumRisk = &minimum
		}
		if source.MaximumRisk != nil {
			maximum := *source.MaximumRisk
			clone.Policies[index].MaximumRisk = &maximum
		}
	}
	clone.Profiles = append([]domain.SecurityProfile(nil), value.Profiles...)
	return clone
}
func (m *Manager) Export() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]any{"running": cloneConfig(m.running), "candidate": cloneConfig(m.candidate), "version": m.version, "candidate_valid": len(m.validator.Validate(m.candidate)) == 0}
}
func SortPolicies(c domain.Config) {
	sort.SliceStable(c.Policies, func(i, j int) bool { return c.Policies[i].Priority < c.Policies[j].Priority })
}
