package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

var ErrIPObjectNotFound = errors.New("ip object not found")

// IPCommandRunner is the small privileged boundary used by the network
// reconciler. Arguments are passed directly to iproute2 without a shell.
type IPCommandRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

type ExecIPCommandRunner struct{ Binary string }

func NewExecIPCommandRunner(binary string) *ExecIPCommandRunner {
	if binary == "" {
		binary = "ip"
	}
	return &ExecIPCommandRunner{Binary: binary}
}

func (r *ExecIPCommandRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	message := strings.ToLower(string(out))
	if strings.Contains(message, "cannot find device") || strings.Contains(message, "does not exist") || strings.Contains(message, "no such process") || strings.Contains(message, "cannot find") || strings.Contains(message, "cannot assign requested address") {
		return out, fmt.Errorf("%w: ip %s: %v: %s", ErrIPObjectNotFound, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
}

const (
	OperationCommand    = "command"
	OperationEnsureLink = "ensure-link"
	OperationEnsureVLAN = "ensure-vlan"
)

// NetworkOperation is exported so the reconciliation plan can be unit tested
// without invoking privileged Linux commands.
type NetworkOperation struct {
	Kind           string
	Description    string
	Args           []string
	IgnoreNotFound bool
	InterfaceName  string
	ParentName     string
	VLANID         int
}

// NetworkReconciler makes the managed interface/address/route state match a
// desired configuration. It removes state recorded in the old snapshot before
// adding the new state and restores the old snapshot when any command fails.
type NetworkReconciler struct{ Runner IPCommandRunner }

func NewNetworkReconciler(runner IPCommandRunner) *NetworkReconciler {
	return &NetworkReconciler{Runner: runner}
}

// NewIPRouteRunner remains as a compatibility constructor for appliance code.
func NewIPRouteRunner(binary string) *NetworkReconciler {
	return NewNetworkReconciler(NewExecIPCommandRunner(binary))
}

func (r *NetworkReconciler) Apply(ctx context.Context, desired domain.Config) error {
	return r.Reconcile(ctx, domain.Config{}, desired)
}

func (r *NetworkReconciler) Reconcile(ctx context.Context, previous, desired domain.Config) error {
	if r == nil || r.Runner == nil {
		return errors.New("network reconciler has no ip command runner")
	}
	plan, err := PlanNetwork(previous, desired)
	if err != nil {
		return err
	}
	if err := r.applyPlan(ctx, plan); err != nil {
		rollbackPlan, planErr := PlanNetwork(desired, previous)
		if planErr != nil {
			return errors.Join(err, fmt.Errorf("build network rollback plan: %w", planErr))
		}
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if rollbackErr := r.applyPlan(rollbackCtx, rollbackPlan); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("restore previous network snapshot: %w", rollbackErr))
		}
		return err
	}
	return nil
}

func (r *NetworkReconciler) applyPlan(ctx context.Context, plan []NetworkOperation) error {
	for _, operation := range plan {
		var err error
		switch operation.Kind {
		case OperationCommand:
			_, err = r.Runner.Run(ctx, operation.Args...)
		case OperationEnsureLink:
			_, err = r.Runner.Run(ctx, "link", "show", "dev", operation.InterfaceName)
		case OperationEnsureVLAN:
			err = r.ensureVLAN(ctx, operation)
		default:
			err = fmt.Errorf("unknown network operation kind %q", operation.Kind)
		}
		if err != nil && operation.IgnoreNotFound && errors.Is(err, ErrIPObjectNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", operation.Description, err)
		}
	}
	return nil
}

type ipLinkDetails struct {
	IfIndex   int    `json:"ifindex"`
	IfName    string `json:"ifname"`
	Link      string `json:"link"`
	LinkIndex int    `json:"link_index"`
	LinkInfo  struct {
		Kind string `json:"info_kind"`
		Data struct {
			ID int `json:"id"`
		} `json:"info_data"`
	} `json:"linkinfo"`
}

func (r *NetworkReconciler) ensureVLAN(ctx context.Context, operation NetworkOperation) error {
	out, err := r.Runner.Run(ctx, "-details", "-json", "link", "show", "dev", operation.InterfaceName)
	if errors.Is(err, ErrIPObjectNotFound) {
		_, err = r.Runner.Run(ctx, "link", "add", "link", operation.ParentName, "name", operation.InterfaceName, "type", "vlan", "id", strconv.Itoa(operation.VLANID))
		return err
	}
	if err != nil {
		return err
	}
	var links []ipLinkDetails
	if err := json.Unmarshal(out, &links); err != nil || len(links) != 1 {
		if err == nil {
			err = fmt.Errorf("expected one link, received %d", len(links))
		}
		return fmt.Errorf("decode existing VLAN %s: %w", operation.InterfaceName, err)
	}
	details := links[0]
	parentMatches := details.Link == operation.ParentName
	if !parentMatches && details.LinkIndex != 0 {
		parentOut, parentErr := r.Runner.Run(ctx, "-json", "link", "show", "dev", operation.ParentName)
		if parentErr != nil {
			return fmt.Errorf("inspect VLAN parent %s: %w", operation.ParentName, parentErr)
		}
		var parents []ipLinkDetails
		if err := json.Unmarshal(parentOut, &parents); err == nil && len(parents) == 1 {
			parentMatches = parents[0].IfIndex == details.LinkIndex
		}
	}
	if details.LinkInfo.Kind == "vlan" && details.LinkInfo.Data.ID == operation.VLANID && parentMatches {
		return nil
	}
	if _, err := r.Runner.Run(ctx, "link", "delete", "dev", operation.InterfaceName); err != nil {
		return fmt.Errorf("remove mismatched interface %s: %w", operation.InterfaceName, err)
	}
	if _, err := r.Runner.Run(ctx, "link", "add", "link", operation.ParentName, "name", operation.InterfaceName, "type", "vlan", "id", strconv.Itoa(operation.VLANID)); err != nil {
		return fmt.Errorf("recreate VLAN %s: %w", operation.InterfaceName, err)
	}
	return nil
}

func PlanNetwork(previous, desired domain.Config) ([]NetworkOperation, error) {
	previousInterfaces := interfaceMap(previous)
	desiredInterfaces := interfaceMap(desired)
	var operations []NetworkOperation

	// Routes and addresses must be removed while their old links still exist.
	desiredRoutes, err := routeSignatures(desired)
	if err != nil {
		return nil, err
	}
	for _, route := range sortedRoutes(previous.Routes) {
		if !route.Enabled {
			continue
		}
		args, err := routeArgs("del", route, previousInterfaces)
		if err != nil {
			return nil, err
		}
		if _, exists := desiredRoutes[routeSignature(args)]; !exists {
			operations = append(operations, command("remove route "+route.ID, true, args...))
		}
	}

	desiredAddresses := addressSet(desired)
	for _, iface := range sortedInterfaces(previous.Interfaces) {
		for _, address := range sortedStrings(iface.IPv4Addresses) {
			if _, exists := desiredAddresses[addressKey("-4", iface.SystemName, address)]; !exists {
				operations = append(operations, command("remove IPv4 address "+address+" from "+iface.SystemName, true, "-4", "addr", "del", address, "dev", iface.SystemName))
			}
		}
		for _, address := range sortedStrings(iface.IPv6Addresses) {
			if _, exists := desiredAddresses[addressKey("-6", iface.SystemName, address)]; !exists {
				operations = append(operations, command("remove IPv6 address "+address+" from "+iface.SystemName, true, "-6", "addr", "del", address, "dev", iface.SystemName))
			}
		}
	}

	for _, iface := range sortedInterfaces(previous.Interfaces) {
		if iface.Mode != domain.InterfaceVLANSub {
			continue
		}
		desiredInterface, exists := desiredInterfaces[iface.ID]
		if !exists || !sameVLAN(iface, desiredInterface, previousInterfaces, desiredInterfaces) {
			operations = append(operations, command("remove VLAN interface "+iface.SystemName, true, "link", "delete", "dev", iface.SystemName))
		}
	}

	for _, iface := range sortedInterfaces(desired.Interfaces) {
		if iface.Mode == domain.InterfaceVLANSub {
			continue
		}
		operations = append(operations, NetworkOperation{Kind: OperationEnsureLink, Description: "verify interface " + iface.SystemName, InterfaceName: iface.SystemName})
	}
	for _, iface := range sortedInterfaces(desired.Interfaces) {
		if iface.Mode != domain.InterfaceVLANSub {
			continue
		}
		parent, ok := desiredInterfaces[iface.ParentInterfaceID]
		if !ok || parent.SystemName == "" {
			return nil, fmt.Errorf("VLAN interface %s has unresolved parent %s", iface.ID, iface.ParentInterfaceID)
		}
		operations = append(operations, NetworkOperation{Kind: OperationEnsureVLAN, Description: "ensure VLAN interface " + iface.SystemName, InterfaceName: iface.SystemName, ParentName: parent.SystemName, VLANID: iface.VLANID})
	}

	for _, iface := range sortedInterfaces(desired.Interfaces) {
		if iface.MTU > 0 {
			operations = append(operations, command("set MTU on "+iface.SystemName, false, "link", "set", "dev", iface.SystemName, "mtu", strconv.Itoa(iface.MTU)))
		}
	}
	for _, iface := range sortedInterfaces(desired.Interfaces) {
		for _, address := range sortedStrings(iface.IPv4Addresses) {
			operations = append(operations, command("apply IPv4 address "+address+" to "+iface.SystemName, false, "-4", "addr", "replace", address, "dev", iface.SystemName))
		}
		for _, address := range sortedStrings(iface.IPv6Addresses) {
			operations = append(operations, command("apply IPv6 address "+address+" to "+iface.SystemName, false, "-6", "addr", "replace", address, "dev", iface.SystemName))
		}
	}
	for _, iface := range sortedInterfaces(desired.Interfaces) {
		state := "down"
		if iface.AdminState {
			state = "up"
		}
		operations = append(operations, command("set administrative state on "+iface.SystemName, false, "link", "set", "dev", iface.SystemName, state))
	}
	for _, route := range sortedRoutes(desired.Routes) {
		if !route.Enabled {
			continue
		}
		args, err := routeArgs("replace", route, desiredInterfaces)
		if err != nil {
			return nil, err
		}
		operations = append(operations, command("apply route "+route.ID, false, args...))
	}
	return operations, nil
}

func command(description string, ignoreNotFound bool, args ...string) NetworkOperation {
	return NetworkOperation{Kind: OperationCommand, Description: description, Args: args, IgnoreNotFound: ignoreNotFound}
}

func interfaceMap(config domain.Config) map[string]domain.Interface {
	result := make(map[string]domain.Interface, len(config.Interfaces))
	for _, iface := range config.Interfaces {
		result[iface.ID] = iface
	}
	return result
}

func sameVLAN(old, desired domain.Interface, oldInterfaces, desiredInterfaces map[string]domain.Interface) bool {
	if desired.Mode != domain.InterfaceVLANSub || old.SystemName != desired.SystemName || old.VLANID != desired.VLANID {
		return false
	}
	oldParent, oldOK := oldInterfaces[old.ParentInterfaceID]
	desiredParent, desiredOK := desiredInterfaces[desired.ParentInterfaceID]
	return oldOK && desiredOK && oldParent.SystemName == desiredParent.SystemName
}

func addressSet(config domain.Config) map[string]struct{} {
	result := map[string]struct{}{}
	for _, iface := range config.Interfaces {
		for _, address := range iface.IPv4Addresses {
			result[addressKey("-4", iface.SystemName, address)] = struct{}{}
		}
		for _, address := range iface.IPv6Addresses {
			result[addressKey("-6", iface.SystemName, address)] = struct{}{}
		}
	}
	return result
}

func addressKey(family, iface, address string) string {
	return strings.Join([]string{family, iface, address}, "\x00")
}

func routeSignatures(config domain.Config) (map[string]struct{}, error) {
	interfaces := interfaceMap(config)
	result := map[string]struct{}{}
	for _, route := range config.Routes {
		if !route.Enabled {
			continue
		}
		args, err := routeArgs("replace", route, interfaces)
		if err != nil {
			return nil, err
		}
		result[routeSignature(args)] = struct{}{}
	}
	return result, nil
}

func routeSignature(args []string) string {
	if len(args) < 4 {
		return strings.Join(args, "\x00")
	}
	withoutAction := append(append([]string{}, args[:2]...), args[3:]...)
	return strings.Join(withoutAction, "\x00")
}

func routeArgs(action string, route domain.Route, interfaces map[string]domain.Interface) ([]string, error) {
	family := "-4"
	if ip, _, err := net.ParseCIDR(route.DestinationCIDR); err == nil && ip.To4() == nil {
		family = "-6"
	}
	args := []string{family, "route", action, route.DestinationCIDR}
	if route.Gateway != "" {
		args = append(args, "via", route.Gateway)
	}
	if route.InterfaceID != "" {
		iface, ok := interfaces[route.InterfaceID]
		if !ok || iface.SystemName == "" {
			return nil, fmt.Errorf("route %s interface %s is unresolved", route.ID, route.InterfaceID)
		}
		args = append(args, "dev", iface.SystemName)
	}
	if route.Metric > 0 {
		args = append(args, "metric", strconv.Itoa(route.Metric))
	}
	return args, nil
}

func sortedInterfaces(interfaces []domain.Interface) []domain.Interface {
	result := append([]domain.Interface(nil), interfaces...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func sortedRoutes(routes []domain.Route) []domain.Route {
	result := append([]domain.Route(nil), routes...)
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
