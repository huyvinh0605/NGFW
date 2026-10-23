package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const m4RoutingPriority = 14000
const m4MarkSpec = "0x40000000/0x40000000"

type TPROXYRoutePlan struct {
	Family   string `json:"family"`
	Table    int    `json:"table"`
	Priority int    `json:"priority"`
	Mark     uint32 `json:"mark"`
	Mask     uint32 `json:"mask"`
}

func M4TPROXYRoutePlan() TPROXYRoutePlan {
	return TPROXYRoutePlan{Family: "ipv4", Table: M4TPROXYRouteTable, Priority: m4RoutingPriority, Mark: M4TPROXYMark, Mask: M4TPROXYMark}
}

// TPROXYRouting manages one fixed, NGFW-owned IPv4 policy route. It refuses
// foreign occupants of its table/priority and never flushes unrelated routes.
// The activation coordinator must call Ensure before adding an nft selector,
// and Remove only after removing that selector.
type TPROXYRouting struct{ IP IPCommandRunner }

type tproxyRouteState struct{ rule, route bool }

func (routing TPROXYRouting) Preflight(ctx context.Context) error {
	_, err := routing.read(ctx)
	return err
}

func (routing TPROXYRouting) read(ctx context.Context) (tproxyRouteState, error) {
	if routing.IP == nil {
		return tproxyRouteState{}, errors.New("TPROXY routing has no ip command runner")
	}
	ruleJSON, err := routing.IP.Run(ctx, "-j", "-4", "rule", "show")
	if err != nil {
		return tproxyRouteState{}, fmt.Errorf("read policy rules: %w", err)
	}
	var rules []struct {
		Priority int             `json:"priority"`
		Table    json.RawMessage `json:"table"`
		Fwmark   string          `json:"fwmark"`
		Fwmask   string          `json:"fwmask"`
	}
	if err := json.Unmarshal(ruleJSON, &rules); err != nil {
		return tproxyRouteState{}, fmt.Errorf("decode policy rules: %w", err)
	}
	state := tproxyRouteState{}
	for _, rule := range rules {
		table, err := m4RouteTableNumber(rule.Table)
		if err != nil {
			if rule.Priority == m4RoutingPriority {
				return tproxyRouteState{}, fmt.Errorf("foreign policy rule occupies M4 TPROXY priority")
			}
			continue // named system tables do not occupy the numeric M4 table
		}
		mark, markErr := strconv.ParseUint(rule.Fwmark, 0, 32)
		mask, maskErr := strconv.ParseUint(rule.Fwmask, 0, 32)
		owned := rule.Priority == m4RoutingPriority && table == M4TPROXYRouteTable && markErr == nil && maskErr == nil && uint32(mark) == M4TPROXYMark && uint32(mask) == M4TPROXYMark
		if owned {
			if state.rule {
				return tproxyRouteState{}, errors.New("duplicate M4 policy rule at owned priority")
			}
			state.rule = true
		} else if rule.Priority == m4RoutingPriority || table == M4TPROXYRouteTable || markErr == nil && maskErr == nil && uint32(mark)&uint32(mask)&M4TPROXYMark != 0 {
			return tproxyRouteState{}, fmt.Errorf("foreign policy rule conflicts with M4 TPROXY routing")
		}
	}
	routeJSON, err := routing.IP.Run(ctx, "-j", "-4", "route", "show", "table", "all")
	if err != nil {
		return tproxyRouteState{}, fmt.Errorf("read routing tables: %w", err)
	}
	var routes []struct {
		Table json.RawMessage `json:"table"`
		Type  string          `json:"type"`
		Dst   string          `json:"dst"`
		Dev   string          `json:"dev"`
	}
	if err := json.Unmarshal(routeJSON, &routes); err != nil {
		return tproxyRouteState{}, fmt.Errorf("decode routing tables: %w", err)
	}
	for _, route := range routes {
		table, err := m4RouteTableNumber(route.Table)
		if err != nil || table != M4TPROXYRouteTable {
			continue
		}
		if route.Type != "local" || route.Dst != "default" && route.Dst != "0.0.0.0/0" || route.Dev != "lo" || state.route {
			return tproxyRouteState{}, fmt.Errorf("foreign route occupies M4 TPROXY table")
		}
		state.route = true
	}
	return state, nil
}

func m4RouteTableNumber(raw json.RawMessage) (int, error) {
	var number int
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, nil
	}
	var label string
	if err := json.Unmarshal(raw, &label); err != nil {
		return 0, err
	}
	return strconv.Atoi(label)
}

func (routing TPROXYRouting) Verify(ctx context.Context) error {
	state, err := routing.read(ctx)
	if err != nil {
		return err
	}
	if !state.rule || !state.route {
		return errors.New("M4 TPROXY policy routing is incomplete")
	}
	return nil
}

func (routing TPROXYRouting) Ensure(ctx context.Context) error {
	state, err := routing.read(ctx)
	if err != nil {
		return err
	}
	addedRoute, addedRule := false, false
	rollback := func(cause error) error {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var failures []error
		if addedRule {
			_, err := routing.IP.Run(rollbackCtx, "-4", "rule", "del", "priority", strconv.Itoa(m4RoutingPriority), "fwmark", m4MarkSpec, "lookup", strconv.Itoa(M4TPROXYRouteTable))
			failures = append(failures, err)
		}
		if addedRoute {
			_, err := routing.IP.Run(rollbackCtx, "-4", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(M4TPROXYRouteTable))
			failures = append(failures, err)
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	if !state.route {
		if _, err := routing.IP.Run(ctx, "-4", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(M4TPROXYRouteTable)); err != nil {
			return fmt.Errorf("add M4 local route: %w", err)
		}
		addedRoute = true
	}
	if !state.rule {
		if _, err := routing.IP.Run(ctx, "-4", "rule", "add", "priority", strconv.Itoa(m4RoutingPriority), "fwmark", m4MarkSpec, "lookup", strconv.Itoa(M4TPROXYRouteTable)); err != nil {
			return rollback(fmt.Errorf("add M4 mark rule: %w", err))
		}
		addedRule = true
	}
	if err := routing.Verify(ctx); err != nil {
		return rollback(err)
	}
	return nil
}

func (routing TPROXYRouting) Remove(ctx context.Context) error {
	state, err := routing.read(ctx)
	if err != nil {
		return err
	}
	if state.rule {
		if out, err := routing.IP.Run(ctx, "-4", "rule", "del", "priority", strconv.Itoa(m4RoutingPriority), "fwmark", m4MarkSpec, "lookup", strconv.Itoa(M4TPROXYRouteTable)); err != nil {
			return fmt.Errorf("remove M4 mark rule: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if state.route {
		if out, err := routing.IP.Run(ctx, "-4", "route", "del", "local", "0.0.0.0/0", "dev", "lo", "table", strconv.Itoa(M4TPROXYRouteTable)); err != nil {
			return fmt.Errorf("remove M4 local route: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
