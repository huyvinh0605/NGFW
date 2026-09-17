package flow

import (
	"fmt"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

// Scope prevents identical tuples in different network namespaces or
// conntrack zones from being merged.
type Scope struct {
	NetworkNamespace string
	ConntrackZone    uint16
}

type Key struct {
	Scope Scope
	Tuple domain.Tuple
}

func NewKey(scope Scope, tuple domain.Tuple) (Key, error) {
	if !tuple.Valid() {
		return Key{}, fmt.Errorf("invalid tuple")
	}
	return Key{Scope: scope, Tuple: tuple}, nil
}

func (k Key) Reverse() Key { k.Tuple = k.Tuple.Reverse(); return k }

func (k Key) String() string {
	return fmt.Sprintf("%s/%d/%s", k.Scope.NetworkNamespace, k.Scope.ConntrackZone, k.Tuple.String())
}

// Bidirectional is a deterministic pair independent of packet arrival order.
// Direction is retained by Key; the pair is only the lookup identity.
type Bidirectional struct {
	A Key
	B Key
}

func Pair(a, b Key) Bidirectional {
	if b.String() < a.String() {
		return Bidirectional{A: b, B: a}
	}
	return Bidirectional{A: a, B: b}
}

func PairFromTuple(key Key) Bidirectional { return Pair(key, key.Reverse()) }

func (p Bidirectional) String() string { return p.A.String() + "|" + p.B.String() }

// Aliases returns all safe tuple views for one conntrack record. Duplicates
// are removed without depending on string concatenation for identity.
func Aliases(scope Scope, original domain.Tuple, reply *domain.Tuple, translated *domain.Tuple) []Key {
	values := make([]Key, 0, 8)
	seen := map[Key]struct{}{}
	add := func(t domain.Tuple) {
		if !t.Valid() {
			return
		}
		k := Key{Scope: scope, Tuple: t}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		values = append(values, k)
	}
	add(original)
	add(original.Reverse())
	if reply != nil {
		add(*reply)
		add(reply.Reverse())
	}
	if translated != nil {
		add(*translated)
		add(translated.Reverse())
		// The forward filter sees pre-SNAT source and post-DNAT
		// destination. For a connection translated on both sides this
		// tuple is distinct from both the conntrack original and the
		// post-NAT tuple, so index it as well.
		policy := original
		policy.DstIP = translated.DstIP
		policy.DstPort = translated.DstPort
		add(policy)
		add(policy.Reverse())
	}
	return values
}

func ParseLegacy(k domain.FlowKey) (Key, error) {
	t, err := domain.TupleFromFlowKey(k)
	if err != nil {
		return Key{}, err
	}
	return NewKey(Scope{NetworkNamespace: strings.TrimSpace(k.Namespace)}, t)
}

func (k Key) FlowKey() domain.FlowKey { return k.Tuple.FlowKey(k.Scope.NetworkNamespace) }
