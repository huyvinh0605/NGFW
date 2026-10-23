package conntrack

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type EventKind string

const (
	EventNew     EventKind = "NEW"
	EventUpdate  EventKind = "UPDATE"
	EventDestroy EventKind = "DESTROY"
)

var (
	ErrUnsupportedPlatform = errors.New("conntrack source is unsupported on this platform")
	ErrSourceClosed        = errors.New("conntrack source is closed")
	ErrDumpIncomplete      = errors.New("conntrack dump incomplete")
	ErrFlowNotFound        = errors.New("conntrack flow confirmed absent")
	ErrAmbiguousIdentity   = errors.New("conntrack identity is ambiguous")
)

type Presence struct {
	OriginalTuple bool
	ReplyTuple    bool
	// Counters remains the all-directions flag for existing Source users.
	// The directional flags preserve partial netlink updates.
	Counters         bool
	CountersOriginal bool
	CountersReply    bool
	Timeout          bool
	Timestamp        bool
	ID               bool
	Mark             bool
	Zone             bool
	ProtoInfo        bool
}

type Record struct {
	Identity        domain.ConntrackIdentity
	OriginalTuple   domain.Tuple
	ReplyTuple      *domain.Tuple
	PacketsOriginal uint64
	BytesOriginal   uint64
	PacketsReply    uint64
	BytesReply      uint64
	Timeout         time.Duration
	KernelStart     time.Time
	KernelStop      time.Time
	TCPState        string
	SeenReply       bool
	Mark            uint32
	Presence        Presence
	ObservedAt      time.Time
	RawState        string
}

type Event struct {
	Kind     EventKind
	Record   Record
	Received time.Time
}

type Loss struct {
	Reason   string
	Count    uint64
	At       time.Time
	ResyncID uint64
	Fatal    bool
}

type EventSink interface {
	TryEnqueue(Event) bool
	ReportLoss(Loss)
}

type DumpLimits struct {
	MaxRecords int
	MaxBytes   int64
	Deadline   time.Duration
}

type DumpResult struct {
	Records  int
	Bytes    int64
	Complete bool
	Reason   string
}

type Identity struct {
	BootID      string
	NetworkNS   string
	Zone        uint16
	Family      domain.IPFamily
	ID          uint32
	KernelStart uint64
	Original    domain.Tuple
}

type Source interface {
	Subscribe(context.Context, EventSink) error
	Dump(context.Context, DumpLimits, func(Record) error) (DumpResult, error)
	Get(context.Context, Identity) (Record, error)
	Close() error
}

type SourceHealth struct {
	Ready       bool
	Degraded    bool
	LastError   string
	LastResync  time.Time
	Events      uint64
	EventDrops  uint64
	DumpRecords uint64
}

func estimateRecordBytes(record Record) int64 {
	// FakeSource uses an approximate decoded-record charge in unit tests.
	// LinuxSource enforces its byte limit against raw netlink datagrams.
	return int64(256 + len(record.OriginalTuple.String()) + len(record.RawState))
}

// FakeSource is deterministic and bounded; it is used by M2 unit/race tests
// and is never wired into either production command.
type FakeSource struct {
	mu      sync.Mutex
	records map[domain.ConntrackIdentity]Record
	sinks   map[EventSink]struct{}
	closed  bool
	queue   []Event
	maxQ    int
}

func NewFakeSource(maxQueue int) *FakeSource {
	if maxQueue <= 0 {
		maxQueue = 10000
	}
	return &FakeSource{records: map[domain.ConntrackIdentity]Record{}, sinks: map[EventSink]struct{}{}, maxQ: maxQueue}
}

func (f *FakeSource) Subscribe(ctx context.Context, sink EventSink) error {
	if sink == nil {
		return errors.New("nil event sink")
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return ErrSourceClosed
	}
	f.sinks[sink] = struct{}{}
	queued := append([]Event(nil), f.queue...)
	f.queue = nil
	f.mu.Unlock()
	for _, ev := range queued {
		if !sink.TryEnqueue(ev) {
			sink.ReportLoss(Loss{Reason: "fake sink queue full", Count: 1, At: time.Now()})
		}
	}
	go func() {
		<-ctx.Done()
		f.mu.Lock()
		delete(f.sinks, sink)
		f.mu.Unlock()
	}()
	return nil
}

func (f *FakeSource) Emit(ev Event) error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return ErrSourceClosed
	}
	if ev.Received.IsZero() {
		ev.Received = time.Now().UTC()
	}
	if ev.Kind != EventDestroy {
		f.records[ev.Record.Identity] = ev.Record
	} else {
		delete(f.records, ev.Record.Identity)
	}
	sinks := make([]EventSink, 0, len(f.sinks))
	for sink := range f.sinks {
		sinks = append(sinks, sink)
	}
	if len(sinks) == 0 {
		if len(f.queue) >= f.maxQ {
			f.queue = f.queue[1:]
		}
		f.queue = append(f.queue, ev)
	}
	f.mu.Unlock()
	for _, sink := range sinks {
		if !sink.TryEnqueue(ev) {
			sink.ReportLoss(Loss{Reason: "fake sink queue full", Count: 1, At: ev.Received})
		}
	}
	return nil
}

// Forget removes a flow from the fake kernel view without publishing a
// DESTROY event. It models a lost conntrack notification so runtime resync
// tests can verify stale-session cleanup.
func (f *FakeSource) Forget(identity domain.ConntrackIdentity) {
	f.mu.Lock()
	delete(f.records, identity)
	f.mu.Unlock()
}

// SetSnapshot updates the fake kernel view without emitting an event. It
// models fields such as counters that may only become available during a
// later conntrack dump.
func (f *FakeSource) SetSnapshot(record Record) {
	f.mu.Lock()
	f.records[record.Identity] = record
	f.mu.Unlock()
}

func (f *FakeSource) Dump(ctx context.Context, limits DumpLimits, visit func(Record) error) (DumpResult, error) {
	if visit == nil {
		return DumpResult{}, errors.New("nil dump visitor")
	}
	if limits.MaxRecords <= 0 {
		limits.MaxRecords = 200000
	}
	if limits.MaxBytes <= 0 {
		limits.MaxBytes = 64 << 20
	}
	if limits.Deadline <= 0 {
		limits.Deadline = 30 * time.Second
	}
	deadline := time.NewTimer(limits.Deadline)
	defer deadline.Stop()
	f.mu.Lock()
	records := make([]Record, 0, len(f.records))
	for _, r := range f.records {
		records = append(records, r)
	}
	f.mu.Unlock()
	result := DumpResult{Complete: true}
	for _, r := range records {
		select {
		case <-ctx.Done():
			result.Complete = false
			result.Reason = ctx.Err().Error()
			return result, ctx.Err()
		case <-deadline.C:
			result.Complete = false
			result.Reason = "deadline"
			return result, ErrDumpIncomplete
		default:
		}
		if result.Records >= limits.MaxRecords || result.Bytes+estimateRecordBytes(r) > limits.MaxBytes {
			result.Complete = false
			if result.Records >= limits.MaxRecords {
				result.Reason = "record limit"
			} else {
				result.Reason = "byte limit"
			}
			return result, ErrDumpIncomplete
		}
		if err := visit(r); err != nil {
			result.Complete = false
			result.Reason = err.Error()
			return result, err
		}
		result.Records++
		result.Bytes += estimateRecordBytes(r)
	}
	return result, nil
}

func (f *FakeSource) Get(ctx context.Context, id Identity) (Record, error) {
	select {
	case <-ctx.Done():
		return Record{}, ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return Record{}, ErrSourceClosed
	}
	if !id.Original.Valid() || id.ID == 0 && id.KernelStart == 0 {
		return Record{}, ErrAmbiguousIdentity
	}
	var found *Record
	for identity, record := range f.records {
		if identity.BootID != id.BootID || identity.NetworkNS != id.NetworkNS ||
			identity.Zone != id.Zone || identity.Family != id.Family || identity.Original != id.Original {
			continue
		}
		if id.ID != 0 && identity.ID != id.ID ||
			id.KernelStart != 0 && identity.KernelStart != id.KernelStart || found != nil {
			return Record{}, ErrAmbiguousIdentity
		}
		copy := record
		found = &copy
	}
	if found == nil {
		return Record{}, ErrFlowNotFound
	}
	return *found, nil
}

func (f *FakeSource) Close() error {
	f.mu.Lock()
	f.closed = true
	f.sinks = map[EventSink]struct{}{}
	f.mu.Unlock()
	return nil
}
