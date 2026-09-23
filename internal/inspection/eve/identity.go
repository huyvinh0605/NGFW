package eve

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

// EventID is stable for the same source record and independent of ingestion
// time. Length prefixes prevent delimiter/collision ambiguities.
func EventID(source inspection.SourcePosition, line []byte) string {
	h := sha256.New()
	putString := func(value string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(value)))
		h.Write(n[:])
		h.Write([]byte(value))
	}
	putString(source.SensorID)
	putString(source.SensorEpoch)
	putString(source.FileGeneration)
	var offset [8]byte
	binary.BigEndian.PutUint64(offset[:], uint64(source.ByteStart))
	h.Write(offset[:])
	binary.BigEndian.PutUint64(offset[:], uint64(source.ByteEnd))
	h.Write(offset[:])
	h.Write(line)
	return hex.EncodeToString(h.Sum(nil))
}

type dedupEntry struct {
	id     string
	bytes  int
	seenAt time.Time
}

type Deduper struct {
	mu       sync.Mutex
	maxCount int
	maxBytes int
	ttl      time.Duration
	bytes    int
	items    map[string]*list.Element
	lru      *list.List
}

func NewDeduper(maxCount, maxBytes int, ttl time.Duration) *Deduper {
	if maxCount <= 0 {
		maxCount = 4096
	}
	if maxBytes <= 0 {
		maxBytes = 8 << 20
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Deduper{maxCount: maxCount, maxBytes: maxBytes, ttl: ttl, items: make(map[string]*list.Element), lru: list.New()}
}

// SeenOrAdd returns true when the id was already seen inside the retention
// window. It performs bounded cleanup on the caller's event path, not with a
// timer per record.
func (d *Deduper) SeenOrAdd(id string, now time.Time) bool {
	if id == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cleanupLocked(now)
	if element, ok := d.items[id]; ok {
		element.Value.(*dedupEntry).seenAt = now
		d.lru.MoveToFront(element)
		return true
	}
	entry := &dedupEntry{id: id, bytes: len(id), seenAt: now}
	d.items[id] = d.lru.PushFront(entry)
	d.bytes += entry.bytes
	for len(d.items) > d.maxCount || d.bytes > d.maxBytes {
		d.removeOldestLocked()
	}
	return false
}

func (d *Deduper) cleanupLocked(now time.Time) {
	for element := d.lru.Back(); element != nil; {
		previous := element.Prev()
		if now.Sub(element.Value.(*dedupEntry).seenAt) > d.ttl {
			d.removeElementLocked(element)
		}
		element = previous
	}
}
func (d *Deduper) removeOldestLocked() {
	if element := d.lru.Back(); element != nil {
		d.removeElementLocked(element)
	}
}
func (d *Deduper) removeElementLocked(element *list.Element) {
	entry := element.Value.(*dedupEntry)
	delete(d.items, entry.id)
	d.bytes -= entry.bytes
	d.lru.Remove(element)
}

func DiscoveryID(source inspection.SourcePosition, flowID uint64, app, direction string) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], flowID)
	h := sha256.New()
	h.Write(raw[:])
	h.Write([]byte(source.SensorID))
	h.Write([]byte{0})
	h.Write([]byte(source.SensorEpoch))
	h.Write([]byte{0})
	h.Write([]byte(app))
	h.Write([]byte{0})
	h.Write([]byte(direction))
	return hex.EncodeToString(h.Sum(nil))
}
