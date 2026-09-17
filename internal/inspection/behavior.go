package inspection

import (
	"fmt"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type behaviorWindow struct {
	Started      time.Time
	Ports        map[string]struct{}
	Hosts        map[string]struct{}
	SYNs         int
	Sessions     int
	HTTPRequests int
}
type BehaviorDetector struct {
	mu               sync.Mutex
	Window           time.Duration
	PortThreshold    int
	HostThreshold    int
	SYNThreshold     int
	SessionThreshold int
	HTTPThreshold    int
	sources          map[string]*behaviorWindow
}

func NewBehaviorDetector(window time.Duration) *BehaviorDetector {
	if window <= 0 {
		window = time.Second
	}
	return &BehaviorDetector{Window: window, PortThreshold: 20, HostThreshold: 20, SYNThreshold: 100, SessionThreshold: 100, HTTPThreshold: 200, sources: map[string]*behaviorWindow{}}
}

type BehaviorObservation struct {
	SourceIP        string
	DestinationIP   string
	DestinationPort int
	SYN             bool
	NewSession      bool
	HTTPRequest     bool
}

func (d *BehaviorDetector) Observe(now time.Time, o BehaviorObservation) []domain.SecurityEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := d.sources[o.SourceIP]
	if w == nil || now.Sub(w.Started) >= d.Window {
		w = &behaviorWindow{Started: now, Ports: map[string]struct{}{}, Hosts: map[string]struct{}{}}
		d.sources[o.SourceIP] = w
	}
	if o.DestinationPort > 0 {
		w.Ports[fmt.Sprintf("%s:%d", o.DestinationIP, o.DestinationPort)] = struct{}{}
	}
	if o.DestinationIP != "" {
		w.Hosts[o.DestinationIP] = struct{}{}
	}
	if o.SYN {
		w.SYNs++
	}
	if o.NewSession {
		w.Sessions++
	}
	if o.HTTPRequest {
		w.HTTPRequests++
	}
	var events []domain.SecurityEvent
	add := func(category string, confidence float64, evidence string) {
		events = append(events, domain.SecurityEvent{EventID: fmt.Sprintf("behavior-%s-%d", category, now.UnixNano()), Timestamp: now, Detector: "BEHAVIOR", Category: category, Severity: domain.SeverityHigh, Confidence: confidence, SourceIP: o.SourceIP, DestinationIP: o.DestinationIP, Evidence: evidence})
	}
	if len(w.Ports) >= d.PortThreshold {
		add("PORT_SCAN", 1, fmt.Sprintf("%d unique destination ports in window", len(w.Ports)))
	}
	if len(w.Hosts) >= d.HostThreshold {
		add("HOST_SCAN", 1, fmt.Sprintf("%d unique destination hosts in window", len(w.Hosts)))
	}
	if w.SYNs >= d.SYNThreshold {
		add("SYN_RATE", 1, fmt.Sprintf("%d SYN packets in window", w.SYNs))
	}
	if w.Sessions >= d.SessionThreshold {
		add("SESSION_RATE", 1, fmt.Sprintf("%d new sessions in window", w.Sessions))
	}
	if w.HTTPRequests >= d.HTTPThreshold {
		add("HTTP_RATE", 1, fmt.Sprintf("%d HTTP requests in window", w.HTTPRequests))
	}
	return events
}
func (d *BehaviorDetector) Cleanup(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for source, w := range d.sources {
		if now.Sub(w.Started) >= 2*d.Window {
			delete(d.sources, source)
		}
	}
}
