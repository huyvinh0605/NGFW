package inspection

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type IDSProvider interface {
	Start(context.Context) error
	Events() <-chan domain.SecurityEvent
	Health() domain.ComponentHealth
}

type EVEAdapter struct {
	Command string
	Socket  string
	Ruleset string
	EVEPath string
	mu      sync.RWMutex
	events  chan domain.SecurityEvent
	health  domain.ComponentHealth
}

func NewEVEAdapter(command, socket string) *EVEAdapter {
	return &EVEAdapter{Command: command, Socket: socket, events: make(chan domain.SecurityEvent, 1000), health: domain.ComponentHealth{Name: "ids", Status: "degraded", UpdatedAt: time.Now()}}
}
func (a *EVEAdapter) Start(ctx context.Context) error {
	if a.Command == "" {
		a.setHealth("degraded", "suricata binary is not configured")
		return nil
	}
	args := []string{"--unix-socket", a.Socket}
	if a.Ruleset != "" {
		args = append([]string{"-c", a.Ruleset}, args...)
	}
	cmd := exec.CommandContext(ctx, a.Command, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		a.setHealth("down", err.Error())
		return err
	}
	a.setHealth("ok", "")
	if a.EVEPath != "" {
		go a.tailEVE(ctx, a.EVEPath)
	} else {
		go a.readEVE(ctx, stdout)
	}
	go func() {
		err := cmd.Wait()
		if ctx.Err() == nil && err != nil {
			a.setHealth("down", err.Error())
		}
	}()
	return nil
}

func (a *EVEAdapter) tailEVE(ctx context.Context, path string) {
	var offset int64
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		file, err := os.Open(path)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if _, err := file.Seek(offset, 0); err != nil {
			_ = file.Close()
			time.Sleep(500 * time.Millisecond)
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			offset += int64(len(scanner.Bytes())) + 1
			a.publishEVE(ctx, scanner.Bytes())
		}
		_ = file.Close()
		time.Sleep(200 * time.Millisecond)
	}
}
func (a *EVEAdapter) Events() <-chan domain.SecurityEvent { return a.events }
func (a *EVEAdapter) Health() domain.ComponentHealth {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.health
}
func (a *EVEAdapter) readEVE(ctx context.Context, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		a.publishEVE(ctx, scanner.Bytes())
	}
}

func (a *EVEAdapter) publishEVE(ctx context.Context, line []byte) {
	var raw struct {
		EventType string    `json:"event_type"`
		Timestamp time.Time `json:"timestamp"`
		FlowID    uint64    `json:"flow_id"`
		SrcIP     string    `json:"src_ip"`
		DstIP     string    `json:"dest_ip"`
		SrcPort   int       `json:"src_port"`
		DstPort   int       `json:"dest_port"`
		Proto     string    `json:"proto"`
		Alert     struct {
			SignatureID int    `json:"signature_id"`
			Signature   string `json:"signature"`
			Category    string `json:"category"`
			Severity    int    `json:"severity"`
		} `json:"alert"`
	}
	if json.Unmarshal(line, &raw) != nil || raw.EventType != "alert" {
		return
	}
	severity := domain.SeverityLow
	if raw.Alert.Severity <= 1 {
		severity = domain.SeverityCritical
	} else if raw.Alert.Severity == 2 {
		severity = domain.SeverityHigh
	} else if raw.Alert.Severity == 3 {
		severity = domain.SeverityMedium
	}
	ev := domain.SecurityEvent{EventID: fmt.Sprintf("suricata-%d-%d", raw.FlowID, time.Now().UnixNano()), Timestamp: raw.Timestamp, FlowID: fmt.Sprint(raw.FlowID), Detector: "IPS", Category: raw.Alert.Category, SignatureID: fmt.Sprint(raw.Alert.SignatureID), Severity: severity, Confidence: 1, SourceIP: raw.SrcIP, DestinationIP: raw.DstIP, Evidence: raw.Alert.Signature, Metadata: map[string]any{"src_port": raw.SrcPort, "dst_port": raw.DstPort, "protocol": raw.Proto}}
	select {
	case a.events <- ev:
	case <-ctx.Done():
		return
	default:
		a.setHealth("degraded", "IDS event queue is full")
	}
}
func (a *EVEAdapter) setHealth(status, message string) {
	a.mu.Lock()
	a.health = domain.ComponentHealth{Name: "ids", Status: status, Message: message, UpdatedAt: time.Now()}
	a.mu.Unlock()
}

// PCAPJob describes a bounded synchronous inspection job used by the lab
// request gate. The adapter keeps each job isolated in its own output folder.
type PCAPJob struct {
	Input     string
	OutputDir string
}

func RunPCAP(ctx context.Context, binary, configPath string, job PCAPJob) ([]domain.SecurityEvent, error) {
	if binary == "" {
		binary = "suricata"
	}
	if job.Input == "" || job.OutputDir == "" {
		return nil, fmt.Errorf("pcap input and output are required")
	}
	if err := os.MkdirAll(job.OutputDir, 0700); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary, "-c", configPath, "-r", job.Input, "-l", job.OutputDir, "--runmode", "single")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("suricata pcap failed: %w: %s", err, string(out))
	}
	files, err := filepath.Glob(filepath.Join(job.OutputDir, "eve.json"))
	if err != nil {
		return nil, err
	}
	var events []domain.SecurityEvent
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var raw map[string]any
			if json.Unmarshal(scanner.Bytes(), &raw) != nil {
				continue
			}
			if raw["event_type"] != "alert" {
				continue
			}
			events = append(events, domain.SecurityEvent{EventID: fmt.Sprintf("suricata-%d", time.Now().UnixNano()), Timestamp: time.Now().UTC(), Detector: "IPS", Severity: domain.SeverityHigh, Confidence: 1, Metadata: raw})
		}
		_ = f.Close()
	}
	return events, nil
}
