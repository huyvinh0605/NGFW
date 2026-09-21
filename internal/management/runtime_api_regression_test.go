package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"golang.org/x/net/websocket"
)

// runtimeAPIFake models the engine IPC boundary. Keeping this fake at the
// management boundary ensures these tests exercise the production Runtime
// handlers rather than the legacy in-process API path.
type runtimeAPIFake struct {
	running       domain.Config
	version       domain.ConfigVersion
	health        domain.RuntimeHealth
	stats         domain.RuntimeStats
	events        domain.RuntimeEventPage
	configErr     error
	commitCalls   int
	lastCommitted domain.Config
}

func (f *runtimeAPIFake) GetRunningConfig(ctx context.Context) (domain.Config, domain.ConfigVersion, error) {
	if f.configErr != nil {
		return domain.Config{}, domain.ConfigVersion{}, f.configErr
	}
	return f.running, f.version, nil
}
func (f *runtimeAPIFake) CommitConfig(_ context.Context, candidate domain.Config, expectedVersion uint64, _, _, _ string) (domain.ConfigVersion, error) {
	if expectedVersion != f.version.Version {
		return f.version, errors.New("version conflict")
	}
	f.commitCalls++
	f.lastCommitted = candidate
	f.running = candidate
	f.version.Version++
	return f.version, nil
}
func (f *runtimeAPIFake) RollbackConfig(context.Context, string, string, string) (domain.ConfigVersion, error) {
	return f.version, nil
}
func (f *runtimeAPIFake) ListSessions(context.Context, domain.SessionQuery) (domain.SessionPage, error) {
	return domain.SessionPage{}, nil
}
func (f *runtimeAPIFake) GetSession(context.Context, string) (domain.RuntimeSession, error) {
	return domain.RuntimeSession{}, errors.New("session not found")
}
func (f *runtimeAPIFake) SessionStats(context.Context) (domain.RuntimeStats, error) {
	return f.stats, nil
}
func (f *runtimeAPIFake) RuntimeHealth(context.Context) (domain.RuntimeHealth, error) {
	return f.health, nil
}
func (f *runtimeAPIFake) RevokeSession(context.Context, string, string) error            { return nil }
func (f *runtimeAPIFake) AddTemporaryBlock(context.Context, domain.TemporaryBlock) error { return nil }
func (f *runtimeAPIFake) RemoveTemporaryBlock(context.Context, string) error             { return nil }
func (f *runtimeAPIFake) ListTemporaryBlocks(context.Context) ([]domain.TemporaryBlock, error) {
	return []domain.TemporaryBlock{}, nil
}
func (f *runtimeAPIFake) ReadRuntimeEvents(context.Context, uint64, int) (domain.RuntimeEventPage, error) {
	return f.events, nil
}

func newRuntimeAPIForTest(t *testing.T, runtime *runtimeAPIFake) *API {
	t.Helper()
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	return NewRuntimeAPI(runtime, manager, "", nil)
}

func TestRuntimeAPIEventsKeepRuntimeLifecycleSchema(t *testing.T) {
	runtime := &runtimeAPIFake{events: domain.RuntimeEventPage{Items: []domain.RuntimeEvent{{
		Sequence:  7,
		Kind:      domain.EventSessionCreated,
		SessionID: "session-1",
		Timestamp: time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC),
	}}}}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/api/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("events status=%d", response.StatusCode)
	}
	var envelope struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.Success {
		t.Fatal("runtime events response was not successful")
	}
	var page struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(envelope.Data, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0]["kind"] != string(domain.EventSessionCreated) || page.Items[0]["session_id"] != "session-1" {
		t.Fatalf("unexpected runtime event payload: %#v", page.Items)
	}
	if _, hasLegacySeverity := page.Items[0]["severity"]; hasLegacySeverity {
		t.Fatal("runtime event unexpectedly promised legacy severity field")
	}
}

func TestRuntimeAPIWebSocketStatsStaysOpen(t *testing.T) {
	runtime := &runtimeAPIFake{stats: domain.RuntimeStats{ActiveSessions: 3}}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/stats"
	conn, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var message struct {
		Success bool `json:"success"`
		Data    struct {
			ActiveSessions uint64 `json:"active_sessions"`
		} `json:"data"`
	}
	if err := websocket.JSON.Receive(conn, &message); err != nil {
		t.Fatal(err)
	}
	if !message.Success || message.Data.ActiveSessions != 3 {
		t.Fatalf("unexpected runtime websocket message: %#v", message)
	}
}

func TestRuntimeAPIWebSocketEventsStreamsRuntimeLifecycleEvent(t *testing.T) {
	runtime := &runtimeAPIFake{events: domain.RuntimeEventPage{Items: []domain.RuntimeEvent{{
		Sequence:  9,
		Kind:      domain.EventDecisionChanged,
		SessionID: "session-9",
		Timestamp: time.Now().UTC(),
	}}}}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/events"
	conn, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var message struct {
		Success bool `json:"success"`
		Data    struct {
			Sequence  uint64 `json:"sequence"`
			Kind      string `json:"kind"`
			SessionID string `json:"session_id"`
		} `json:"data"`
	}
	if err := websocket.JSON.Receive(conn, &message); err != nil {
		t.Fatal(err)
	}
	if !message.Success || message.Data.Sequence != 9 || message.Data.Kind != string(domain.EventDecisionChanged) || message.Data.SessionID != "session-9" {
		t.Fatalf("unexpected runtime events websocket message: %#v", message)
	}
}

func TestRuntimeAPIConfigReportsEngineTimeoutAsServiceUnavailable(t *testing.T) {
	runtime := &runtimeAPIFake{configErr: context.DeadlineExceeded}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("config status=%d", response.StatusCode)
	}
}

func TestRuntimeAPIConfigReadAndCandidateSaveDoNotActivateEngine(t *testing.T) {
	running := config.Defaults()
	runtime := &runtimeAPIFake{
		running: running,
		version: domain.ConfigVersion{Version: 7, Author: "admin", Timestamp: time.Now().UTC()},
	}
	manager, err := config.NewManager(t.TempDir(), running)
	if err != nil {
		t.Fatal(err)
	}
	api := NewRuntimeAPI(runtime, manager, "test-token", nil)
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	response, err := http.Get(server.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("config read status=%d", response.StatusCode)
	}
	if runtime.commitCalls != 0 || runtime.version.Version != 7 {
		t.Fatalf("reading Running activated engine: calls=%d version=%d", runtime.commitCalls, runtime.version.Version)
	}

	candidate := manager.Candidate()
	candidate.MaxSessions++
	payload, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/config/candidate", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("candidate save status=%d", response.StatusCode)
	}
	if runtime.commitCalls != 0 || runtime.version.Version != 7 {
		t.Fatalf("candidate save activated engine: calls=%d version=%d", runtime.commitCalls, runtime.version.Version)
	}
	if runtime.running.MaxSessions != running.MaxSessions {
		t.Fatalf("candidate save changed Running: got %d want %d", runtime.running.MaxSessions, running.MaxSessions)
	}
	if manager.Candidate().MaxSessions != candidate.MaxSessions {
		t.Fatal("candidate save did not update the management Candidate")
	}
	api.mu.RLock()
	for _, entry := range api.audit {
		if entry.Action == "COMMIT" {
			api.mu.RUnlock()
			t.Fatal("config read or candidate save created a COMMIT audit event")
		}
	}
	api.mu.RUnlock()

	request, err = http.NewRequest(http.MethodPost, server.URL+"/api/v1/policies/commit", strings.NewReader(`{"expected_version":7,"author":"test","comment":"activate"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("commit status=%d", response.StatusCode)
	}
	if runtime.commitCalls != 1 || runtime.version.Version != 8 || runtime.lastCommitted.MaxSessions != candidate.MaxSessions {
		t.Fatalf("explicit commit did not perform exactly one activation: calls=%d version=%d", runtime.commitCalls, runtime.version.Version)
	}
}
