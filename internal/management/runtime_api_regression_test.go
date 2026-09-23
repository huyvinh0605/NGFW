package management

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
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
	running        domain.Config
	version        domain.ConfigVersion
	health         domain.RuntimeHealth
	stats          domain.RuntimeStats
	events         domain.RuntimeEventPage
	configErr      error
	commitCalls    int
	lastCommitted  domain.Config
	inspection     domain.InspectionHealth
	capabilities   domain.InspectionCapabilities
	security       domain.SecurityEventPage
	securityEvent  domain.ThreatEvent
	securityQuery  domain.SecurityQuery
	securityErr    error
	securityGetErr error
}

func (f *runtimeAPIFake) InspectionHealth(context.Context) (domain.InspectionHealth, error) {
	return f.inspection, nil
}
func (f *runtimeAPIFake) InspectionCapabilities(context.Context) (domain.InspectionCapabilities, error) {
	return f.capabilities, nil
}
func (f *runtimeAPIFake) ListSecurityEvents(_ context.Context, query domain.SecurityQuery) (domain.SecurityEventPage, error) {
	f.securityQuery = query
	return f.security, f.securityErr
}
func (f *runtimeAPIFake) GetSecurityEvent(context.Context, string) (domain.ThreatEvent, error) {
	return f.securityEvent, f.securityGetErr
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

func TestRuntimeAPIM3HealthEventsAndStrictFilters(t *testing.T) {
	runtime := &runtimeAPIFake{
		inspection:    domain.InspectionHealth{Enabled: true, Status: "degraded", Generation: 7, Sources: map[string]domain.InspectionSourceStatus{"ips": {SensorID: "ips", Mode: domain.InspectionModeIPS, State: "UNAVAILABLE"}}, Stats: map[string]uint64{"observation_drops": 2}},
		capabilities:  domain.InspectionCapabilities{Supported: true, Modes: []domain.InspectionMode{domain.InspectionModeIDS, domain.InspectionModeIPS}, FailModes: []string{"OPEN"}},
		security:      domain.SecurityEventPage{Items: []domain.ThreatEvent{{EventID: "evt-1", CaptureMode: domain.InspectionModeIPS, CorrelationState: domain.CorrelationCorrelated, Severity: domain.SeverityHigh, Verdict: domain.VerdictDrop}}, NextSequence: 9},
		securityEvent: domain.ThreatEvent{EventID: "evt-1", SuricataFlowID: "18446744073709551615", CaptureMode: domain.InspectionModeIPS},
	}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()

	for _, path := range []string{"/api/v1/inspection/health", "/api/v1/inspection/capabilities", "/api/v1/security/events?mode=ips&severity=high&verdict=drop&correlation_state=correlated&limit=1", "/api/v1/security/events/evt-1"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			t.Fatalf("%s status=%d", path, response.StatusCode)
		}
		response.Body.Close()
	}
	if runtime.securityQuery.Mode != domain.InspectionModeIPS || runtime.securityQuery.Severity != domain.SeverityHigh || runtime.securityQuery.Verdict != domain.VerdictDrop || runtime.securityQuery.Correlation != domain.CorrelationCorrelated || runtime.securityQuery.Limit != 1 {
		t.Fatalf("security filters were not forwarded: %#v", runtime.securityQuery)
	}
	for _, path := range []string{"/api/v1/security/events?mode=off", "/api/v1/security/events?limit=201", "/api/v1/security/events?after=-1", "/api/v1/security/events?correlation_state=clean", "/api/v1/security/events?sensor_id=other", "/api/v1/security/events?cursor=bad", "/api/v1/security/events?cursor=stream:1&stream_id=stream"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusBadRequest {
			response.Body.Close()
			t.Fatalf("invalid filter %s status=%d", path, response.StatusCode)
		}
		response.Body.Close()
	}
}

func TestRuntimeAPISecurityCursorAndResponseLimit(t *testing.T) {
	runtime := &runtimeAPIFake{security: domain.SecurityEventPage{StreamID: "stream-a", Items: []domain.ThreatEvent{
		{EventID: "a", Sequence: 1, Signature: strings.Repeat("a", 700<<10)},
		{EventID: "b", Sequence: 2, Signature: strings.Repeat("b", 700<<10)},
	}, NextSequence: 2, NextCursor: "stream-a:2"}}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()
	response, err := http.Get(server.URL + "/api/v1/security/events?cursor=stream-a:7&limit=200")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || len(body) > 1<<20 {
		t.Fatalf("status=%d response bytes=%d", response.StatusCode, len(body))
	}
	if runtime.securityQuery.StreamID != "stream-a" || runtime.securityQuery.AfterSequence != 7 {
		t.Fatalf("cursor was not decoded: %#v", runtime.securityQuery)
	}
	var envelope struct {
		Data domain.SecurityEventPage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Data.Items) != 1 || !envelope.Data.HasMore || envelope.Data.NextCursor != "stream-a:7" {
		t.Fatalf("response was not bounded at an event boundary: %#v", envelope.Data)
	}
}

func TestRuntimeAPISecurityErrorsPreserveTimeoutUnavailableAndNotFound(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		listErr error
		getErr  error
		want    int
	}{
		{name: "list timeout", path: "/api/v1/security/events", listErr: context.DeadlineExceeded, want: http.StatusGatewayTimeout},
		{name: "list unavailable", path: "/api/v1/security/events", listErr: errors.New("engine offline"), want: http.StatusServiceUnavailable},
		{name: "get not found", path: "/api/v1/security/events/missing", getErr: domain.ErrSecurityEventNotFound, want: http.StatusNotFound},
		{name: "get unavailable", path: "/api/v1/security/events/missing", getErr: errors.New("engine offline"), want: http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runtime := &runtimeAPIFake{securityErr: tc.listErr, securityGetErr: tc.getErr}
			server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
			defer server.Close()
			response, err := http.Get(server.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != tc.want {
				t.Fatalf("status=%d want=%d", response.StatusCode, tc.want)
			}
		})
	}
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

func TestRuntimeAPIWebSocketStatsStaysOpenThroughProxyWithBrowserOrigin(t *testing.T) {
	runtime := &runtimeAPIFake{stats: domain.RuntimeStats{ActiveSessions: 8}}
	target := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(targetURL))
	defer proxy.Close()

	wsURL := "ws" + strings.TrimPrefix(proxy.URL, "http") + "/ws/stats"
	conn, err := websocket.Dial(wsURL, "", "http://192.168.100.1:5173")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	for index := 0; index < 2; index++ {
		var message struct {
			Success bool `json:"success"`
			Data    struct {
				ActiveSessions uint64 `json:"active_sessions"`
			} `json:"data"`
		}
		if err := websocket.JSON.Receive(conn, &message); err != nil {
			t.Fatalf("proxied message %d: %v", index, err)
		}
		if !message.Success || message.Data.ActiveSessions != 8 {
			t.Fatalf("unexpected proxied message %d: %#v", index, message)
		}
	}
}

func TestRuntimeAPIWebSocketClearsInheritedHTTPReadDeadline(t *testing.T) {
	runtime := &runtimeAPIFake{stats: domain.RuntimeStats{ActiveSessions: 5}}
	server := httptest.NewUnstartedServer(newRuntimeAPIForTest(t, runtime).Handler())
	server.Config.ReadTimeout = 25 * time.Millisecond
	server.Start()
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/stats"
	conn, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	for index := 0; index < 2; index++ {
		var message struct {
			Success bool `json:"success"`
		}
		if err := websocket.JSON.Receive(conn, &message); err != nil {
			t.Fatalf("message %d after HTTP ReadTimeout: %v", index, err)
		}
		if !message.Success {
			t.Fatalf("message %d was unsuccessful", index)
		}
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

func TestRuntimeAPIWebSocketEventsSendsHeartbeatWhenIdle(t *testing.T) {
	runtime := &runtimeAPIFake{}
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
		Success bool   `json:"success"`
		Type    string `json:"type"`
		Data    any    `json:"data"`
	}
	if err := websocket.JSON.Receive(conn, &message); err != nil {
		t.Fatal(err)
	}
	if !message.Success || message.Type != "heartbeat" || message.Data != nil {
		t.Fatalf("heartbeat=%#v", message)
	}
}

func TestRuntimeAPIWebSocketEventsReportsCursorGapExplicitly(t *testing.T) {
	runtime := &runtimeAPIFake{events: domain.RuntimeEventPage{StreamID: "boot-a", GapFrom: 5, NextSequence: 8}}
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
		Success  bool   `json:"success"`
		Type     string `json:"type"`
		StreamID string `json:"stream_id"`
		Data     struct {
			GapFrom      uint64 `json:"gap_from"`
			NextSequence uint64 `json:"next_sequence"`
		} `json:"data"`
	}
	if err := websocket.JSON.Receive(conn, &message); err != nil {
		t.Fatal(err)
	}
	if !message.Success || message.Type != "gap" || message.StreamID != "boot-a" || message.Data.GapFrom != 5 || message.Data.NextSequence != 8 {
		t.Fatalf("gap notification=%#v", message)
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

func TestRuntimeAPICandidateValidationStateFollowsCandidateRevision(t *testing.T) {
	running := config.Defaults()
	runtime := &runtimeAPIFake{running: running, version: domain.ConfigVersion{Version: 1}}
	manager, err := config.NewManager(t.TempDir(), running)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewRuntimeAPI(runtime, manager, "test-token", nil).Handler())
	defer server.Close()
	candidate := manager.Candidate()
	candidate.MaxSessions++
	body, _ := json.Marshal(candidate)
	request, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/config/candidate", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("candidate save status=%d", response.StatusCode)
	}
	readState := func() (bool, string) {
		response, err := http.Get(server.URL + "/api/v1/config")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var envelope struct {
			Data struct {
				CandidateValid bool `json:"candidate_valid"`
				Validation     struct {
					State string `json:"state"`
				} `json:"candidate_validation"`
			} `json:"data"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatal(err)
		}
		return envelope.Data.CandidateValid, envelope.Data.Validation.State
	}
	if valid, state := readState(); !valid || state != "NOT_RUN" {
		t.Fatalf("after save validation valid=%v state=%s", valid, state)
	}
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/policies/validate", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("validate status=%d", response.StatusCode)
	}
	if valid, state := readState(); !valid || state != "VALID" {
		t.Fatalf("after validate validation valid=%v state=%s", valid, state)
	}
}

func TestRuntimeAPIValidateRejectsM2IncompatibleScopeBeforeCommit(t *testing.T) {
	running := config.Defaults()
	runtime := &runtimeAPIFake{running: running, version: domain.ConfigVersion{Version: 3}}
	manager, err := config.NewManager(t.TempDir(), running)
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Policies = []domain.SecurityPolicy{{ID: "packet-rule", Priority: 1, Scope: "PACKET", Action: domain.DecisionAllow, Enabled: true}}
	if validation := manager.SetCandidate(candidate); len(validation) != 0 {
		t.Fatalf("syntax validation unexpectedly failed: %v", validation)
	}
	api := NewRuntimeAPI(runtime, manager, "test-token", nil)
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	configResponse, err := http.Get(server.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	var configEnvelope struct {
		Data struct {
			CandidateValid bool `json:"candidate_valid"`
		} `json:"data"`
	}
	if err := json.NewDecoder(configResponse.Body).Decode(&configEnvelope); err != nil {
		configResponse.Body.Close()
		t.Fatal(err)
	}
	configResponse.Body.Close()
	if configEnvelope.Data.CandidateValid {
		t.Fatal("config view advertised an M2-incompatible candidate as valid")
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/policies/validate", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("validate status=%d", response.StatusCode)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), "outside M2 session scope") || runtime.commitCalls != 0 || runtime.version.Version != 3 {
		t.Fatalf("validate payload=%s calls=%d version=%d", payload, runtime.commitCalls, runtime.version.Version)
	}
}

func TestRuntimeAPIValidationExplainsServiceSyntax(t *testing.T) {
	running := config.Defaults()
	runtime := &runtimeAPIFake{running: running, version: domain.ConfigVersion{Version: 2}}
	manager, err := config.NewManager(t.TempDir(), running)
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Policies = []domain.SecurityPolicy{{ID: "web", Priority: 1, Services: []string{"80"}, Scope: "SESSION", Action: domain.DecisionAllow, Enabled: true}}
	payload, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	api := NewRuntimeAPI(runtime, manager, "test-token", nil)
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	request, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/config/candidate", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responsePayload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(responsePayload), "tcp:80") {
		t.Fatalf("service validation status=%d payload=%s", response.StatusCode, responsePayload)
	}
}

func TestRuntimeAPIHealthUsesCanonicalComponentStatus(t *testing.T) {
	runtime := &runtimeAPIFake{health: domain.RuntimeHealth{Status: "healthy", UpdatedAt: time.Now().UTC()}}
	server := httptest.NewServer(newRuntimeAPIForTest(t, runtime).Handler())
	defer server.Close()
	response, err := http.Get(server.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope struct {
		Data struct {
			Components map[string]struct {
				Status         string `json:"status"`
				ManagementMode string `json:"management_mode"`
			} `json:"components"`
		} `json:"data"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	dataplane := envelope.Data.Components["dataplane"]
	if dataplane.Status != "healthy" || dataplane.ManagementMode != "engine" {
		t.Fatalf("dataplane health=%+v", dataplane)
	}
}

func TestRuntimeAPIWebSocketReconnectRepeatedDisconnectAndShutdown(t *testing.T) {
	runtime := &runtimeAPIFake{stats: domain.RuntimeStats{ActiveSessions: 4}}
	api := newRuntimeAPIForTest(t, runtime)
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws/stats"

	for index := 0; index < 12; index++ {
		conn, err := websocket.Dial(wsURL, "", server.URL)
		if err != nil {
			t.Fatalf("dial %d: %v", index, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var message map[string]any
		if err := websocket.JSON.Receive(conn, &message); err != nil {
			t.Fatalf("receive %d: %v", index, err)
		}
		if message["success"] != true {
			t.Fatalf("message %d=%#v", index, message)
		}
		// Closing immediately models both navigation and abrupt transport loss;
		// the next iteration proves a fresh connection is accepted.
		if err := conn.Close(); err != nil {
			t.Fatalf("close %d: %v", index, err)
		}
	}

	conn, err := websocket.Dial(wsURL, "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var first map[string]any
	if err := websocket.JSON.Receive(conn, &first); err != nil {
		t.Fatal(err)
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := api.Shutdown(shutdownContext); err != nil {
		t.Fatalf("websocket shutdown: %v", err)
	}
	var afterShutdown map[string]any
	if err := websocket.JSON.Receive(conn, &afterShutdown); err == nil {
		t.Fatalf("connection remained readable after API shutdown: %#v", afterShutdown)
	}
}
