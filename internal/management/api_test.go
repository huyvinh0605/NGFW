package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/auth"
	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/enforcement"
	"github.com/kltngfw/ngfw/internal/engine"
	"golang.org/x/net/websocket"
)

func TestAPIHealthAndProtectedCommit(t *testing.T) {
	m, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(engine.New(m, enforcement.NewMemory()), m, "secret", nil)
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	resp, err := http.Get(server.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("health status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/policies/commit", strings.NewReader(`{"expected_version":0}`))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthed commit status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/policies/commit", strings.NewReader(`{"expected_version":0}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("commit without engine status=%d", resp.StatusCode)
	}
}

func TestPoliciesRejectShadowedRuleWithoutMutatingCandidate(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Zones = []domain.Zone{{ID: "lan"}, {ID: "wan"}}
	candidate.Interfaces = []domain.Interface{
		{ID: "lan0", SystemName: "eth1", ZoneID: "lan", Mode: domain.InterfaceL3},
		{ID: "wan0", SystemName: "eth0", ZoneID: "wan", Mode: domain.InterfaceL3},
	}
	base := domain.SecurityPolicy{ID: "allow-lan-web", Name: "LAN web", Priority: 10, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443", "udp:53"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}
	candidate.Policies = []domain.SecurityPolicy{base}
	if errs := manager.SetCandidate(candidate); len(errs) != 0 {
		t.Fatalf("base candidate is invalid: %v", errs)
	}

	api := NewAPI(engine.New(manager, enforcement.NewMemory()), manager, "secret", nil)
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	shadowed := domain.SecurityPolicy{ID: "test-lan-http", Name: "LAN web access", Priority: 50, SourceZones: []string{"lan"}, DestinationZones: []string{"wan"}, Services: []string{"tcp:80", "tcp:443"}, Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}
	body, err := json.Marshal([]domain.SecurityPolicy{base, shadowed})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPut, server.URL+"/api/v1/policies", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var envelope struct {
		Error struct {
			Details []string `json:"details"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(envelope.Error.Details, "\n"), "policy test-lan-http is unreachable") {
		t.Fatalf("unexpected error: %#v", envelope.Error.Details)
	}
	if policies := manager.Candidate().Policies; len(policies) != 1 || policies[0].ID != "allow-lan-web" {
		t.Fatalf("invalid policy changed Candidate: %#v", policies)
	}
}

func TestAPIRollbackAppliesPreviousConfiguration(t *testing.T) {
	manager, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	candidate := manager.Candidate()
	candidate.Zones = []domain.Zone{{ID: "lan"}}
	manager.SetCandidate(candidate)
	if _, err := manager.Commit("test", "prepare", 0); err != nil {
		t.Fatal(err)
	}
	api := NewAPI(engine.New(manager, enforcement.NewMemory()), manager, "secret", nil)
	var applied domain.Config
	api.ApplyConfig = func(_ context.Context, value domain.Config) error {
		applied = value
		return nil
	}
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/policies/rollback", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rollback status=%d", response.StatusCode)
	}
	if len(applied.Zones) != 0 || len(manager.Running().Zones) != 0 {
		t.Fatalf("API rollback did not apply previous config: %#v", applied)
	}
}

func TestTemporaryBlockRemovalAndAudit(t *testing.T) {
	m, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	eng := engine.New(m, enforcement.NewMemory())
	api := NewAPI(eng, m, "secret", nil)
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/blocks", strings.NewReader(`{"indicator":"203.0.113.8","reason":"test"}`))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create block status=%d", resp.StatusCode)
	}
	var created struct {
		Data domain.TemporaryBlock `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if _, ok := eng.ActiveBlock("203.0.113.8", time.Now()); !ok {
		t.Fatal("block was not installed in engine")
	}

	req, _ = http.NewRequest(http.MethodDelete, server.URL+"/api/v1/blocks/"+created.Data.ID, nil)
	req.Header.Set("Authorization", "Bearer secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete block status=%d", resp.StatusCode)
	}
	if _, ok := eng.ActiveBlock("203.0.113.8", time.Now()); ok {
		t.Fatal("block remained active after deletion")
	}

	resp, err = http.Get(server.URL + "/api/v1/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var audit struct {
		Data struct {
			Items []domain.AuditEntry `json:"items"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	if len(audit.Data.Items) != 2 || audit.Data.Items[0].Action != "DELETE" || audit.Data.Items[1].Action != "CREATE" {
		t.Fatalf("unexpected audit entries: %#v", audit.Data.Items)
	}
}

func TestWebSocketStats(t *testing.T) {
	m, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(engine.New(m, enforcement.NewMemory()), m, "", nil)
	server := httptest.NewServer(api.Handler())
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
			ActiveSessions int `json:"active_sessions"`
		} `json:"data"`
	}
	if err := websocket.JSON.Receive(conn, &message); err != nil {
		t.Fatal(err)
	}
	if !message.Success || message.Data.ActiveSessions != 0 {
		t.Fatalf("unexpected websocket message: %#v", message)
	}
}

func TestAdminCanManageUsers(t *testing.T) {
	m, err := config.NewManager(t.TempDir(), config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	users := auth.NewStore(0)
	if err := users.AddUser("admin", "admin", "bootstrap password", auth.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	token, _, err := users.Login("admin", "bootstrap password")
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(engine.New(m, enforcement.NewMemory()), m, "", nil)
	api.Auth = users
	server := httptest.NewServer(api.Handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/api/v1/users")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated user list status=%d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/users", strings.NewReader(`{"username":"analyst","password":"analyst password","role":"VIEWER","enabled":true}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user status=%d", resp.StatusCode)
	}
	var created struct {
		Data auth.User `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Data.Username != "analyst" || created.Data.Role != auth.RoleViewer || created.Data.PasswordHash != "" {
		t.Fatalf("unexpected user response: %#v", created.Data)
	}
}
