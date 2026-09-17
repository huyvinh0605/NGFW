package management

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/auth"
	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engine"
	"github.com/kltngfw/ngfw/internal/inspection"
	"golang.org/x/net/websocket"
)

type API struct {
	Engine      *engine.Engine
	Runtime     RuntimeClient
	Config      *config.Manager
	Token       string
	Auth        *auth.Store
	Logger      *slog.Logger
	ApplyConfig func(context.Context, domain.Config) error
	Reputation  *inspection.ReputationStore
	mu          sync.RWMutex
	events      []domain.SecurityEvent
	audit       []domain.AuditEntry
	blocks      map[string]domain.TemporaryBlock
}

func NewAPI(e *engine.Engine, c *config.Manager, token string, l *slog.Logger) *API {
	if l == nil {
		l = slog.Default()
	}
	return &API{Engine: e, Config: c, Token: token, Logger: l, Reputation: inspection.NewReputationStore(100000), blocks: map[string]domain.TemporaryBlock{}}
}

// NewRuntimeAPI constructs the production management API. Runtime state is
// owned by ngfw-engine and reached only through RuntimeClient (normally the
// Unix-socket engine IPC client). The legacy NewAPI constructor remains for
// existing unit tests and compatibility fixtures.
func NewRuntimeAPI(runtime RuntimeClient, c *config.Manager, token string, l *slog.Logger) *API {
	if l == nil {
		l = slog.Default()
	}
	return &API{Runtime: runtime, Config: c, Token: token, Logger: l, Reputation: inspection.NewReputationStore(100000), blocks: map[string]domain.TemporaryBlock{}}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.health)
	mux.HandleFunc("/api/v1/auth/login", a.login)
	mux.HandleFunc("/api/v1/auth/logout", a.logout)
	mux.HandleFunc("/api/v1/auth/me", a.me)
	mux.HandleFunc("/api/v1/users", a.users)
	mux.HandleFunc("/api/v1/users/", a.userByID)
	mux.HandleFunc("/api/v1/health", a.health)
	mux.HandleFunc("/api/v1/config", a.configView)
	mux.HandleFunc("/api/v1/config/candidate", a.candidate)
	mux.HandleFunc("/api/v1/interfaces", a.interfaces)
	mux.HandleFunc("/api/v1/interfaces/", func(w http.ResponseWriter, r *http.Request) { a.objectByID(w, r, "interface") })
	mux.HandleFunc("/api/v1/zones", a.zones)
	mux.HandleFunc("/api/v1/zones/", func(w http.ResponseWriter, r *http.Request) { a.objectByID(w, r, "zone") })
	mux.HandleFunc("/api/v1/routes", a.routes)
	mux.HandleFunc("/api/v1/routes/", func(w http.ResponseWriter, r *http.Request) { a.objectByID(w, r, "route") })
	mux.HandleFunc("/api/v1/nat/rules", a.natRules)
	mux.HandleFunc("/api/v1/nat/rules/", func(w http.ResponseWriter, r *http.Request) { a.objectByID(w, r, "nat") })
	mux.HandleFunc("/api/v1/policies", a.policies)
	mux.HandleFunc("/api/v1/policies/", a.policyByID)
	mux.HandleFunc("/api/v1/security-profiles", a.profiles)
	mux.HandleFunc("/api/v1/security-profiles/", func(w http.ResponseWriter, r *http.Request) { a.objectByID(w, r, "profile") })
	mux.HandleFunc("/api/v1/policies/validate", a.validate)
	mux.HandleFunc("/api/v1/policies/commit", a.commit)
	mux.HandleFunc("/api/v1/policies/rollback", a.rollback)
	mux.HandleFunc("/api/v1/sessions", a.sessions)
	mux.HandleFunc("/api/v1/sessions/", a.sessionByID)
	mux.HandleFunc("/api/v1/events", a.eventsHandler)
	mux.HandleFunc("/api/v1/events/", a.eventByID)
	mux.HandleFunc("/api/v1/audit", a.auditHandler)
	mux.HandleFunc("/api/v1/blocks", a.blocksHandler)
	mux.HandleFunc("/api/v1/blocks/", a.blockByID)
	mux.HandleFunc("/api/v1/stats/system", a.stats)
	mux.HandleFunc("/api/v1/stats/interfaces", a.stats)
	mux.HandleFunc("/api/v1/stats/traffic", a.stats)
	mux.HandleFunc("/api/v1/stats/applications", a.stats)
	mux.HandleFunc("/api/v1/stats/threats", a.stats)
	mux.HandleFunc("/api/v1/ml/status", a.mlStatus)
	mux.HandleFunc("/api/v1/reputation", a.reputation)
	mux.Handle("/ws/events", websocket.Handler(a.wsEvents))
	mux.Handle("/ws/stats", websocket.Handler(a.wsStats))
	return logging(recoverer(a.authMiddleware(mux)), a.Logger)
}

func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicRead := r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/v1/users")
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/v1/auth/login" || publicRead {
			next.ServeHTTP(w, r)
			return
		}
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.Token != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(a.Token)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		if a.Auth != nil {
			if user, ok := a.Auth.Validate(provided); ok {
				if r.Method != http.MethodGet && user.Role == auth.RoleViewer {
					writeError(w, http.StatusForbidden, "FORBIDDEN", "viewer role is read-only")
					return
				}
				adminOnly := strings.HasPrefix(r.URL.Path, "/api/v1/config") || strings.HasSuffix(r.URL.Path, "/commit") || strings.HasSuffix(r.URL.Path, "/rollback") || strings.HasPrefix(r.URL.Path, "/api/v1/interfaces") || strings.HasPrefix(r.URL.Path, "/api/v1/zones") || strings.HasPrefix(r.URL.Path, "/api/v1/routes") || strings.HasPrefix(r.URL.Path, "/api/v1/nat/") || strings.HasPrefix(r.URL.Path, "/api/v1/security-profiles") || strings.HasPrefix(r.URL.Path, "/api/v1/users")
				if adminOnly && user.Role != auth.RoleAdmin {
					writeError(w, http.StatusForbidden, "FORBIDDEN", "admin role required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
		}
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
	})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || a.Auth == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "authentication is not configured")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, "INVALID_JSON", err.Error())
		return
	}
	token, user, err := a.Auth.Login(req.Username, req.Password)
	if err != nil {
		writeError(w, 401, "INVALID_CREDENTIALS", "invalid credentials")
		return
	}
	a.recordAudit(domain.AuditEntry{ID: "audit-" + strconv.FormatInt(time.Now().UnixNano(), 10), Timestamp: time.Now().UTC(), Actor: user.Username, Role: string(user.Role), Action: "LOGIN", Resource: "auth", Result: "SUCCESS"})
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"token": token, "user": user}})
}
func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	a.auditAction(r, "LOGOUT", "auth", "", "SUCCESS", "")
	if a.Auth != nil {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		a.Auth.Logout(token)
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]bool{"logged_out": true}})
}
func (a *API) me(w http.ResponseWriter, r *http.Request) {
	if a.Auth == nil {
		writeError(w, 404, "NOT_FOUND", "authentication is not configured")
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if user, ok := a.Auth.Validate(token); ok {
		writeJSON(w, 200, map[string]any{"success": true, "data": user})
		return
	}
	writeError(w, 401, "UNAUTHORIZED", "authentication required")
}

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	if a.Auth == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "account authentication is not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": a.Auth.List()})
	case http.MethodPost:
		var req struct {
			ID       string    `json:"id"`
			Username string    `json:"username"`
			Password string    `json:"password"`
			Role     auth.Role `json:"role"`
			Enabled  *bool     `json:"enabled"`
		}
		if err := decode(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
			return
		}
		if req.ID == "" {
			req.ID = "user-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		if err := a.Auth.AddUser(req.ID, req.Username, req.Password, req.Role); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_USER", err.Error())
			return
		}
		if req.Enabled != nil && !*req.Enabled {
			if err := a.Auth.UpdateUser(req.ID, req.Username, "", req.Role, false); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_USER", err.Error())
				return
			}
		}
		user, _ := a.Auth.Get(req.ID)
		a.auditAction(r, "CREATE", "user", req.ID, "SUCCESS", req.Username)
		writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": user})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or POST required")
	}
}

func (a *API) userByID(w http.ResponseWriter, r *http.Request) {
	if a.Auth == nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "account authentication is not configured")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if id == "" {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user id required")
		return
	}
	current, exists := a.Auth.Get(id)
	if !exists {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": current})
	case http.MethodPut:
		actor, actorRole := a.auditIdentity(r)
		var req struct {
			Username string    `json:"username"`
			Password string    `json:"password"`
			Role     auth.Role `json:"role"`
			Enabled  *bool     `json:"enabled"`
		}
		if err := decode(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
			return
		}
		if req.Username == "" {
			req.Username = current.Username
		}
		if req.Role == "" {
			req.Role = current.Role
		}
		enabled := current.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if err := a.Auth.UpdateUser(id, req.Username, req.Password, req.Role, enabled); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_USER", err.Error())
			return
		}
		updated, _ := a.Auth.Get(id)
		a.recordAudit(domain.AuditEntry{ID: "audit-" + strconv.FormatInt(time.Now().UnixNano(), 10), Timestamp: time.Now().UTC(), Actor: actor, Role: actorRole, Action: "UPDATE", Resource: "user", ResourceID: id, Result: "SUCCESS", Message: req.Username})
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": updated})
	case http.MethodDelete:
		actor, actorRole := a.auditIdentity(r)
		if err := a.Auth.DeleteUser(id); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_USER", err.Error())
			return
		}
		audit := domain.AuditEntry{ID: "audit-" + strconv.FormatInt(time.Now().UnixNano(), 10), Timestamp: time.Now().UTC(), Actor: actor, Role: actorRole, Action: "DELETE", Resource: "user", ResourceID: id, Result: "SUCCESS", Message: current.Username}
		a.recordAudit(audit)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]string{"deleted": id}})
	default:
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET, PUT or DELETE required")
	}
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	if a.Runtime != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		health, err := a.Runtime.RuntimeHealth(ctx)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "error": map[string]string{"code": "ENGINE_UNAVAILABLE", "message": err.Error()}})
			return
		}
		status := strings.ToLower(health.Status)
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"status": status, "components": map[string]any{"session_engine": health, "dataplane": map[string]any{"status": "managed-by-engine"}}}})
		return
	}
	components := a.Engine.Health()
	status := "HEALTHY"
	for _, h := range components {
		if h.Status == "down" || h.Status == "degraded" {
			status = "DEGRADED"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"status": strings.ToLower(status), "components": components}})
}
func (a *API) configView(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	if a.Runtime != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		running, version, err := a.Runtime.GetRunningConfig(ctx)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"running": running, "candidate": a.Config.Candidate(), "version": version, "candidate_valid": len(a.Config.ValidateCandidate()) == 0}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": a.Config.Export()})
}
func (a *API) candidate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": a.Config.Candidate()})
	case "PUT", "POST":
		var c domain.Config
		if err := decode(r, &c); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		errs := a.Config.SetCandidate(c)
		if len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "candidate rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "config", "candidate", "SUCCESS", "candidate replaced")
		writeJSON(w, 200, map[string]any{"success": true, "data": c})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}
func (a *API) policies(w http.ResponseWriter, r *http.Request) {
	c := a.Config.Candidate()
	switch r.Method {
	case "GET":
		writeJSON(w, 200, map[string]any{"success": true, "data": c.Policies})
	case "PUT", "POST":
		var items []domain.SecurityPolicy
		if err := decode(r, &items); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		c.Policies = items
		errs := a.Config.SetCandidate(c)
		if len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_POLICY", "message": "policy rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "policies", "candidate", "SUCCESS", strconv.Itoa(len(items))+" policies")
		writeJSON(w, 200, map[string]any{"success": true, "data": items})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}
func (a *API) policyByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	if id == "" {
		writeError(w, 404, "NOT_FOUND", "policy id required")
		return
	}
	c := a.Config.Candidate()
	if r.Method == http.MethodGet {
		for _, p := range c.Policies {
			if p.ID == id {
				writeJSON(w, 200, map[string]any{"success": true, "data": p})
				return
			}
		}
		writeError(w, 404, "NOT_FOUND", "policy not found")
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET, PUT or DELETE required")
		return
	}
	if r.Method == http.MethodDelete {
		for i, p := range c.Policies {
			if p.ID == id {
				c.Policies = append(c.Policies[:i], c.Policies[i+1:]...)
				break
			}
		}
	} else {
		var p domain.SecurityPolicy
		if err := decode(r, &p); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		p.ID = id
		replaced := false
		for i, x := range c.Policies {
			if x.ID == id {
				c.Policies[i] = p
				replaced = true
			}
		}
		if !replaced {
			c.Policies = append(c.Policies, p)
		}
	}
	if errs := a.Config.SetCandidate(c); len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_POLICY", "message": "policy rejected", "details": errs}})
		return
	}
	a.auditAction(r, strings.ToUpper(r.Method), "policy", id, "SUCCESS", "candidate updated")
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]string{"id": id, "state": "candidate"}})
}

func (a *API) interfaces(w http.ResponseWriter, r *http.Request) {
	c := a.Config.Candidate()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "data": c.Interfaces})
	case http.MethodPut, http.MethodPost:
		var v []domain.Interface
		if err := decode(r, &v); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		c.Interfaces = v
		if errs := a.Config.SetCandidate(c); len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "interfaces rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "interfaces", "candidate", "SUCCESS", strconv.Itoa(len(v))+" interfaces")
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}
func (a *API) zones(w http.ResponseWriter, r *http.Request) {
	c := a.Config.Candidate()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "data": c.Zones})
	case http.MethodPut, http.MethodPost:
		var v []domain.Zone
		if err := decode(r, &v); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		c.Zones = v
		if errs := a.Config.SetCandidate(c); len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "zones rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "zones", "candidate", "SUCCESS", strconv.Itoa(len(v))+" zones")
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}
func (a *API) routes(w http.ResponseWriter, r *http.Request) {
	c := a.Config.Candidate()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "data": c.Routes})
	case http.MethodPut, http.MethodPost:
		var v []domain.Route
		if err := decode(r, &v); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		c.Routes = v
		if errs := a.Config.SetCandidate(c); len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "routes rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "routes", "candidate", "SUCCESS", strconv.Itoa(len(v))+" routes")
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}
func (a *API) natRules(w http.ResponseWriter, r *http.Request) {
	c := a.Config.Candidate()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "data": c.NATRules})
	case http.MethodPut, http.MethodPost:
		var v []domain.NATRule
		if err := decode(r, &v); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		c.NATRules = v
		if errs := a.Config.SetCandidate(c); len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "NAT rules rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "nat_rules", "candidate", "SUCCESS", strconv.Itoa(len(v))+" rules")
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}
func (a *API) profiles(w http.ResponseWriter, r *http.Request) {
	c := a.Config.Candidate()
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "data": c.Profiles})
	case http.MethodPut, http.MethodPost:
		var v []domain.SecurityProfile
		if err := decode(r, &v); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		c.Profiles = v
		if errs := a.Config.SetCandidate(c); len(errs) > 0 {
			writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "profiles rejected", "details": errs}})
			return
		}
		a.auditAction(r, "UPDATE", "security_profiles", "candidate", "SUCCESS", strconv.Itoa(len(v))+" profiles")
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET or PUT required")
	}
}

func (a *API) objectByID(w http.ResponseWriter, r *http.Request, kind string) {
	prefixes := map[string]string{"interface": "/api/v1/interfaces/", "zone": "/api/v1/zones/", "route": "/api/v1/routes/", "nat": "/api/v1/nat/rules/", "profile": "/api/v1/security-profiles/"}
	id := strings.TrimPrefix(r.URL.Path, prefixes[kind])
	if id == "" {
		writeError(w, 404, "NOT_FOUND", "object id required")
		return
	}
	c := a.Config.Candidate()
	if r.Method == http.MethodGet {
		var value any
		switch kind {
		case "interface":
			for _, v := range c.Interfaces {
				if v.ID == id {
					value = v
				}
			}
		case "zone":
			for _, v := range c.Zones {
				if v.ID == id {
					value = v
				}
			}
		case "route":
			for _, v := range c.Routes {
				if v.ID == id {
					value = v
				}
			}
		case "nat":
			for _, v := range c.NATRules {
				if v.ID == id {
					value = v
				}
			}
		case "profile":
			for _, v := range c.Profiles {
				if v.ID == id {
					value = v
				}
			}
		}
		if value == nil {
			writeError(w, 404, "NOT_FOUND", "object not found")
			return
		}
		writeJSON(w, 200, map[string]any{"success": true, "data": value})
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodDelete {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET, PUT or DELETE required")
		return
	}
	if r.Method == http.MethodDelete {
		switch kind {
		case "interface":
			c.Interfaces = removeInterface(c.Interfaces, id)
		case "zone":
			c.Zones = removeZone(c.Zones, id)
		case "route":
			c.Routes = removeRoute(c.Routes, id)
		case "nat":
			c.NATRules = removeNAT(c.NATRules, id)
		case "profile":
			c.Profiles = removeProfile(c.Profiles, id)
		}
	} else {
		switch kind {
		case "interface":
			var v domain.Interface
			if err := decode(r, &v); err != nil {
				writeError(w, 400, "INVALID_JSON", err.Error())
				return
			}
			v.ID = id
			c.Interfaces = replaceInterface(c.Interfaces, v)
		case "zone":
			var v domain.Zone
			if err := decode(r, &v); err != nil {
				writeError(w, 400, "INVALID_JSON", err.Error())
				return
			}
			v.ID = id
			c.Zones = replaceZone(c.Zones, v)
		case "route":
			var v domain.Route
			if err := decode(r, &v); err != nil {
				writeError(w, 400, "INVALID_JSON", err.Error())
				return
			}
			v.ID = id
			c.Routes = replaceRoute(c.Routes, v)
		case "nat":
			var v domain.NATRule
			if err := decode(r, &v); err != nil {
				writeError(w, 400, "INVALID_JSON", err.Error())
				return
			}
			v.ID = id
			c.NATRules = replaceNAT(c.NATRules, v)
		case "profile":
			var v domain.SecurityProfile
			if err := decode(r, &v); err != nil {
				writeError(w, 400, "INVALID_JSON", err.Error())
				return
			}
			v.ID = id
			c.Profiles = replaceProfile(c.Profiles, v)
		}
	}
	if errs := a.Config.SetCandidate(c); len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "object rejected", "details": errs}})
		return
	}
	a.auditAction(r, strings.ToUpper(r.Method), kind, id, "SUCCESS", "candidate updated")
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]string{"id": id, "state": "candidate"}})
}
func removeInterface(v []domain.Interface, id string) []domain.Interface {
	for i, x := range v {
		if x.ID == id {
			return append(v[:i], v[i+1:]...)
		}
	}
	return v
}
func removeZone(v []domain.Zone, id string) []domain.Zone {
	for i, x := range v {
		if x.ID == id {
			return append(v[:i], v[i+1:]...)
		}
	}
	return v
}
func removeRoute(v []domain.Route, id string) []domain.Route {
	for i, x := range v {
		if x.ID == id {
			return append(v[:i], v[i+1:]...)
		}
	}
	return v
}
func removeNAT(v []domain.NATRule, id string) []domain.NATRule {
	for i, x := range v {
		if x.ID == id {
			return append(v[:i], v[i+1:]...)
		}
	}
	return v
}
func removeProfile(v []domain.SecurityProfile, id string) []domain.SecurityProfile {
	for i, x := range v {
		if x.ID == id {
			return append(v[:i], v[i+1:]...)
		}
	}
	return v
}
func replaceInterface(v []domain.Interface, x domain.Interface) []domain.Interface {
	for i, y := range v {
		if y.ID == x.ID {
			v[i] = x
			return v
		}
	}
	return append(v, x)
}
func replaceZone(v []domain.Zone, x domain.Zone) []domain.Zone {
	for i, y := range v {
		if y.ID == x.ID {
			v[i] = x
			return v
		}
	}
	return append(v, x)
}
func replaceRoute(v []domain.Route, x domain.Route) []domain.Route {
	for i, y := range v {
		if y.ID == x.ID {
			v[i] = x
			return v
		}
	}
	return append(v, x)
}
func replaceNAT(v []domain.NATRule, x domain.NATRule) []domain.NATRule {
	for i, y := range v {
		if y.ID == x.ID {
			v[i] = x
			return v
		}
	}
	return append(v, x)
}
func replaceProfile(v []domain.SecurityProfile, x domain.SecurityProfile) []domain.SecurityProfile {
	for i, y := range v {
		if y.ID == x.ID {
			v[i] = x
			return v
		}
	}
	return append(v, x)
}
func (a *API) validate(w http.ResponseWriter, _ *http.Request) {
	errs := a.Config.ValidateCandidate()
	if len(errs) > 0 {
		writeJSON(w, 400, map[string]any{"success": false, "error": map[string]any{"code": "INVALID_CONFIG", "message": "candidate invalid", "details": errs}})
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"valid": true}})
}
func (a *API) commit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	var req struct {
		ExpectedVersion uint64 `json:"expected_version"`
		Author          string `json:"author"`
		Comment         string `json:"comment"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, 400, "INVALID_JSON", err.Error())
		return
	}
	if req.Author == "" {
		req.Author = "api"
	}
	var v domain.ConfigVersion
	var err error
	if a.Runtime != nil {
		candidate := a.Config.Candidate()
		operationID := "commit-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		v, err = a.Runtime.CommitConfig(r.Context(), candidate, req.ExpectedVersion, req.Author, req.Comment, operationID)
		if err != nil {
			a.auditAction(r, "COMMIT", "config", strconv.FormatUint(req.ExpectedVersion, 10), "FAILED", err.Error())
			writeError(w, 409, "COMMIT_FAILED", err.Error())
			return
		}
		a.Config.SyncRunning(candidate, v)
		a.auditAction(r, "COMMIT", "config", strconv.FormatUint(v.Version, 10), "SUCCESS", req.Comment)
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
		return
	}
	if a.ApplyConfig == nil {
		a.auditAction(r, "COMMIT", "config", strconv.FormatUint(req.ExpectedVersion, 10), "FAILED", "privileged engine command interface unavailable")
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", "privileged engine command interface unavailable")
		return
	}
	v, err = a.Config.CommitWithApply(r.Context(), req.Author, req.Comment, req.ExpectedVersion, a.ApplyConfig)
	if err != nil {
		a.auditAction(r, "COMMIT", "config", strconv.FormatUint(req.ExpectedVersion, 10), "FAILED", err.Error())
		writeError(w, 409, "COMMIT_FAILED", err.Error())
		return
	}
	a.auditAction(r, "COMMIT", "config", strconv.FormatUint(v.Version, 10), "SUCCESS", req.Comment)
	writeJSON(w, 200, map[string]any{"success": true, "data": v})
}
func (a *API) rollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "POST required")
		return
	}
	var v domain.ConfigVersion
	var err error
	if a.Runtime != nil {
		operationID := "rollback-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		v, err = a.Runtime.RollbackConfig(r.Context(), "api", "rollback", operationID)
		if err != nil {
			a.auditAction(r, "ROLLBACK", "config", "", "FAILED", err.Error())
			writeError(w, 409, "ROLLBACK_FAILED", err.Error())
			return
		}
		if running, _, syncErr := a.Runtime.GetRunningConfig(r.Context()); syncErr == nil {
			// Rollback response carries the new version; the engine response is
			// authoritative for the configuration payload.
			a.Config.SyncRunning(running, v)
		}
		a.auditAction(r, "ROLLBACK", "config", strconv.FormatUint(v.Version, 10), "SUCCESS", "restored previous configuration")
		writeJSON(w, 200, map[string]any{"success": true, "data": v})
		return
	}
	if a.ApplyConfig == nil {
		a.auditAction(r, "ROLLBACK", "config", "", "FAILED", "privileged engine command interface unavailable")
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", "privileged engine command interface unavailable")
		return
	}
	v, err = a.Config.RollbackWithApply(r.Context(), "api", "rollback", a.ApplyConfig)
	if err != nil {
		a.auditAction(r, "ROLLBACK", "config", "", "FAILED", err.Error())
		writeError(w, 409, "ROLLBACK_FAILED", err.Error())
		return
	}
	a.auditAction(r, "ROLLBACK", "config", strconv.FormatUint(v.Version, 10), "SUCCESS", "restored previous configuration")
	writeJSON(w, 200, map[string]any{"success": true, "data": v})
}
func (a *API) sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	if a.Runtime != nil {
		query, err := parseSessionQuery(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_FILTER", err.Error())
			return
		}
		result, err := a.Runtime.ListSessions(r.Context(), query)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": result})
		return
	}
	items := a.Engine.ListSessions()
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"items": items, "page": 1, "page_size": len(items), "total": len(items)}})
}
func (a *API) sessionByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/sessions/")
	if id == "" {
		writeError(w, 404, "NOT_FOUND", "session id required")
		return
	}
	if a.Runtime != nil {
		if r.Method == http.MethodDelete {
			if err := a.Runtime.RevokeSession(r.Context(), id, "manual session revoke"); err != nil {
				writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
				return
			}
			a.auditAction(r, "REVOKE", "session", id, "SUCCESS", "runtime revoke guard installed")
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"session_id": id, "revoked": true, "enforcement": "DROP", "tcp_reset_sent": false}})
			return
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET or DELETE required")
			return
		}
		value, err := a.Runtime.GetSession(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"session": value, "security_context": nil}})
		return
	}
	if r.Method == "DELETE" {
		if err := a.Engine.Sessions.Delete(id); err != nil {
			a.auditAction(r, "TERMINATE", "session", id, "FAILED", err.Error())
			writeError(w, 404, "NOT_FOUND", err.Error())
			return
		}
		a.auditAction(r, "TERMINATE", "session", id, "SUCCESS", "session removed from engine")
		writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"terminated": id}})
		return
	}
	s, c, ok := a.Engine.GetSession(id)
	if !ok {
		writeError(w, 404, "NOT_FOUND", "session not found")
		return
	}
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"session": s, "security_context": c}})
}

func parseSessionQuery(r *http.Request) (domain.SessionQuery, error) {
	query := r.URL.Query()
	result := domain.SessionQuery{SourceIP: query.Get("source_ip"), DestinationIP: query.Get("destination_ip"), SourceZone: query.Get("source_zone"), DestinationZone: query.Get("destination_zone"), TupleView: query.Get("tuple_view")}
	if raw := query.Get("protocol"); raw != "" {
		protocol, ok := domain.ParseProtocol(raw)
		if !ok {
			return result, fmt.Errorf("invalid protocol %q", raw)
		}
		result.Protocol = protocol
	}
	if raw := query.Get("state"); raw != "" {
		result.State = domain.SessionState(strings.ToUpper(raw))
		switch result.State {
		case domain.SessionNew, domain.SessionEstablished, domain.SessionClosing, domain.SessionClosed:
		default:
			return result, fmt.Errorf("invalid state %q", raw)
		}
	}
	if raw := query.Get("decision"); raw != "" {
		result.Decision = domain.Decision(strings.ToUpper(raw))
		if !result.Decision.Valid() {
			return result, fmt.Errorf("invalid decision %q", raw)
		}
	}
	if result.TupleView != "" && result.TupleView != "original" && result.TupleView != "translated" && result.TupleView != "any" {
		return result, fmt.Errorf("invalid tuple_view %q", result.TupleView)
	}
	if raw := query.Get("page"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return result, errors.New("page must be at least 1")
		}
		result.Page = value
	}
	if raw := query.Get("page_size"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 500 {
			return result, errors.New("page_size must be between 1 and 500")
		}
		result.PageSize = value
	}
	return result, nil
}
func (a *API) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	if a.Runtime != nil {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		limit := 200
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 500 {
				limit = parsed
			}
		}
		page, err := a.Runtime.ReadRuntimeEvents(r.Context(), after, limit)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": page})
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"items": a.events, "total": len(a.events)}})
}
func (a *API) eventByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/events/")
	if id == "" || r.Method != http.MethodGet {
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET /events/{id} required")
		return
	}
	if a.Runtime != nil {
		sequence, parseErr := strconv.ParseUint(id, 10, 64)
		if parseErr != nil || sequence == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_EVENT_ID", "runtime event id must be a sequence number")
			return
		}
		page, err := a.Runtime.ReadRuntimeEvents(r.Context(), sequence-1, 1)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", err.Error())
			return
		}
		if len(page.Items) == 1 && page.Items[0].Sequence == sequence {
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": page.Items[0]})
			return
		}
		writeError(w, http.StatusNotFound, "NOT_FOUND", "runtime event not found or evicted")
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, ev := range a.events {
		if ev.EventID == id {
			writeJSON(w, 200, map[string]any{"success": true, "data": ev})
			return
		}
	}
	writeError(w, 404, "NOT_FOUND", "event not found")
}
func (a *API) auditHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	limit := 250
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	a.mu.RLock()
	count := len(a.audit)
	if limit > count {
		limit = count
	}
	items := make([]domain.AuditEntry, 0, limit)
	for i := count - 1; i >= count-limit; i-- {
		items = append(items, a.audit[i])
	}
	a.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"items": items, "total": count}})
}
func (a *API) blocksHandler(w http.ResponseWriter, r *http.Request) {
	if a.Runtime != nil {
		switch r.Method {
		case http.MethodGet:
			items, err := a.Runtime.ListTemporaryBlocks(r.Context())
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": items})
		case http.MethodPost:
			var block domain.TemporaryBlock
			if err := decode(r, &block); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_JSON", err.Error())
				return
			}
			if block.ID == "" {
				block.ID = "block-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			}
			if block.CreatedAt.IsZero() {
				block.CreatedAt = time.Now().UTC()
			}
			if block.ExpiresAt.IsZero() {
				block.ExpiresAt = block.CreatedAt.Add(5 * time.Minute)
			}
			if err := a.Runtime.AddTemporaryBlock(r.Context(), block); err != nil {
				writeError(w, http.StatusServiceUnavailable, "ENFORCEMENT_FAILED", err.Error())
				return
			}
			a.auditAction(r, "CREATE", "temporary_block", block.ID, "SUCCESS", block.Indicator)
			writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": block})
		case http.MethodDelete:
			indicator := r.URL.Query().Get("indicator")
			if indicator == "" {
				writeError(w, http.StatusBadRequest, "INVALID_BLOCK", "indicator required")
				return
			}
			if err := a.Runtime.RemoveTemporaryBlock(r.Context(), indicator); err != nil {
				writeError(w, http.StatusServiceUnavailable, "ENFORCEMENT_FAILED", err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]string{"deleted": indicator}})
		default:
			writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET, POST or DELETE required")
		}
		return
	}
	switch r.Method {
	case "GET":
		a.mu.RLock()
		out := make([]domain.TemporaryBlock, 0, len(a.blocks))
		for _, b := range a.blocks {
			if b.ExpiresAt.After(time.Now()) {
				out = append(out, b)
			}
		}
		a.mu.RUnlock()
		writeJSON(w, 200, map[string]any{"success": true, "data": out})
	case "POST":
		var b domain.TemporaryBlock
		if err := decode(r, &b); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		if b.ID == "" {
			b.ID = "block-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		}
		if b.CreatedAt.IsZero() {
			b.CreatedAt = time.Now()
		}
		if b.ExpiresAt.IsZero() {
			b.ExpiresAt = time.Now().Add(5 * time.Minute)
		}
		a.mu.Lock()
		a.blocks[b.ID] = b
		a.mu.Unlock()
		if err := a.Engine.AddTemporaryBlock(r.Context(), b); err != nil {
			a.mu.Lock()
			delete(a.blocks, b.ID)
			a.mu.Unlock()
			a.auditAction(r, "CREATE", "temporary_block", b.ID, "FAILED", err.Error())
			writeError(w, 503, "ENFORCEMENT_FAILED", err.Error())
			return
		}
		a.auditAction(r, "CREATE", "temporary_block", b.ID, "SUCCESS", b.Indicator)
		writeJSON(w, 201, map[string]any{"success": true, "data": b})
	case "DELETE":
		id := strings.TrimPrefix(r.URL.Query().Get("id"), "/")
		a.mu.Lock()
		block := a.blocks[id]
		delete(a.blocks, id)
		a.mu.Unlock()
		if block.Indicator != "" {
			a.Engine.RemoveTemporaryBlock(block.Indicator)
		}
		a.auditAction(r, "DELETE", "temporary_block", id, "SUCCESS", "")
		writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"deleted": id}})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET, POST or DELETE required")
	}
}
func (a *API) blockByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/blocks/")
	if id == "" || r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "DELETE /blocks/{id} required")
		return
	}
	if a.Runtime != nil {
		if err := a.Runtime.RemoveTemporaryBlock(r.Context(), id); err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]string{"deleted": id}})
		return
	}
	a.mu.Lock()
	block, exists := a.blocks[id]
	delete(a.blocks, id)
	a.mu.Unlock()
	if exists {
		a.Engine.RemoveTemporaryBlock(block.Indicator)
	}
	if !exists {
		a.auditAction(r, "DELETE", "temporary_block", id, "FAILED", "block not found")
		writeError(w, http.StatusNotFound, "NOT_FOUND", "block not found")
		return
	}
	a.auditAction(r, "DELETE", "temporary_block", id, "SUCCESS", "")
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]string{"deleted": id}})
}
func (a *API) statsSnapshot() map[string]any {
	if a.Runtime != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		stats, err := a.Runtime.SessionStats(ctx)
		if err != nil {
			return map[string]any{"status": "unavailable", "error": err.Error(), "timestamp": time.Now().UTC()}
		}
		return map[string]any{"active_sessions": stats.ActiveSessions, "created": stats.Created, "closed": stats.Closed, "invalidated": stats.Invalidated, "tracking_drops": stats.TrackingDrops, "capacity_drops": stats.CapacityDrops, "event_queue_dropped": stats.EventDrops, "resyncs": stats.Resyncs, "timestamp": time.Now().UTC()}
	}
	sessions := a.Engine.ListSessions()
	apps := map[string]int{}
	blocked := 0
	for _, s := range sessions {
		apps[s.Application]++
		if s.Decision != domain.DecisionAllow {
			blocked++
		}
	}
	return map[string]any{"active_sessions": len(sessions), "event_queue_dropped": a.Engine.Events.Dropped(), "applications": apps, "blocked_sessions": blocked, "timestamp": time.Now().UTC()}
}
func (a *API) stats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"success": true, "data": a.statsSnapshot()})
}
func (a *API) mlStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"success": true, "data": map[string]any{"status": "external", "configured": os.Getenv("NGFW_ML_URL") != ""}})
}
func (a *API) reputation(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"success": true, "data": a.Reputation.List()})
	case http.MethodPost:
		var entry domain.ReputationEntry
		if err := decode(r, &entry); err != nil {
			writeError(w, 400, "INVALID_JSON", err.Error())
			return
		}
		if entry.Indicator == "" || entry.ReputationScore < 0 || entry.ReputationScore > 100 {
			writeError(w, 400, "INVALID_REPUTATION", "indicator and score 0..100 required")
			return
		}
		if !a.Reputation.Upsert(entry) {
			writeError(w, 507, "REPUTATION_CAPACITY", "reputation store is full")
			return
		}
		a.auditAction(r, "UPSERT", "reputation", entry.Indicator, "SUCCESS", strconv.Itoa(entry.ReputationScore))
		writeJSON(w, 201, map[string]any{"success": true, "data": entry})
	case http.MethodDelete:
		indicator := r.URL.Query().Get("indicator")
		if indicator == "" {
			writeError(w, 400, "INVALID_REPUTATION", "indicator required")
			return
		}
		a.Reputation.Delete(indicator)
		a.auditAction(r, "DELETE", "reputation", indicator, "SUCCESS", "")
		writeJSON(w, 200, map[string]any{"success": true, "data": map[string]string{"deleted": indicator}})
	default:
		writeError(w, 405, "METHOD_NOT_ALLOWED", "GET, POST or DELETE required")
	}
}

func (a *API) RecordEvent(ev domain.SecurityEvent) {
	a.mu.Lock()
	a.events = append(a.events, ev)
	if len(a.events) > 10000 {
		a.events = a.events[len(a.events)-10000:]
	}
	a.mu.Unlock()
}
func (a *API) auditAction(r *http.Request, action, resource, resourceID, result, message string) {
	actor, role := a.auditIdentity(r)
	a.recordAudit(domain.AuditEntry{ID: "audit-" + strconv.FormatInt(time.Now().UnixNano(), 10), Timestamp: time.Now().UTC(), Actor: actor, Role: role, Action: action, Resource: resource, ResourceID: resourceID, Result: result, Message: message})
}
func (a *API) auditIdentity(r *http.Request) (string, string) {
	actor, role := "unknown", ""
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if a.Token != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(a.Token)) == 1 {
		actor, role = "api-token", "TOKEN"
	} else if a.Auth != nil {
		if user, ok := a.Auth.Validate(provided); ok {
			actor, role = user.Username, string(user.Role)
		}
	}
	return actor, role
}
func (a *API) recordAudit(entry domain.AuditEntry) {
	a.mu.Lock()
	a.audit = append(a.audit, entry)
	if len(a.audit) > 10000 {
		a.audit = a.audit[len(a.audit)-10000:]
	}
	a.mu.Unlock()
}
func (a *API) wsEvents(conn *websocket.Conn) {
	if a.Runtime != nil {
		var cursor uint64
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			page, err := a.Runtime.ReadRuntimeEvents(ctx, cursor, 200)
			cancel()
			if err != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_ = websocket.JSON.Send(conn, map[string]any{"success": false, "error": map[string]string{"code": "ENGINE_UNAVAILABLE", "message": err.Error()}})
				return
			}
			for _, event := range page.Items {
				cursor = event.Sequence
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := websocket.JSON.Send(conn, map[string]any{"success": true, "data": event}); err != nil {
					return
				}
			}
			<-ticker.C
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for event := range a.Engine.Events.Subscribe(ctx) {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Send(conn, map[string]any{"success": true, "data": event}); err != nil {
			return
		}
	}
}
func (a *API) wsStats(conn *websocket.Conn) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Send(conn, map[string]any{"success": true, "data": a.statsSnapshot()}); err != nil {
			return
		}
		<-ticker.C
	}
}
func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"success": false, "error": map[string]string{"code": code, "message": message}})
}
func logging(next http.Handler, l *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		l.Debug("http request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start).String())
	})
}
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				writeError(w, 500, "INTERNAL_ERROR", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
