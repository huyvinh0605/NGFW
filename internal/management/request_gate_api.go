package management

import (
	"context"
	"net/http"
	"strconv"

	"github.com/kltngfw/ngfw/internal/domain"
)

type requestGateRuntimeClient interface {
	RequestGateHealth(context.Context) (domain.RequestGateHealth, error)
	RequestGateCapabilities(context.Context) (domain.RequestGateCapabilities, error)
	ListRequestGateEvidence(context.Context, uint64, int) (domain.RequestGateEvidencePage, error)
}

func (a *API) gateClient() (requestGateRuntimeClient, bool) {
	if a == nil || a.Runtime == nil {
		return nil, false
	}
	client, ok := a.Runtime.(requestGateRuntimeClient)
	return client, ok
}

func (a *API) requestGateHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	client, ok := a.gateClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", "engine request-gate runtime unavailable")
		return
	}
	health, err := client.RequestGateHealth(r.Context())
	if err != nil {
		writeInspectionReadError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": health})
}

func (a *API) requestGateCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	client, ok := a.gateClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", "engine request-gate runtime unavailable")
		return
	}
	capabilities, err := client.RequestGateCapabilities(r.Context())
	if err != nil {
		writeInspectionReadError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": capabilities})
}

func (a *API) requestGateEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	client, ok := a.gateClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", "engine request-gate runtime unavailable")
		return
	}
	if len(r.URL.Query()) > 2 {
		writeError(w, http.StatusBadRequest, "INVALID_FILTER", "only after_sequence and limit are supported")
		return
	}
	query := r.URL.Query()
	for key, values := range query {
		if (key != "after_sequence" && key != "limit") || len(values) != 1 {
			writeError(w, http.StatusBadRequest, "INVALID_FILTER", "invalid request-gate evidence filter")
			return
		}
	}
	after := uint64(0)
	if raw := query.Get("after_sequence"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_FILTER", "after_sequence must be unsigned")
			return
		}
		after = value
	}
	limit := 50
	if raw := query.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 128 {
			writeError(w, http.StatusBadRequest, "INVALID_FILTER", "limit must be 1..128")
			return
		}
		limit = value
	}
	page, err := client.ListRequestGateEvidence(r.Context(), after, limit)
	if err != nil {
		writeInspectionReadError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": page})
}
