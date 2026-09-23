package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

func (a *API) inspectionClient() (InspectionRuntimeClient, bool) {
	if a == nil || a.Runtime == nil {
		return nil, false
	}
	client, ok := a.Runtime.(InspectionRuntimeClient)
	return client, ok
}

func (a *API) inspectionHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	client, ok := a.inspectionClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "INSPECTION_UNAVAILABLE", "engine does not expose inspection runtime")
		return
	}
	value, err := client.InspectionHealth(r.Context())
	if err != nil {
		writeInspectionReadError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": value})
}
func (a *API) inspectionCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	client, ok := a.inspectionClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "INSPECTION_UNAVAILABLE", "engine does not expose inspection capabilities")
		return
	}
	value, err := client.InspectionCapabilities(r.Context())
	if err != nil {
		writeInspectionReadError(w, err, false)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": value})
}

func (a *API) securityEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	client, ok := a.inspectionClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "INSPECTION_UNAVAILABLE", "engine does not expose security events")
		return
	}
	query, err := parseSecurityQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_FILTER", err.Error())
		return
	}
	page, err := client.ListSecurityEvents(r.Context(), query)
	if err != nil {
		writeInspectionReadError(w, err, false)
		return
	}
	page, err = fitSecurityPage(page, query, 1<<20)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "RESPONSE_TOO_LARGE", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": page})
}
func (a *API) securityEventByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/security/events/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "INVALID_EVENT_ID", "event id required")
		return
	}
	client, ok := a.inspectionClient()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "INSPECTION_UNAVAILABLE", "engine does not expose security events")
		return
	}
	value, err := client.GetSecurityEvent(r.Context(), id)
	if err != nil {
		writeInspectionReadError(w, err, true)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": value})
}

func parseSecurityQuery(r *http.Request) (domain.SecurityQuery, error) {
	values := r.URL.Query()
	result := domain.SecurityQuery{SessionID: values.Get("session_id"), SensorID: values.Get("sensor_id"), Application: values.Get("application"), StreamID: values.Get("stream_id")}
	if result.SensorID != "" && result.SensorID != "ids" && result.SensorID != "ips" {
		return result, &filterError{"sensor_id must be ids or ips"}
	}
	if len(result.Application) > 128 || len(result.SessionID) > 256 || len(result.StreamID) > 256 {
		return result, &filterError{"filter value is too long"}
	}
	if raw := values.Get("mode"); raw != "" {
		result.Mode = domain.InspectionMode(strings.ToUpper(raw))
		if !result.Mode.Valid() || result.Mode == domain.InspectionModeOff {
			return result, &filterError{"invalid mode"}
		}
	}
	if raw := values.Get("severity"); raw != "" {
		result.Severity = domain.Severity(strings.ToUpper(raw))
		switch result.Severity {
		case domain.SeverityUnknown, domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh:
		default:
			return result, &filterError{"invalid severity"}
		}
	}
	if raw := values.Get("verdict"); raw != "" {
		result.Verdict = domain.LatestVerdict(strings.ToUpper(raw))
		if !result.Verdict.Valid() {
			return result, &filterError{"invalid verdict"}
		}
	}
	if raw := values.Get("correlation_state"); raw != "" {
		result.Correlation = domain.CorrelationState(strings.ToUpper(raw))
		if !result.Correlation.Valid() {
			return result, &filterError{"invalid correlation_state"}
		}
	}
	afterRaw := values.Get("after_sequence")
	if afterRaw == "" {
		afterRaw = values.Get("after")
	}
	if rawCursor := values.Get("cursor"); rawCursor != "" {
		if afterRaw != "" || result.StreamID != "" {
			return result, &filterError{"cursor cannot be combined with after_sequence or stream_id"}
		}
		separator := strings.LastIndexByte(rawCursor, ':')
		if separator < 1 || separator == len(rawCursor)-1 {
			return result, &filterError{"cursor must be <stream_id>:<sequence>"}
		}
		result.StreamID = rawCursor[:separator]
		afterRaw = rawCursor[separator+1:]
	}
	if afterRaw != "" {
		value, err := strconv.ParseUint(afterRaw, 10, 64)
		if err != nil {
			return result, &filterError{"after_sequence must be an unsigned sequence"}
		}
		result.AfterSequence = value
	}
	if raw := values.Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			return result, &filterError{"limit must be between 1 and 200"}
		}
		result.Limit = value
	}
	return result, nil
}

type codedRuntimeError interface{ ErrorCode() string }

func writeInspectionReadError(w http.ResponseWriter, err error, allowNotFound bool) {
	var coded codedRuntimeError
	code := ""
	if errors.As(err, &coded) {
		code = coded.ErrorCode()
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded) || code == "DEADLINE_EXCEEDED":
		writeError(w, http.StatusGatewayTimeout, "ENGINE_TIMEOUT", err.Error())
	case allowNotFound && (errors.Is(err, domain.ErrSecurityEventNotFound) || code == "NOT_FOUND"):
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
	default:
		writeError(w, http.StatusServiceUnavailable, "ENGINE_UNAVAILABLE", err.Error())
	}
}

func fitSecurityPage(page domain.SecurityEventPage, query domain.SecurityQuery, maxBytes int) (domain.SecurityEventPage, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	for {
		envelope := struct {
			Success bool                     `json:"success"`
			Data    domain.SecurityEventPage `json:"data"`
		}{Success: true, Data: page}
		encoded, err := json.Marshal(envelope)
		if err != nil {
			return domain.SecurityEventPage{}, err
		}
		if len(encoded)+1 <= maxBytes {
			return page, nil
		}
		if len(page.Items) <= 1 {
			return domain.SecurityEventPage{}, errors.New("one security event exceeds the 1 MiB HTTP response limit")
		}
		page.Items = page.Items[:len(page.Items)-1]
		page.HasMore = true
		page.NextSequence = page.Items[len(page.Items)-1].Sequence
		if page.NextSequence < query.AfterSequence {
			page.NextSequence = query.AfterSequence
		}
		page.NextCursor = page.StreamID + ":" + strconv.FormatUint(page.NextSequence, 10)
	}
}

type filterError struct{ message string }

func (e *filterError) Error() string { return e.message }
