package management

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/engineipc"
)

// The peer writes the engine's wire JSON independently of the API's DTO. Using
// a typed fake here would hide a missing field on both sides of the test.
func TestRequestGateForwardSurvivesRuntimeIPCAndHTTPAPI(t *testing.T) {
	for _, tc := range []struct {
		name    string
		forward string
	}{
		{"legacy_without_forward", ""},
		{"response_received", `{"http_status":200,"reason_code":"UPSTREAM_RESPONSE_RECEIVED","observed_at":"2026-10-30T08:44:41.364771255Z"}`},
		{"upstream_verification_failed", `{"http_status":502,"reason_code":"TLS_UPSTREAM_VERIFY_FAILED","observed_at":"2026-10-30T08:44:41.364771255Z"}`},
		{"upstream_mtls_unsupported", `{"http_status":502,"reason_code":"TLS_UPSTREAM_MTLS_UNSUPPORTED","client_certificate_requested":true,"observed_at":"2026-10-30T08:44:41.364771255Z"}`},
		{"truncated_response", `{"http_status":200,"reason_code":"UPSTREAM_RESPONSE_TRUNCATED","observed_at":"2026-10-30T08:44:41.364771255Z"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "m4wire-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			socket := filepath.Join(dir, "e.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			if err := listener.(*net.UnixListener).SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			item := `{"event_id":"event-9","sequence":9,"context":{"request_id":"request-9"},"decision":{"verdict":"ALLOW","coverage":"COMPLETE","reason_code":"GATE_INSPECTION_COMPLETE"}`
			if tc.forward != "" {
				item += `,"forward":` + tc.forward
			}
			item += `}`
			page := json.RawMessage(`{"items":[` + item + `],"next_sequence":9,"has_more":false}`)
			done := make(chan error, 1)
			go func() {
				connection, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				var request struct {
					Version   uint16 `json:"version"`
					RequestID string `json:"request_id"`
					Operation string `json:"operation"`
					Payload   struct {
						After uint64 `json:"after"`
						Limit int    `json:"limit"`
					} `json:"payload"`
				}
				if err := json.NewDecoder(connection).Decode(&request); err != nil {
					done <- err
					return
				}
				if request.Operation != "list_request_gate_evidence" || request.Payload.After != 8 || request.Payload.Limit != 1 {
					done <- fmt.Errorf("unexpected request: %+v", request)
					return
				}
				done <- json.NewEncoder(connection).Encode(map[string]any{
					"version": request.Version, "request_id": request.RequestID,
					"ok": true, "data": page,
				})
			}()

			a := newRuntimeAPIForTest(t, &runtimeAPIFake{})
			a.Runtime = engineipc.NewRuntimeClient(socket)
			a.Token = "m4-forward-contract-token"
			handler := a.Handler()
			unauthorized := httptest.NewRecorder()
			handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/request-gate/evidence", nil))
			if unauthorized.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized evidence status=%d", unauthorized.Code)
			}
			request := httptest.NewRequest(http.MethodGet, "/api/v1/request-gate/evidence?after_sequence=8&limit=1", nil)
			request.Header.Set("Authorization", "Bearer "+a.Token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("engine fixture did not complete")
			}
			var envelope struct {
				Success bool `json:"success"`
				Data    struct {
					Items []map[string]json.RawMessage `json:"items"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if !envelope.Success || len(envelope.Data.Items) != 1 {
				t.Fatalf("invalid API envelope: %s", response.Body.String())
			}
			actual, present := envelope.Data.Items[0]["forward"]
			if tc.forward == "" {
				if present {
					t.Fatalf("API invented forward result from inspection ALLOW: %s", actual)
				}
				return
			}
			if !present {
				t.Fatalf("API lost engine forward result: %s", response.Body.String())
			}
			var want, got any
			if err := json.Unmarshal([]byte(tc.forward), &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(actual, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("forward result changed: want=%s got=%s", tc.forward, actual)
			}
		})
	}
}
