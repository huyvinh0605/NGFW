package management

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/auth"
	"golang.org/x/net/websocket"
)

func TestInspectionReadsRequireAuthenticatedViewer(t *testing.T) {
	api := newRuntimeAPIForTest(t, &runtimeAPIFake{})
	api.Token = "master-token"
	api.Auth = auth.NewStore(time.Minute)
	tokens := map[string]string{"anonymous": "", "invalid": "bad-token", "master": api.Token}
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin} {
		name := strings.ToLower(string(role))
		if err := api.Auth.AddUser(name, name, "temporary test password", role); err != nil {
			t.Fatal(err)
		}
		token, _, err := api.Auth.Login(name, "temporary test password")
		if err != nil {
			t.Fatal(err)
		}
		tokens[name] = token
	}
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	for name, token := range tokens {
		for _, path := range []string{"/api/v1/inspection/health", "/api/v1/inspection/capabilities", "/api/v1/security/events", "/api/v1/security/events/missing", "/api/v1/sessions", "/api/v1/sessions/missing", "/api/v1/events"} {
			t.Run(name+path, func(t *testing.T) {
				request, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
				if token != "" {
					request.Header.Set("Authorization", "Bearer "+token)
				}
				response, err := http.DefaultClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				response.Body.Close()
				anonymous := name == "anonymous" || name == "invalid"
				want := http.StatusOK
				if anonymous {
					want = http.StatusUnauthorized
				} else if path == "/api/v1/sessions/missing" {
					want = http.StatusNotFound
				}
				if response.StatusCode != want {
					t.Fatalf("status=%d, want=%d", response.StatusCode, want)
				}
			})
		}
	}
	for _, role := range []string{"viewer", "operator"} {
		request, _ := http.NewRequest(http.MethodPut, server.URL+"/api/v1/config/candidate", strings.NewReader(`{}`))
		request.Header.Set("Authorization", "Bearer "+tokens[role])
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s config mutation status=%d", role, response.StatusCode)
		}
	}
	logout, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/auth/logout", nil)
	logout.Header.Set("Authorization", "Bearer "+tokens["viewer"])
	loggedOut, err := http.DefaultClient.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	loggedOut.Body.Close()
	if loggedOut.StatusCode != http.StatusOK {
		t.Fatalf("viewer logout status=%d, want 200", loggedOut.StatusCode)
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sessions", nil)
	request.Header.Set("Authorization", "Bearer "+tokens["viewer"])
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("logged-out token still reads sessions")
	}
	getLogout, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/auth/logout", nil)
	getLogout.Header.Set("Authorization", "Bearer "+tokens["operator"])
	methodResponse, err := http.DefaultClient.Do(getLogout)
	if err != nil {
		t.Fatal(err)
	}
	methodResponse.Body.Close()
	if methodResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status=%d, want 405", methodResponse.StatusCode)
	}
	stillValid, _ := http.NewRequest(http.MethodGet, server.URL+"/api/v1/sessions", nil)
	stillValid.Header.Set("Authorization", "Bearer "+tokens["operator"])
	validResponse, err := http.DefaultClient.Do(stillValid)
	if err != nil {
		t.Fatal(err)
	}
	validResponse.Body.Close()
	if validResponse.StatusCode != http.StatusOK {
		t.Fatalf("GET logout revoked operator token: status=%d", validResponse.StatusCode)
	}
}

func TestWebSocketAuthenticationBeforeUpgradeAndNoCredentialEcho(t *testing.T) {
	api := newRuntimeAPIForTest(t, &runtimeAPIFake{})
	api.Token = "master-token"
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	for _, path := range []string{"/ws/events", "/ws/stats"} {
		credential := webSocketCredentialPrefix + base64.RawURLEncoding.EncodeToString([]byte(api.Token))
		for _, protocols := range []string{"", "ngfw.v1, ngfw.auth.!!!", "ngfw.v1, ngfw.auth." + base64.RawURLEncoding.EncodeToString([]byte("bad-token")), "ngfw.v1, " + credential + ", " + credential} {
			request, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
			request.Header.Set("Sec-WebSocket-Protocol", protocols)
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("unauthenticated %s status=%d", path, response.StatusCode)
			}
		}
		config, err := websocket.NewConfig("ws"+strings.TrimPrefix(server.URL, "http")+path, server.URL)
		if err != nil {
			t.Fatal(err)
		}
		config.Protocol = []string{webSocketProtocol, webSocketCredentialPrefix + base64.RawURLEncoding.EncodeToString([]byte(api.Token))}
		connection, err := websocket.DialConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		if protocols := connection.Config().Protocol; len(protocols) != 1 || protocols[0] != webSocketProtocol {
			t.Fatalf("credential echoed in selected protocol: %q", protocols)
		}
		connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		var message map[string]any
		if err := websocket.JSON.Receive(connection, &message); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		if message["success"] != true {
			connection.Close()
			t.Fatalf("authenticated stream returned an error: %#v", message)
		}
		connection.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := api.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
