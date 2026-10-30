package management

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engineipc"
)

type failedSessionReader struct {
	*runtimeAPIFake
	err error
}

func (f failedSessionReader) ListSessions(context.Context, domain.SessionQuery) (domain.SessionPage, error) {
	return domain.SessionPage{}, f.err
}
func (f failedSessionReader) GetSession(context.Context, string) (domain.RuntimeSession, error) {
	return domain.RuntimeSession{}, f.err
}
func (f failedSessionReader) RevokeSession(context.Context, string, string) error { return f.err }

func TestSessionReadErrorsKeepUnavailableTimeoutAndNotFoundDistinct(t *testing.T) {
	for _, target := range []struct{ method, path string }{{"GET", "/api/v1/sessions"}, {"GET", "/api/v1/sessions/absent"}, {"DELETE", "/api/v1/sessions/absent"}} {
		path := target.path
		for _, test := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{"socket deadline", fmt.Errorf("read runtime: %w", &net.OpError{Op: "read", Net: "unix", Err: os.ErrDeadlineExceeded}), 504, "ENGINE_TIMEOUT"},
			{"remote deadline", &engineipc.RemoteError{Code: "DEADLINE_EXCEEDED", Message: "query timeout"}, 504, "ENGINE_TIMEOUT"},
			{"disconnect", io.EOF, 503, "ENGINE_UNAVAILABLE"},
			{"remote not found", &engineipc.RemoteError{Code: "NOT_FOUND", Message: "runtime session not found"}, 404, "NOT_FOUND"},
			{"typed store not found", domain.ErrRuntimeSessionNotFound, 404, "NOT_FOUND"},
		} {
			if test.status == 404 && path == "/api/v1/sessions" {
				test.status, test.code = 503, "ENGINE_UNAVAILABLE"
			}
			t.Run(target.method+path+"/"+test.name, func(t *testing.T) {
				manager, err := config.NewManager(t.TempDir(), config.Defaults())
				if err != nil {
					t.Fatal(err)
				}
				api := NewRuntimeAPI(failedSessionReader{runtimeAPIFake: &runtimeAPIFake{}, err: test.err}, manager, "session-read-test-token", nil)
				response := httptest.NewRecorder()
				request := httptest.NewRequest(target.method, path, nil)
				request.Header.Set("Authorization", "Bearer session-read-test-token")
				api.Handler().ServeHTTP(response, request)
				if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
					t.Fatalf("HTTP %d %s; want %d %s", response.Code, response.Body, test.status, test.code)
				}
			})
		}
	}
}
