package management

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engineipc"
)

func TestInspectionReadErrorDistinguishesTransportTimeoutFromUnavailable(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"wrapped socket read deadline", fmt.Errorf("decode runtime response: %w", &net.OpError{Op: "read", Net: "unix", Err: os.ErrDeadlineExceeded}), 504, "ENGINE_TIMEOUT"},
		{"wrapped socket dial deadline", fmt.Errorf("dial runtime: %w", &net.OpError{Op: "dial", Net: "unix", Err: os.ErrDeadlineExceeded}), 504, "ENGINE_TIMEOUT"},
		{"context deadline", fmt.Errorf("query: %w", context.DeadlineExceeded), 504, "ENGINE_TIMEOUT"},
		{"typed remote deadline", &engineipc.RemoteError{Code: "DEADLINE_EXCEEDED", Message: "engine query deadline"}, 504, "ENGINE_TIMEOUT"},
		{"closed socket", fmt.Errorf("decode runtime response: %w", io.EOF), 503, "ENGINE_UNAVAILABLE"},
		{"timeout words without timeout type", errors.New("peer description says i/o timeout"), 503, "ENGINE_UNAVAILABLE"},
		{"request cancellation", context.Canceled, 503, "ENGINE_UNAVAILABLE"},
		{"missing event", domain.ErrSecurityEventNotFound, 404, "NOT_FOUND"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			writeInspectionReadError(response, test.err, true)
			if response.Code != test.status || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("got HTTP %d %s; want HTTP %d %s", response.Code, response.Body.String(), test.status, test.code)
			}
		})
	}
}
