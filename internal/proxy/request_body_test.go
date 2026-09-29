package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

type countingBody struct {
	*bytes.Reader
	read   int
	closed bool
}

func (body *countingBody) Read(target []byte) (int, error) {
	n, err := body.Reader.Read(target)
	body.read += n
	return n, err
}

func (body *countingBody) Close() error { body.closed = true; return nil }

func TestReadGateRequestBodyOversizeAndReplayOnlyAfterAllow(t *testing.T) {
	raw := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	source := &countingBody{Reader: bytes.NewReader(raw)}
	body, err := ReadGateRequestBody(context.Background(), source, 8)
	if err != nil || source.read != 9 {
		t.Fatalf("body reader was not bounded to max+1: bytes=%d err=%v", source.read, err)
	}
	prefix, oversize := body.InspectionPrefix()
	if !oversize || string(prefix) != "01234567" {
		t.Fatalf("oversize inspection prefix incorrect: %q %v", prefix, oversize)
	}
	allocator, _ := NewRequestIdentityAllocator("0123456789abcdef0123456789abcdef")
	request := httptest.NewRequest(http.MethodPost, "http://app.example/upload", nil)
	limits := domain.DefaultRequestGateConfig()
	limits.MaxRawBodyBytes = 8
	context, normalized, err := allocator.NormalizeBufferedRequest(request, body, "session-1", false, limits)
	if err != nil || !context.Truncated || context.BodyBytes != 8 || len(normalized.Body) != 8 {
		t.Fatalf("oversize coverage was not marked partial: %+v %v", context, err)
	}
	blocked := domain.RequestDecision{DecisionID: "d1", RequestID: context.RequestID, Verdict: domain.RequestBlock, Coverage: domain.RequestCoveragePartial}
	if reader, err := body.ReplayAfterAllow(blocked, context.RequestID); reader != nil || !errors.Is(err, ErrGateDecisionInvalid) {
		t.Fatalf("BLOCK released original body: %v", err)
	}
	allowed := domain.RequestDecision{DecisionID: "d2", RequestID: context.RequestID, Verdict: domain.RequestAllow, Coverage: domain.RequestCoveragePartial}
	if reader, err := body.ReplayAfterAllow(allowed, "wrong-request-id"); reader != nil || !errors.Is(err, ErrGateDecisionInvalid) {
		t.Fatalf("wrong request decision released body: %v", err)
	}
	replay, err := body.ReplayAfterAllow(allowed, context.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := io.ReadAll(replay)
	if err != nil || !bytes.Equal(forwarded, raw) {
		t.Fatalf("ALLOW_PARTIAL changed raw upstream body: %q %v", forwarded, err)
	}
	if _, err := body.ReplayAfterAllow(allowed, context.RequestID); !errors.Is(err, ErrGateDecisionInvalid) {
		t.Fatal("body could be forwarded twice")
	}
	if err := replay.Close(); err != nil || !source.closed {
		t.Fatalf("replay did not close original body: %v", err)
	}
}

func TestReadGateRequestBodyExactLimitAndCancel(t *testing.T) {
	body, err := ReadGateRequestBody(context.Background(), io.NopCloser(bytes.NewReader([]byte("1234"))), 4)
	if err != nil {
		t.Fatal(err)
	}
	prefix, oversize := body.InspectionPrefix()
	if oversize || string(prefix) != "1234" {
		t.Fatalf("exact limit was treated as oversize: %q %v", prefix, oversize)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if body, err := ReadGateRequestBody(cancelled, io.NopCloser(bytes.NewReader([]byte("1234"))), 4); body != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request body was read: %v", err)
	}
	if body, err := ReadGateRequestBody(context.Background(), http.NoBody, 1<<21); body != nil || err == nil {
		t.Fatal("invalid body cap was accepted")
	}
}
