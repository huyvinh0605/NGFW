package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

// BufferedRequestBody keeps at most max+1 bytes in memory. The extra byte
// distinguishes exactly-at-limit from oversize without draining an unbounded
// request before the engine decides what to do. No upstream object exists here.
type BufferedRequestBody struct {
	mu       sync.Mutex
	buffered []byte
	source   io.ReadCloser
	max      int
	oversize bool
	used     bool
	closed   bool
}

func ReadGateRequestBody(ctx context.Context, source io.ReadCloser, max int) (*BufferedRequestBody, error) {
	if ctx == nil || max < 1 || max > 1<<20 {
		return nil, inspection.ErrGateHTTPMalformed
	}
	if source == nil {
		source = http.NoBody
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = source.Close() })
	defer stop()
	buffered, err := io.ReadAll(io.LimitReader(source, int64(max)+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &BufferedRequestBody{buffered: buffered, source: source, max: max, oversize: len(buffered) > max}, nil
}

func (body *BufferedRequestBody) InspectionPrefix() ([]byte, bool) {
	if body == nil {
		return nil, false
	}
	body.mu.Lock()
	defer body.mu.Unlock()
	limit := min(len(body.buffered), body.max)
	return append([]byte(nil), body.buffered[:limit]...), body.oversize
}

func (body *BufferedRequestBody) Close() error {
	if body == nil {
		return nil
	}
	body.mu.Lock()
	if body.closed || body.used {
		body.mu.Unlock()
		return nil
	}
	body.closed = true
	source := body.source
	body.mu.Unlock()
	return source.Close()
}

type gateBodyReplay struct {
	io.Reader
	source io.Closer
}

func (replay gateBodyReplay) Close() error { return replay.source.Close() }

// ReplayAfterAllow is the only way to transfer the original body to an
// upstream request. A BLOCK/UNAVAILABLE or wrong-request decision cannot
// acquire the reader. The original raw bytes are replayed before the unread
// tail; detector normalization never rewrites the application payload.
func (body *BufferedRequestBody) ReplayAfterAllow(decision domain.RequestDecision, expectedRequestID string) (io.ReadCloser, error) {
	if body == nil || decision.Verdict != domain.RequestAllow || decision.DecisionID == "" || decision.RequestID == "" || decision.RequestID != expectedRequestID || !decision.Coverage.Valid() {
		return nil, ErrGateDecisionInvalid
	}
	body.mu.Lock()
	defer body.mu.Unlock()
	if body.used || body.closed {
		return nil, ErrGateDecisionInvalid
	}
	body.used = true
	return gateBodyReplay{Reader: io.MultiReader(bytes.NewReader(body.buffered), body.source), source: body.source}, nil
}

func (allocator *RequestIdentityAllocator) NormalizeBufferedRequest(request *http.Request, body *BufferedRequestBody, sessionID string, secure bool, limits domain.RequestGateConfig) (domain.RequestContext, inspection.GateHTTPRequest, error) {
	if body == nil {
		return domain.RequestContext{}, inspection.GateHTTPRequest{}, errors.New("missing bounded request body")
	}
	prefix, oversize := body.InspectionPrefix()
	context, normalized, err := allocator.NormalizeRequest(request, prefix, sessionID, secure, limits)
	if err != nil {
		return domain.RequestContext{}, inspection.GateHTTPRequest{}, err
	}
	context.Truncated = oversize
	return context, normalized, nil
}
