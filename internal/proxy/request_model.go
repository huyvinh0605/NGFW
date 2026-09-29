package proxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"net/http"
	"sync/atomic"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

var ErrRequestIdentity = errors.New("GATE_REQUEST_IDENTITY_UNAVAILABLE")

// RequestIdentityAllocator belongs to exactly one downstream connection.
// HTTP/2 streams share only this atomic ordinal counter, never bodies,
// detector results, or decision pointers.
type RequestIdentityAllocator struct {
	connectionID string
	next         atomic.Uint64
}

func NewRequestIdentityAllocator(connectionID string) (*RequestIdentityAllocator, error) {
	if len(connectionID) != 32 {
		return nil, ErrRequestIdentity
	}
	if _, err := hex.DecodeString(connectionID); err != nil {
		return nil, ErrRequestIdentity
	}
	return &RequestIdentityAllocator{connectionID: connectionID}, nil
}

// NormalizeRequest builds a detached in-memory inspection view and the only
// metadata DTO that may be sent to the engine. Query/headers/body remain out
// of the DTO and its JSON representation. No wire StreamID is fabricated.
func (allocator *RequestIdentityAllocator) NormalizeRequest(request *http.Request, body []byte, sessionID string, secure bool, limits domain.RequestGateConfig) (domain.RequestContext, inspection.GateHTTPRequest, error) {
	if allocator == nil {
		return domain.RequestContext{}, inspection.GateHTTPRequest{}, ErrRequestIdentity
	}
	normalized, err := inspection.NormalizeGateHTTPRequest(request, body, limits)
	if err != nil {
		return domain.RequestContext{}, inspection.GateHTTPRequest{}, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return domain.RequestContext{}, inspection.GateHTTPRequest{}, ErrRequestIdentity
	}
	var ordinal uint64
	for {
		current := allocator.next.Load()
		if current == math.MaxUint64 {
			return domain.RequestContext{}, inspection.GateHTTPRequest{}, ErrRequestIdentity
		}
		if allocator.next.CompareAndSwap(current, current+1) {
			ordinal = current + 1
			break
		}
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	normalized.Scheme = scheme
	context := domain.RequestContext{
		RequestID: hex.EncodeToString(random[:]), ConnectionID: allocator.connectionID,
		SessionID: sessionID, RequestOrdinal: ordinal,
		HTTPVersion: normalized.HTTPVersion, Method: normalized.Method, Scheme: scheme,
		Host: normalized.Host, Path: normalized.Path,
		QueryPresent: request.URL.RawQuery != "" || request.URL.ForceQuery,
		ContentType:  normalized.ContentType, ContentEncoding: normalized.ContentEncoding,
		HeaderBytes: normalized.HeaderBytes, BodyBytes: len(normalized.Body),
	}
	if len(normalized.Body) > 0 {
		sum := sha256.Sum256(normalized.Body)
		context.BodySHA256 = hex.EncodeToString(sum[:])
	}
	if normalized.ContentEncoding == "" || normalized.ContentEncoding == "identity" {
		context.DecodedBodyBytes = len(normalized.Body)
	}
	return context, normalized, nil
}
