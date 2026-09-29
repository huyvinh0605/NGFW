package inspection

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

var (
	ErrGateHTTPMalformed   = errors.New("GATE_REQUEST_MALFORMED")
	ErrGateHeadersTooLarge = errors.New("GATE_HEADERS_TOO_LARGE")
	ErrGateURLTooLong      = errors.New("GATE_URL_TOO_LONG")
	ErrGateBodyTooLarge    = errors.New("GATE_REQUEST_TOO_LARGE")
)

// GateHTTPRequest is an in-memory inspection view. Sensitive query, headers
// and body are deliberately excluded from JSON; only RequestContext crosses
// the engine IPC or enters telemetry. Each value owns detached copies.
type GateHTTPRequest struct {
	Method          string      `json:"method"`
	Scheme          string      `json:"scheme"`
	Host            string      `json:"host"`
	Path            string      `json:"path"`
	RawQuery        string      `json:"-"`
	Headers         http.Header `json:"-"`
	Body            []byte      `json:"-"`
	HTTPVersion     string      `json:"http_version"`
	ContentType     string      `json:"content_type,omitempty"`
	ContentEncoding string      `json:"content_encoding,omitempty"`
	HeaderBytes     int         `json:"header_bytes"`
}

func (value GateHTTPRequest) Clone() GateHTTPRequest {
	value.Headers = value.Headers.Clone()
	value.Body = append([]byte(nil), value.Body...)
	return value
}

// NormalizeGateHTTPRequest accepts a body already read under T17's streaming
// cap. It also enforces hard limits defensively before building an inspection
// view; it never consumes a live request body or dials upstream.
func NormalizeGateHTTPRequest(request *http.Request, body []byte, limits domain.RequestGateConfig) (GateHTTPRequest, error) {
	if request == nil || request.URL == nil || request.Method == "" || request.Host == "" || request.ProtoMajor < 1 || request.ProtoMajor > 2 {
		return GateHTTPRequest{}, ErrGateHTTPMalformed
	}
	limits = limits.WithDefaults()
	if limits.MaxHeaderBytes < 1 || limits.MaxHeaderBytes > 64<<10 || limits.MaxHeaderCount < 1 || limits.MaxHeaderCount > 256 || limits.MaxURLBytes < 1 || limits.MaxURLBytes > 16<<10 || limits.MaxRawBodyBytes < 1 || limits.MaxRawBodyBytes > 1<<20 {
		return GateHTTPRequest{}, ErrGateHTTPMalformed
	}
	urlValue := request.URL.RequestURI()
	if len(urlValue) > limits.MaxURLBytes {
		return GateHTTPRequest{}, ErrGateURLTooLong
	}
	if len(body) > limits.MaxRawBodyBytes {
		return GateHTTPRequest{}, ErrGateBodyTooLarge
	}
	headerBytes := len(request.Method) + len(urlValue) + len(request.Proto) + len(request.Host) + 12
	headerCount := 1 // Host
	for name, values := range request.Header {
		if name == "" || len(values) == 0 {
			return GateHTTPRequest{}, ErrGateHTTPMalformed
		}
		for _, value := range values {
			headerBytes += len(name) + len(value) + 4
			headerCount++
		}
		if headerBytes > limits.MaxHeaderBytes || headerCount > limits.MaxHeaderCount {
			return GateHTTPRequest{}, ErrGateHeadersTooLarge
		}
	}
	if headerBytes > limits.MaxHeaderBytes || headerCount > limits.MaxHeaderCount {
		return GateHTTPRequest{}, ErrGateHeadersTooLarge
	}
	return GateHTTPRequest{
		Method: request.Method, Host: request.Host, Path: request.URL.EscapedPath(),
		RawQuery: request.URL.RawQuery, Headers: request.Header.Clone(), Body: append([]byte(nil), body...),
		HTTPVersion: request.Proto, ContentType: request.Header.Get("Content-Type"),
		ContentEncoding: strings.TrimSpace(strings.ToLower(request.Header.Get("Content-Encoding"))), HeaderBytes: headerBytes,
	}, nil
}
