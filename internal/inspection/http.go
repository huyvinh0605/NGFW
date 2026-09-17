package inspection

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/kltngfw/ngfw/internal/domain"
)

var ErrInspectionLimit = errors.New("HTTP inspection limit exceeded")

type HTTPLimits struct {
	MaxHeaderSize  int
	MaxBodySize    int
	MaxURLLength   int
	MaxHeaders     int
	MaxDecodeDepth int
}

func DefaultHTTPLimits() HTTPLimits {
	return HTTPLimits{MaxHeaderSize: 32 * 1024, MaxBodySize: 64 * 1024, MaxURLLength: 8 * 1024, MaxHeaders: 64, MaxDecodeDepth: 2}
}

type HTTPRequest struct {
	RequestID     string            `json:"request_id"`
	StreamID      uint32            `json:"stream_id,omitempty"`
	Method        string            `json:"method"`
	Host          string            `json:"host"`
	Path          string            `json:"path"`
	Query         string            `json:"query,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	Body          []byte            `json:"-"`
	BodyTruncated bool              `json:"body_truncated"`
	HTTPVersion   string            `json:"http_version"`
}

func ParseHTTPRequest(raw []byte, limits HTTPLimits) (HTTPRequest, error) {
	if limits.MaxHeaderSize <= 0 || limits.MaxBodySize <= 0 || limits.MaxURLLength <= 0 || limits.MaxHeaders <= 0 {
		limits = DefaultHTTPLimits()
	}
	if len(raw) > limits.MaxHeaderSize+limits.MaxBodySize+8192 {
		return HTTPRequest{}, ErrInspectionLimit
	}
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return HTTPRequest{}, errors.New("incomplete HTTP request")
	}
	if headerEnd > limits.MaxHeaderSize {
		return HTTPRequest{}, ErrInspectionLimit
	}
	reader := bufio.NewReader(bytes.NewReader(raw[:headerEnd+4]))
	req, err := http.ReadRequest(reader)
	if err != nil {
		return HTTPRequest{}, fmt.Errorf("parse HTTP request: %w", err)
	}
	if req.URL == nil || len(req.URL.String()) > limits.MaxURLLength {
		return HTTPRequest{}, ErrInspectionLimit
	}
	if req.Header == nil {
		return HTTPRequest{}, errors.New("missing headers")
	}
	if len(req.Header) > limits.MaxHeaders {
		return HTTPRequest{}, ErrInspectionLimit
	}
	bodyStart := headerEnd + 4
	body := raw[bodyStart:]
	truncated := len(body) > limits.MaxBodySize
	if truncated {
		body = body[:limits.MaxBodySize]
	}
	headers := map[string]string{}
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = bounded(v[0], 4096)
		}
	}
	host := req.Host
	if host == "" {
		host = headers["host"]
	}
	return HTTPRequest{Method: req.Method, Host: host, Path: req.URL.Path, Query: req.URL.RawQuery, Headers: headers, ContentType: req.Header.Get("Content-Type"), Body: append([]byte(nil), body...), BodyTruncated: truncated, HTTPVersion: req.Proto}, nil
}

func (r HTTPRequest) URL() string {
	if r.Query == "" {
		return r.Path
	}
	return r.Path + "?" + r.Query
}
func (r HTTPRequest) MLInput(max int) string {
	if max <= 0 || max > 64*1024 {
		max = 64 * 1024
	}
	body := string(r.Body)
	value := r.Method + " " + r.Host + " " + r.URL() + "\n" + body
	if len(value) > max {
		value = value[:max]
	}
	return value
}
func (r HTTPRequest) SecurityContext(ctx *domain.SecurityContext) {
	ctx.App.Protocol = r.HTTPVersion
	ctx.App.Application = "HTTP"
	ctx.App.Confidence = 1
	ctx.App.Hostname = r.Host
	ctx.App.URL = bounded(r.URL(), 8192)
	ctx.App.Method = r.Method
	ctx.App.ContentType = r.ContentType
}

type URLVerdict struct {
	Allowed  bool
	Category string
	Reason   string
}
type URLFilter struct {
	BlockedDomains  []string
	BlockedPrefixes []string
}

func (f URLFilter) Evaluate(req HTTPRequest) URLVerdict {
	host := strings.ToLower(strings.TrimSuffix(req.Host, "."))
	for _, d := range f.BlockedDomains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if host == d || strings.HasSuffix(host, "."+d) {
			return URLVerdict{Reason: "blocked domain " + d, Category: "DOMAIN"}
		}
	}
	for _, p := range f.BlockedPrefixes {
		if strings.HasPrefix(req.Path, p) {
			return URLVerdict{Reason: "blocked path prefix " + p, Category: "PATH"}
		}
	}
	return URLVerdict{Allowed: true}
}

func DecodeForInspection(s string, depth int) string {
	if depth <= 0 {
		return s
	}
	for i := 0; i < depth; i++ {
		next, err := url.QueryUnescape(s)
		if err != nil || next == s {
			break
		}
		s = next
	}
	return strings.Map(func(r rune) rune {
		if r == '\x00' || !utf8.ValidRune(r) {
			return ' '
		}
		return r
	}, s)
}
func ReadBounded(r io.Reader, max int) ([]byte, bool, error) {
	if max <= 0 {
		return nil, false, errors.New("max must be positive")
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, false, err
	}
	if len(b) > max {
		return b[:max], true, nil
	}
	return b, false, nil
}
func bounded(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
