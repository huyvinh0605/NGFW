package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engine"
	"github.com/kltngfw/ngfw/internal/inspection"
)

type Classifier interface {
	Classify(context.Context, string) (domain.MLContext, error)
}
type SignatureDetector func(inspection.HTTPRequest) []domain.SecurityEvent

type Gate struct {
	Engine                      *engine.Engine
	Upstream                    *url.URL
	Limits                      inspection.HTTPLimits
	SourceZone                  string
	DestinationZone             string
	URLFilter                   inspection.URLFilter
	Reputation                  *inspection.ReputationStore
	ML                          Classifier
	Signatures                  SignatureDetector
	FailClosedOnInspectionError bool
	requestID                   atomic.Uint64
}

func NewGate(e *engine.Engine, upstream string) (*Gate, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("upstream must include scheme and host")
	}
	return &Gate{Engine: e, Upstream: u, Limits: inspection.DefaultHTTPLimits(), SourceZone: "lan", DestinationZone: "dmz", Signatures: DefaultSignatures}, nil
}

func (g *Gate) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		http.Error(w, "CONNECT is not supported by the lab request gate", http.StatusNotImplemented)
		return
	}
	limits := g.Limits
	if limits.MaxBodySize <= 0 {
		limits = inspection.DefaultHTTPLimits()
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limits.MaxBodySize)+1))
	if err != nil {
		http.Error(w, "request body unavailable", http.StatusBadRequest)
		return
	}
	if len(body) > limits.MaxBodySize {
		http.Error(w, "request body exceeds inspection limit", http.StatusRequestEntityTooLarge)
		return
	}
	_ = r.Body.Close()
	requestID := fmt.Sprintf("req-%d", g.requestID.Add(1))
	info := inspection.HTTPRequest{RequestID: requestID, Method: r.Method, Host: r.Host, Path: r.URL.Path, Query: r.URL.RawQuery, ContentType: r.Header.Get("Content-Type"), HTTPVersion: r.Proto, Body: body, Headers: map[string]string{}}
	for k, v := range r.Header {
		if len(v) > 0 {
			info.Headers[strings.ToLower(k)] = v[0]
		}
	}
	clientIP := remoteIP(r.RemoteAddr)
	dstIP := hostIP(g.Upstream.Hostname())
	dstPort := g.Upstream.Port()
	if dstPort == "" {
		if g.Upstream.Scheme == "https" {
			dstPort = "443"
		} else {
			dstPort = "80"
		}
	}
	port, _ := strconv.Atoi(dstPort)
	key := domain.FlowKey{SrcIP: clientIP, DstIP: dstIP, SrcPort: remotePort(r.RemoteAddr), DstPort: port, Protocol: "tcp", Namespace: "proxy"}
	var hints []domain.SecurityEvent
	if verdict := g.URLFilter.Evaluate(info); !verdict.Allowed {
		hints = append(hints, domain.SecurityEvent{EventID: requestID + "-url", Timestamp: time.Now().UTC(), Detector: "URL", Category: "BLOCKED_URL", Severity: domain.SeverityHigh, Confidence: 1, SourceIP: clientIP, DestinationIP: dstIP, Application: "HTTP", Evidence: verdict.Reason})
	}
	if g.Signatures != nil {
		hints = append(hints, g.Signatures(info)...)
	}
	ml := domain.MLContext{Available: false}
	if g.ML != nil {
		var mlErr error
		ml, mlErr = g.ML.Classify(r.Context(), info.MLInput(limits.MaxBodySize))
		if mlErr != nil && g.FailClosedOnInspectionError {
			http.Error(w, "inspection unavailable", http.StatusServiceUnavailable)
			return
		}
		if mlErr == nil && ml.PredictedClass != "BENIGN" {
			hints = append(hints, domain.SecurityEvent{EventID: requestID + "-ml", Timestamp: time.Now().UTC(), Detector: "ML", Category: ml.PredictedClass, Severity: domain.SeverityHigh, Confidence: ml.Confidence, SourceIP: clientIP, DestinationIP: dstIP, Application: "HTTP", Evidence: "bounded ML request classification"})
		}
	}
	deadline := time.Duration(2) * time.Second
	if g.Engine != nil {
		if c := g.Engine.Config.Running(); c.RequestInspectionTimeoutMillis > 0 {
			deadline = time.Duration(c.RequestInspectionTimeoutMillis) * time.Millisecond
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), deadline)
	defer cancel()
	reputation := domain.ReputationContext{}
	if g.Reputation != nil {
		reputation = g.Reputation.LookupContext(clientIP, info.Host)
	}
	sess, sec, decision, err := g.Engine.EvaluateFlow(ctx, engine.FlowObservation{Key: key, SourceZone: g.SourceZone, DestinationZone: g.DestinationZone, Application: "HTTP", ApplicationConfidence: 1, RiskHints: hints, Reputation: reputation, ML: ml, Packets: 1, Bytes: uint64(len(body)), FromClient: true})
	if err != nil {
		http.Error(w, "decision unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("X-NGFW-Request-ID", requestID)
	w.Header().Set("X-NGFW-Decision", string(decision.Action))
	if decision.Action != domain.DecisionAllow {
		status := http.StatusForbidden
		if decision.Action == domain.DecisionRateLimit {
			status = http.StatusTooManyRequests
		}
		http.Error(w, fmt.Sprintf("request blocked by NGFW: %s (risk=%d)", decision.Reason, sec.Risk.Score), status)
		_ = sess
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL = &url.URL{Scheme: g.Upstream.Scheme, Host: g.Upstream.Host, Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery}
	r2.Host = g.Upstream.Host
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	r2.Header.Set("X-NGFW-Request-ID", requestID)
	proxy := httputil.NewSingleHostReverseProxy(g.Upstream)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r2)
}

func DefaultSignatures(req inspection.HTTPRequest) []domain.SecurityEvent {
	value := strings.ToLower(inspection.DecodeForInspection(req.Method+" "+req.URL()+" "+string(req.Body), 2))
	var result []domain.SecurityEvent
	add := func(id, category, evidence string) {
		result = append(result, domain.SecurityEvent{EventID: req.RequestID + "-" + id, Timestamp: time.Now().UTC(), Detector: "IPS", Category: category, SignatureID: id, Severity: domain.SeverityHigh, Confidence: 1, Application: "HTTP", Evidence: evidence})
	}
	if strings.Contains(value, "union select") || strings.Contains(value, " or 1=1") || strings.Contains(value, "sleep(") {
		add("942100", "SQL_INJECTION", "bounded SQL injection signature")
	}
	if strings.Contains(value, "<script") || strings.Contains(value, "javascript:") || strings.Contains(value, "onerror=") {
		add("941100", "XSS", "bounded XSS signature")
	}
	return result
}
func remoteIP(value string) string {
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return host
	}
	return value
}
func remotePort(value string) int {
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}
func hostIP(value string) string {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}
