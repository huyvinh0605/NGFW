package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/gateipc"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/requestworker"
)

// RuntimeBuilder contains deployment artifacts and the kernel resolver, not
// firewall policy. Limits and CA requirements always come from the engine.
type RuntimeBuilder struct {
	Client                             *gateipc.Client
	Resolver                           OriginalDestinationResolver
	Transparent                        bool
	ListenHost                         string
	CACertPath, CAKeyPath              string
	UpstreamCAPath                     string
	SuricataBinary, SuricataConfigPath string
	RulesetID, RulesetPath, WorkerRoot string
	WorkerFactory                      requestworker.SessionFactory
}

func (builder RuntimeBuilder) Start(ctx context.Context, descriptor domain.RequestGateRuntime) (ManagedRuntime, error) {
	if ctx == nil || !validRuntimeDescriptor(descriptor) || !descriptor.Config.Enabled || (!descriptor.InterceptionReady && descriptor.PreparationID == "") || builder.Client == nil {
		return nil, ErrGateRuntimeInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The native resolver is injected only after the supported kernel path is
	// established. Never fall back to the listener address or fixed upstream.
	if builder.Resolver == nil {
		return nil, ErrOriginalDestinationUnavailable
	}
	limits := descriptor.Config.WithDefaults()
	var ca *inspection.MITMCA
	var err error
	if descriptor.RequiresCA {
		ca, err = inspection.LoadMITMCA(builder.CACertPath, builder.CAKeyPath)
		if err != nil {
			return nil, errors.New("GATE_CA_UNAVAILABLE")
		}
		if err := ca.ConfigureLeafCache(limits.LeafCacheEntries, time.Duration(limits.LeafCacheTTLSeconds)*time.Second); err != nil {
			return nil, errors.New("GATE_CA_UNAVAILABLE")
		}
	}
	var roots *x509.CertPool
	if builder.UpstreamCAPath != "" {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("GATE_CA_UNAVAILABLE")
		}
		pem, readErr := boundedArtifact(builder.UpstreamCAPath)
		if readErr != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("GATE_CA_UNAVAILABLE")
		}
	}
	if builder.RulesetID != limits.RulesetID {
		return nil, errors.New("GATE_RULESET_UNAVAILABLE")
	}
	rules, err := boundedArtifact(builder.RulesetPath)
	if err != nil {
		return nil, errors.New("GATE_RULESET_UNAVAILABLE")
	}
	hash := sha256.Sum256(rules)
	artifacts := domain.RequestGateArtifacts{RulesetID: limits.RulesetID, RulesetHash: hex.EncodeToString(hash[:])}
	if ca != nil {
		artifacts.CAFingerprint = ca.FingerprintSHA256()
	}
	if builder.WorkerFactory == nil {
		workerConfig, err := boundedArtifact(builder.SuricataConfigPath)
		if err != nil {
			return nil, errors.New("GATE_SENSOR_UNAVAILABLE")
		}
		sum := sha256.Sum256(workerConfig)
		artifacts.WorkerConfigHash = hex.EncodeToString(sum[:])
	}
	if descriptor.ExpectedArtifacts != (domain.RequestGateArtifacts{}) && descriptor.ExpectedArtifacts != artifacts {
		return nil, errors.New("GATE_RULESET_UNAVAILABLE")
	}
	factory := builder.WorkerFactory
	if factory == nil {
		factory, err = requestworker.ProductionFactory(requestworker.ProcessConfig{Binary: builder.SuricataBinary, ConfigPath: builder.SuricataConfigPath, RootDir: builder.WorkerRoot, DropNetworkRawCapability: builder.Transparent})
		if err != nil {
			return nil, errors.New("GATE_SENSOR_UNAVAILABLE")
		}
	}
	runtimeCtx, cancel := context.WithCancel(ctx)
	pool, err := requestworker.New(runtimeCtx, requestworker.Config{
		RootDir: builder.WorkerRoot, WorkerCount: limits.WorkerCount, QueueItems: limits.QueueItems,
		QueueBytes: limits.QueueBytes, RequestTimeout: time.Duration(limits.RequestTimeoutMillis) * time.Millisecond,
	}, factory)
	if err != nil {
		cancel()
		return nil, errors.New("GATE_SENSOR_UNAVAILABLE")
	}
	host := builder.ListenHost
	if host == "" {
		host = "0.0.0.0"
	}
	listen := func(port int) (net.Listener, error) {
		if builder.Transparent {
			return listenTransparentTCP(runtimeCtx, host, port)
		}
		return (&net.ListenConfig{}).Listen(runtimeCtx, "tcp4", net.JoinHostPort(host, strconv.Itoa(port)))
	}
	httpListener, err := listen(limits.ListenHTTPPort)
	if err != nil {
		cancel()
		pool.Close()
		return nil, errors.New("GATE_LISTENER_UNAVAILABLE")
	}
	httpsListener, err := listen(limits.ListenHTTPSPort)
	if err != nil {
		cancel()
		_ = httpListener.Close()
		pool.Close()
		return nil, errors.New("GATE_LISTENER_UNAVAILABLE")
	}
	gate := &HTTP1RequestGate{
		Limits: limits, Roots: roots,
		Inspector:  SuricataRequestInspector{Pool: pool, RulesetID: limits.RulesetID, RulesetHash: hex.EncodeToString(hash[:])},
		Authorizer: IPCRequestAuthorizer{Client: builder.Client, EngineInstanceID: descriptor.EngineInstanceID, Generation: descriptor.ConfigGeneration},
	}
	handler := &GateConnectionHandler{
		Authorizer: IPCConnectionAuthorizer{Client: builder.Client, EngineInstanceID: descriptor.EngineInstanceID, Generation: descriptor.ConfigGeneration},
		HTTPGate:   gate, CA: ca, ClientHelloBytes: limits.ClientHelloBytes,
		ClientHelloTimeout: time.Duration(limits.ClientHelloTimeoutMillis) * time.Millisecond,
	}
	server := NewConnectionServer(builder.Resolver, handler)
	runtime := &managedProxyRuntime{ctx: runtimeCtx, cancel: cancel, pool: pool, server: server, handler: handler, gate: gate, caLoaded: ca != nil, artifacts: artifacts, http: httpListener, https: httpsListener, done: make(chan struct{})}
	go func() {
		defer close(runtime.done)
		_ = server.Serve(runtimeCtx, httpListener, httpsListener)
		cancel()
	}()
	return runtime, nil
}

func boundedArtifact(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, ErrGateRuntimeInvalid
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(data) == 0 || len(data) > 1<<20 {
		return nil, ErrGateRuntimeInvalid
	}
	return data, nil
}

type managedProxyRuntime struct {
	ctx         context.Context
	cancel      context.CancelFunc
	pool        *requestworker.Pool
	server      *ConnectionServer
	handler     *GateConnectionHandler
	gate        *HTTP1RequestGate
	caLoaded    bool
	artifacts   domain.RequestGateArtifacts
	http, https net.Listener
	done        chan struct{}
	once        sync.Once
}

func (runtime *managedProxyRuntime) Snapshot() domain.RequestGateHeartbeat {
	connections, requests, workers := runtime.server.Stats(), runtime.gate.Stats(), runtime.pool.Stats()
	beat := domain.RequestGateHeartbeat{
		Artifacts:         runtime.artifacts,
		HTTPListenerReady: runtime.ctx.Err() == nil, HTTPSListenerReady: runtime.ctx.Err() == nil,
		CALoaded: runtime.caLoaded, WorkersReady: workers.WorkersReady, QueueDepth: workers.QueuedItems,
		ActiveConnections: int(connections.Active), ActiveRequests: requests.ActiveRequests, Counters: requests.Counters,
	}
	for name, count := range runtime.handler.Stats().Counters {
		beat.Counters[name] += count
	}
	beat.Counters["capacity_rejected"] += connections.CapacityRejected
	beat.Counters["resolve_failed"], beat.Counters["handler_failed"] = connections.ResolveFailed, connections.HandlerFailed
	if workers.WorkersReady != workers.Workers {
		beat.FailureCode = "GATE_SENSOR_UNAVAILABLE"
	}
	if runtime.ctx.Err() != nil {
		beat.FailureCode = "GATE_LISTENER_UNAVAILABLE"
	}
	return beat
}

func (runtime *managedProxyRuntime) Close() {
	runtime.once.Do(func() {
		runtime.cancel()
		_ = runtime.http.Close()
		_ = runtime.https.Close()
		runtime.pool.Close()
		<-runtime.done
	})
}
