// Package requestworker owns a bounded synchronous Suricata request-inspection
// pool. Detector bytes never enter the engine IPC; T22 normalizes job-local
// EVE before the proxy sends evidence to the authoritative engine.
package requestworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/requestpcap"
)

var (
	ErrInvalidConfig = errors.New("REQUEST_WORKER_INVALID_CONFIG")
	ErrQueueFull     = errors.New("GATE_QUEUE_FULL")
	ErrUnavailable   = errors.New("GATE_SENSOR_UNAVAILABLE")
	ErrFlowIDLimit   = errors.New("REQUEST_WORKER_FLOW_ID_LIMIT")
)

type Config struct {
	RootDir        string
	WorkerCount    int
	QueueItems     int
	QueueBytes     int
	RequestTimeout time.Duration
}

type Session interface {
	Run(ctx context.Context, pcapPath, outputDir string) ([]byte, error)
	Close() error
}

type SessionFactory func(ctx context.Context, workerID int) (Session, error)

type Result struct {
	RequestID string
	WorkerID  int
	FlowID    uint32
	PCAPPath  string
	EVE       []byte
	Duration  time.Duration
}

type Stats struct {
	QueuedItems   int
	InFlightItems int
	QueuedBytes   int
	Workers       int
}

type job struct {
	ctx       context.Context
	requestID string
	flowID    uint32
	pcap      []byte
	result    chan outcome
}

type outcome struct {
	result Result
	err    error
}

type Pool struct {
	config   Config
	ctx      context.Context
	cancel   context.CancelFunc
	jobs     chan *job
	slots    chan struct{}
	builders chan struct{}
	sessions []Session
	flowID   atomic.Uint32
	workers  sync.WaitGroup
	mu       sync.Mutex
	closed   bool
	inFlight int
	bytes    int
}

// New starts a fixed number of workers. Each factory result must own one
// Suricata process and command socket; failed startup closes prior sessions.
func New(parent context.Context, config Config, factory SessionFactory) (*Pool, error) {
	if parent == nil || factory == nil || config.WorkerCount < 1 || config.WorkerCount > 4 || config.QueueItems < 1 || config.QueueItems > 1024 || config.QueueBytes < 64<<10 || config.QueueBytes > 32<<20 || config.RequestTimeout < 100*time.Millisecond || config.RequestTimeout > 30*time.Second || !filepath.IsAbs(config.RootDir) {
		return nil, ErrInvalidConfig
	}
	if parent.Err() != nil {
		return nil, parent.Err()
	}
	if err := os.MkdirAll(config.RootDir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(config.RootDir)
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalidConfig
	}
	ctx, cancel := context.WithCancel(parent)
	pool := &Pool{
		config: config, ctx: ctx, cancel: cancel,
		jobs:     make(chan *job, config.QueueItems),
		slots:    make(chan struct{}, config.QueueItems+config.WorkerCount),
		builders: make(chan struct{}, config.WorkerCount),
	}
	for workerID := 0; workerID < config.WorkerCount; workerID++ {
		session, err := factory(ctx, workerID)
		if err != nil || session == nil {
			cancel()
			for _, started := range pool.sessions {
				_ = started.Close()
			}
			if err == nil {
				err = ErrUnavailable
			}
			return nil, err
		}
		pool.sessions = append(pool.sessions, session)
	}
	for workerID, session := range pool.sessions {
		pool.workers.Add(1)
		go pool.worker(workerID, session)
	}
	return pool, nil
}

// Inspect rejects overflow immediately. The caller's deadline includes queue
// wait, and no worker may return a result for a different RequestID.
func (pool *Pool) Inspect(ctx context.Context, requestID string, request inspection.GateHTTPRequest) (Result, error) {
	if pool == nil || ctx == nil || requestID == "" {
		return Result{}, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	pool.mu.Lock()
	closed := pool.closed
	pool.mu.Unlock()
	if closed || pool.ctx.Err() != nil {
		return Result{}, ErrUnavailable
	}
	select {
	case pool.slots <- struct{}{}:
	default:
		return Result{}, ErrQueueFull
	}
	select {
	case pool.builders <- struct{}{}:
	default:
		<-pool.slots
		return Result{}, ErrQueueFull
	}
	building := true
	defer func() {
		if building {
			<-pool.builders
		}
	}()
	callCtx, cancel := context.WithTimeout(ctx, pool.config.RequestTimeout)
	defer cancel()
	var flowID uint32
	for {
		previous := pool.flowID.Load()
		if previous == ^uint32(0) {
			<-pool.slots
			return Result{}, ErrFlowIDLimit
		}
		if pool.flowID.CompareAndSwap(previous, previous+1) {
			flowID = previous + 1
			break
		}
	}
	pcap, err := requestpcap.Build(request, flowID)
	if err != nil {
		<-pool.slots
		return Result{}, err
	}
	work := &job{ctx: callCtx, requestID: requestID, flowID: flowID, pcap: pcap, result: make(chan outcome, 1)}
	pool.mu.Lock()
	if pool.closed || pool.ctx.Err() != nil {
		pool.mu.Unlock()
		<-pool.slots
		return Result{}, ErrUnavailable
	}
	if callCtx.Err() != nil {
		pool.mu.Unlock()
		<-pool.slots
		return Result{}, callCtx.Err()
	}
	if pool.bytes+len(pcap) > pool.config.QueueBytes {
		pool.mu.Unlock()
		<-pool.slots
		return Result{}, ErrQueueFull
	}
	select {
	case pool.jobs <- work:
		pool.bytes += len(pcap)
		pool.inFlight++
	default:
		pool.mu.Unlock()
		<-pool.slots
		return Result{}, ErrQueueFull
	}
	pool.mu.Unlock()
	<-pool.builders
	building = false
	select {
	case value := <-work.result:
		if err := callCtx.Err(); err != nil {
			return Result{}, err
		}
		return value.result, value.err
	case <-callCtx.Done():
		return Result{}, callCtx.Err()
	case <-pool.ctx.Done():
		return Result{}, ErrUnavailable
	}
}

func (pool *Pool) Stats() Stats {
	if pool == nil {
		return Stats{}
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return Stats{QueuedItems: len(pool.jobs), InFlightItems: pool.inFlight, QueuedBytes: pool.bytes, Workers: len(pool.sessions)}
}

func (pool *Pool) Close() {
	if pool == nil {
		return
	}
	pool.mu.Lock()
	if pool.closed {
		pool.mu.Unlock()
		return
	}
	pool.closed = true
	pool.mu.Unlock()
	pool.cancel()
	for _, session := range pool.sessions {
		_ = session.Close()
	}
	pool.workers.Wait()
	for {
		select {
		case work := <-pool.jobs:
			pool.finish(work, Result{}, ErrUnavailable)
		default:
			return
		}
	}
}

func (pool *Pool) worker(workerID int, session Session) {
	defer pool.workers.Done()
	for {
		select {
		case <-pool.ctx.Done():
			return
		case work := <-pool.jobs:
			if work.ctx.Err() != nil {
				pool.finish(work, Result{}, work.ctx.Err())
				continue
			}
			start := time.Now()
			result, err := pool.run(work, workerID, session)
			result.Duration = time.Since(start)
			pool.finish(work, result, err)
		}
	}
}

func (pool *Pool) run(work *job, workerID int, session Session) (Result, error) {
	ctx, cancel := context.WithCancel(work.ctx)
	stop := context.AfterFunc(pool.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := work.ctx.Err(); err != nil {
		return Result{}, err
	}
	directory, err := os.MkdirTemp(pool.config.RootDir, "job-")
	if err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0700); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	output := filepath.Join(directory, "output")
	if err := os.Mkdir(output, 0700); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	pcapPath := filepath.Join(directory, "request.pcap")
	if err := os.WriteFile(pcapPath, work.pcap, 0600); err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	eve, err := session.Run(ctx, pcapPath, output)
	if err != nil {
		return Result{}, errors.Join(ErrUnavailable, err)
	}
	if len(eve) == 0 || len(eve) > 1<<20 {
		return Result{}, ErrUnavailable
	}
	return Result{RequestID: work.requestID, WorkerID: workerID, FlowID: work.flowID, PCAPPath: pcapPath, EVE: append([]byte(nil), eve...)}, nil
}

func (pool *Pool) finish(work *job, result Result, err error) {
	pool.mu.Lock()
	pool.inFlight--
	pool.bytes -= len(work.pcap)
	pool.mu.Unlock()
	<-pool.slots
	work.result <- outcome{result: result, err: err}
}
