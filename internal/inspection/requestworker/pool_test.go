package requestworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

type fakeSession struct {
	run   func(context.Context, string, string) ([]byte, error)
	close func()
}

func (session *fakeSession) Run(ctx context.Context, pcapPath, outputDir string) ([]byte, error) {
	return session.run(ctx, pcapPath, outputDir)
}
func (session *fakeSession) Close() error {
	if session.close != nil {
		session.close()
	}
	return nil
}

func poolConfig(t *testing.T) Config {
	t.Helper()
	return Config{RootDir: t.TempDir(), WorkerCount: 1, QueueItems: 1, QueueBytes: 64 << 10, RequestTimeout: time.Second}
}

func sampleRequest() inspection.GateHTTPRequest {
	return inspection.GateHTTPRequest{Method: "POST", Host: "lab.example", Path: "/test", Body: []byte("x=1")}
}

func TestPoolJobIsolationAndCleanup(t *testing.T) {
	config := poolConfig(t)
	factory := func(_ context.Context, _ int) (Session, error) {
		return &fakeSession{run: func(ctx context.Context, pcapPath, outputDir string) ([]byte, error) {
			capture, err := os.ReadFile(pcapPath)
			if err != nil || len(capture) < 24 || !bytes.Equal(capture[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
				t.Errorf("job PCAP missing: len=%d err=%v", len(capture), err)
			}
			if runtime.GOOS != "windows" {
				for _, path := range []string{filepath.Dir(pcapPath), outputDir} {
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != 0700 {
						t.Errorf("workdir permission: %s %v %v", path, info, err)
					}
				}
				info, err := os.Stat(pcapPath)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Errorf("PCAP permission: %v %v", info, err)
				}
			}
			return []byte("{\"event_type\":\"flow\"}\n"), nil
		}}, nil
	}
	pool, err := New(context.Background(), config, factory)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	result, err := pool.Inspect(context.Background(), "request-1", sampleRequest())
	if err != nil || result.RequestID != "request-1" || result.WorkerID != 0 || len(result.EVE) == 0 {
		t.Fatalf("wrong result: %#v %v", result, err)
	}
	entries, err := os.ReadDir(config.RootDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("job workdir leaked: %v %v", entries, err)
	}
	if stats := pool.Stats(); stats.InFlightItems != 0 || stats.QueuedBytes != 0 {
		t.Fatalf("resources not released: %#v", stats)
	}
}

func TestPoolQueueAndByteLimits(t *testing.T) {
	config := poolConfig(t)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	factory := func(_ context.Context, _ int) (Session, error) {
		return &fakeSession{
			run: func(ctx context.Context, _, _ string) ([]byte, error) {
				select {
				case started <- struct{}{}:
				default:
				}
				select {
				case <-release:
					return []byte("{\"event_type\":\"flow\"}\n"), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
			close: func() { once.Do(func() { close(release) }) },
		}, nil
	}
	pool, err := New(context.Background(), config, factory)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	first := make(chan error, 1)
	go func() { _, err := pool.Inspect(context.Background(), "first", sampleRequest()); first <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first job never started")
	}
	second := make(chan error, 1)
	go func() { _, err := pool.Inspect(context.Background(), "second", sampleRequest()); second <- err }()
	waitStats(t, pool, func(stats Stats) bool { return stats.QueuedItems == 1 && stats.InFlightItems == 2 })
	if _, err := pool.Inspect(context.Background(), "third", sampleRequest()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full item queue accepted: %v", err)
	}
	once.Do(func() { close(release) })
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	large := sampleRequest()
	large.Body = bytes.Repeat([]byte("x"), 64<<10)
	if _, err := pool.Inspect(context.Background(), "large", large); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("byte limit did not reject PCAP: %v", err)
	}
	if stats := pool.Stats(); stats.InFlightItems != 0 || stats.QueuedBytes != 0 {
		t.Fatalf("limits leaked counters: %#v", stats)
	}
}

func TestPoolCancellationCloseAndFlowIDExhaustion(t *testing.T) {
	config := poolConfig(t)
	factory := func(_ context.Context, _ int) (Session, error) {
		return &fakeSession{run: func(ctx context.Context, _, _ string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}, nil
	}
	pool, err := New(context.Background(), config, factory)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	if _, err := pool.Inspect(ctx, "cancelled", sampleRequest()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not propagated: %v", err)
	}
	waitStats(t, pool, func(stats Stats) bool { return stats.InFlightItems == 0 && stats.QueuedBytes == 0 })
	pool.flowID.Store(^uint32(0))
	if _, err := pool.Inspect(context.Background(), "wrapped", sampleRequest()); !errors.Is(err, ErrFlowIDLimit) {
		t.Fatalf("flowID wrap not rejected: %v", err)
	}
	pool.Close()
	if _, err := pool.Inspect(context.Background(), "after-close", sampleRequest()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed pool accepted job: %v", err)
	}
	if stats := pool.Stats(); stats.InFlightItems != 0 || stats.QueuedBytes != 0 {
		t.Fatalf("close leaked resources: %#v", stats)
	}
}

func TestPoolStartupFailureClosesPreviousSessions(t *testing.T) {
	config := poolConfig(t)
	config.WorkerCount = 2
	closed := false
	factory := func(_ context.Context, workerID int) (Session, error) {
		if workerID == 1 {
			return nil, ErrUnavailable
		}
		return &fakeSession{close: func() { closed = true }}, nil
	}
	if _, err := New(context.Background(), config, factory); !errors.Is(err, ErrUnavailable) || !closed {
		t.Fatalf("partial startup leaked session: err=%v closed=%v", err, closed)
	}
}

func TestReadBoundedEVE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	if _, err := readBoundedEVE(path); !errors.Is(err, ErrOutputUnavailable) {
		t.Fatalf("missing EVE looked clean: %v", err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedEVE(path); !errors.Is(err, ErrOutputUnavailable) {
		t.Fatalf("empty EVE looked clean: %v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxEVEBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedEVE(path); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized EVE looked clean: %v", err)
	}
}

func waitStats(t *testing.T, pool *Pool, ready func(Stats) bool) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if ready(pool.Stats()) {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("stats never reached expected state: %#v", pool.Stats())
		case <-ticker.C:
		}
	}
}
