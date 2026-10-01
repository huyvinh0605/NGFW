package requestworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection/suricata_socket"
)

const maxEVEBytes = 1 << 20

var ErrOutputUnavailable = errors.New("SURICATA_OUTPUT_UNAVAILABLE")

type ProcessConfig struct {
	Binary         string
	ConfigPath     string
	RootDir        string
	StartupTimeout time.Duration
	PollInterval   time.Duration
}

type suricataSession struct {
	command *exec.Cmd
	client  *suricata_socket.Client
	done    chan struct{}
	closed  atomic.Bool
	once    sync.Once
	poll    time.Duration
}

// ProductionFactory starts one persistent Suricata Unix-socket process per
// worker, separate from the M3 live sensor. Files remain under a trusted root.
func ProductionFactory(config ProcessConfig) (SessionFactory, error) {
	if config.Binary == "" || !filepath.IsAbs(config.ConfigPath) || !filepath.IsAbs(config.RootDir) {
		return nil, ErrInvalidConfig
	}
	if config.StartupTimeout <= 0 || config.StartupTimeout > 30*time.Second {
		config.StartupTimeout = 10 * time.Second
	}
	if config.PollInterval <= 0 || config.PollInterval > time.Second {
		config.PollInterval = 25 * time.Millisecond
	}
	return func(ctx context.Context, workerID int) (Session, error) {
		if ctx == nil || workerID < 0 || workerID >= 4 {
			return nil, ErrInvalidConfig
		}
		root := filepath.Join(config.RootDir, fmt.Sprintf("worker-%d", workerID))
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return nil, ErrInvalidConfig
		}
		socketPath := filepath.Join(root, "suricata.sock")
		if len(socketPath) >= 100 {
			return nil, ErrInvalidConfig
		}
		if info, err := os.Lstat(socketPath); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, ErrInvalidConfig
			}
			if existing, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond); dialErr == nil {
				_ = existing.Close()
				return nil, ErrUnavailable // a different worker still owns this socket
			}
			if err := os.Remove(socketPath); err != nil {
				return nil, errors.Join(ErrUnavailable, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(ErrUnavailable, err)
		}
		command := exec.Command(config.Binary, "-c", config.ConfigPath, "--unix-socket="+socketPath, "-l", root)
		command.Stdout, command.Stderr = io.Discard, io.Discard
		if err := command.Start(); err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		session := &suricataSession{command: command, done: make(chan struct{}), poll: config.PollInterval}
		go func() { _ = command.Wait(); close(session.done) }()
		startupCtx, cancel := context.WithTimeout(ctx, config.StartupTimeout)
		defer cancel()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-session.done:
				_ = session.Close()
				return nil, ErrUnavailable
			case <-startupCtx.Done():
				_ = session.Close()
				return nil, errors.Join(ErrUnavailable, startupCtx.Err())
			default:
			}
			client, err := suricata_socket.Dial(startupCtx, socketPath, 2*time.Second)
			if err == nil {
				session.client = client
				return session, nil
			}
			if !errors.Is(err, suricata_socket.ErrUnavailable) {
				_ = session.Close()
				return nil, errors.Join(ErrUnavailable, err)
			}
			select {
			case <-ticker.C:
			case <-startupCtx.Done():
			}
		}
	}, nil
}

func (session *suricataSession) Run(ctx context.Context, pcapPath, outputDir string) ([]byte, error) {
	if session == nil || ctx == nil || session.closed.Load() || session.client == nil {
		return nil, ErrUnavailable
	}
	select {
	case <-session.done:
		return nil, ErrUnavailable
	default:
	}
	if err := session.client.Submit(ctx, pcapPath, outputDir); err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	// Submission acknowledgement plus drained current/list/count is required.
	// Neither a fixed sleep nor an empty EVE file is evidence of inspection.
	ticker := time.NewTicker(session.poll)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case <-session.done:
			return nil, ErrUnavailable
		default:
		}
		current, err := session.client.Current(ctx)
		if err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		queued, err := session.client.Queued(ctx)
		if err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		depth, err := session.client.QueueDepth(ctx)
		if err != nil {
			return nil, errors.Join(ErrUnavailable, err)
		}
		if current != "" && current != pcapPath {
			return nil, ErrUnavailable
		}
		for _, path := range queued {
			if path != pcapPath {
				return nil, ErrUnavailable
			}
		}
		if current == "" && len(queued) == 0 && depth == 0 {
			eve, err := readBoundedEVE(filepath.Join(outputDir, "eve.json"))
			if err == nil {
				return eve, nil
			}
			if !errors.Is(err, ErrOutputUnavailable) {
				return nil, err
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-session.done:
			return nil, ErrUnavailable
		}
	}
}

func (session *suricataSession) Close() error {
	if session == nil {
		return nil
	}
	session.once.Do(func() {
		session.closed.Store(true)
		if session.command != nil && session.command.Process != nil {
			_ = session.command.Process.Kill()
		}
		if session.client != nil {
			_ = session.client.Close()
		}
		if session.done != nil {
			<-session.done
		}
	})
	return nil
}

func readBoundedEVE(path string) ([]byte, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrOutputUnavailable
	}
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxEVEBytes+1))
	if err != nil {
		return nil, errors.Join(ErrUnavailable, err)
	}
	if len(contents) == 0 {
		return nil, ErrOutputUnavailable
	}
	if len(contents) > maxEVEBytes {
		return nil, ErrUnavailable
	}
	return contents, nil
}
