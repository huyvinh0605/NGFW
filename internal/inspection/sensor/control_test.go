package sensor

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlClientNegotiatesBeforeCommandAndHandlesFragmentedReply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		decoder := json.NewDecoder(connection)
		var handshake map[string]any
		if err := decoder.Decode(&handshake); err != nil {
			done <- err
			return
		}
		if handshake["version"] != "0.1" {
			done <- &testControlError{"missing protocol negotiation"}
			return
		}
		_, _ = connection.Write([]byte(`{"ret`))
		_, _ = connection.Write([]byte(`urn":"OK"}`))
		var command map[string]any
		if err := decoder.Decode(&command); err != nil {
			done <- err
			return
		}
		if command["command"] != "uptime" {
			done <- &testControlError{"unexpected command"}
			return
		}
		_, _ = connection.Write([]byte(`{"message":12`))
		_, _ = connection.Write([]byte(`3,"return":"OK"}`))
		done <- nil
	}()

	client := ControlClient{SocketPath: path, Timeout: time.Second, MaxReplyBytes: 1024}
	probe, err := client.Probe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !probe.OK || probe.Message != "123" {
		t.Fatalf("unexpected control result: %#v", probe)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestControlClientRejectsUnboundedReply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		decoder := json.NewDecoder(connection)
		var value map[string]any
		_ = decoder.Decode(&value)
		_, _ = connection.Write([]byte(`{"return":"OK"}`))
		_ = decoder.Decode(&value)
		_, _ = connection.Write([]byte(`{"return":"OK","message":"` + strings.Repeat("x", 2048) + `"}`))
	}()
	client := ControlClient{SocketPath: path, Timeout: time.Second, MaxReplyBytes: 128}
	if _, err := client.Probe(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected bounded response error, got %v", err)
	}
}

type testControlError struct{ text string }

func (e *testControlError) Error() string { return e.text }
