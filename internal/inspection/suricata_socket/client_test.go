package suricata_socket

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const requiredCommands = `["pcap-file","pcap-current","pcap-file-list","pcap-file-number"]`

func TestDialFragmentedResponsesAndCommands(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "suricata.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("Unix sockets are unavailable in this local environment: %v", err)
	}
	defer listener.Close()
	submitted := make(chan map[string]string, 1)
	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				serverDone <- err
				return
			}
			var request struct {
				Version   string            `json:"version"`
				Command   string            `json:"command"`
				Arguments map[string]string `json:"arguments"`
			}
			if err := json.Unmarshal(line, &request); err != nil {
				serverDone <- err
				return
			}
			message := `null`
			switch request.Command {
			case "":
				if request.Version != protocolVersion {
					serverDone <- ErrProtocol
					return
				}
			case "command-list":
				message = requiredCommands
			case "pcap-file":
				submitted <- request.Arguments
				message = `"added"`
			case "pcap-current":
				message = `"/tmp/work/one.pcap"`
			case "pcap-file-list":
				message = `{"count":1,"files":["/tmp/work/one.pcap"]}`
			case "pcap-file-number":
				message = `1`
			default:
				serverDone <- ErrProtocol
				return
			}
			response := []byte(`{"return":"OK","message":` + message + `}` + "\n")
			for _, octet := range response { // prove byte-fragmented responses are reassembled
				if _, err := connection.Write([]byte{octet}); err != nil {
					serverDone <- err
					return
				}
			}
		}
	}()
	client, err := Dial(context.Background(), socketPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	job := t.TempDir()
	pcap := filepath.Join(job, "request.pcap")
	if err := client.Submit(context.Background(), pcap, job); err != nil {
		t.Fatal(err)
	}
	paths := <-submitted
	if paths["filename"] != pcap || paths["output-dir"] != job {
		t.Fatalf("wrong pcap arguments: %#v", paths)
	}
	if current, err := client.Current(context.Background()); err != nil || current != "/tmp/work/one.pcap" {
		t.Fatalf("current=%q err=%v", current, err)
	}
	if files, err := client.Queued(context.Background()); err != nil || len(files) != 1 || files[0] != "/tmp/work/one.pcap" {
		t.Fatalf("files=%v err=%v", files, err)
	}
	if depth, err := client.QueueDepth(context.Background()); err != nil || depth != 1 {
		t.Fatalf("depth=%d err=%v", depth, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("fake server exited without a close/read result")
		}
	case <-time.After(time.Second):
		t.Fatal("fake server did not exit after client close")
	}
}

func TestClientRejectsMissingCapabilities(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "suricata.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("Unix sockets are unavailable in this local environment: %v", err)
	}
	defer listener.Close()
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		_, _ = reader.ReadBytes('\n')
		_, _ = connection.Write([]byte(`{"return":"OK"}` + "\n"))
		_, _ = reader.ReadBytes('\n')
		_, _ = connection.Write([]byte(`{"return":"OK","message":["pcap-file"]}` + "\n"))
	}()
	if _, err := Dial(context.Background(), socketPath, time.Second); !errors.Is(err, ErrProtocol) {
		t.Fatalf("missing pcap commands accepted: %v", err)
	}
}

func TestClientResponseLimitAndCancellation(t *testing.T) {
	for name, response := range map[string]string{
		"oversized": `{"return":"OK","message":"` + strings.Repeat("x", maxResponseBytes) + `"}`,
		"malformed": `{"return":"maybe"}`,
		"rejected":  `{"return":"NOK","message":"not allowed"}`,
	} {
		t.Run(name, func(t *testing.T) {
			clientConnection, serverConnection := net.Pipe()
			defer serverConnection.Close()
			client := &Client{conn: clientConnection, timeout: time.Second}
			defer client.Close()
			go func() {
				_, _ = bufio.NewReader(serverConnection).ReadBytes('\n')
				_, _ = serverConnection.Write([]byte(response))
			}()
			_, err := client.CommandList(context.Background())
			want := ErrProtocol
			if name == "oversized" {
				want = ErrResponseLimit
			}
			if name == "rejected" {
				want = ErrRejected
			}
			if !errors.Is(err, want) {
				t.Fatalf("want %v, got %v", want, err)
			}
		})
	}
	clientConnection, serverConnection := net.Pipe()
	defer serverConnection.Close()
	client := &Client{conn: clientConnection, timeout: time.Second}
	defer client.Close()
	go func() {
		_, _ = bufio.NewReader(serverConnection).ReadBytes('\n')
		_, _ = io.Copy(io.Discard, serverConnection)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.CommandList(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("timeout was not unavailable: %v", err)
	}
	if _, err := client.CommandList(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("desynchronized connection was reused: %v", err)
	}
}

func TestClientConcurrentCallsSerialize(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer serverConnection.Close()
	client := &Client{conn: clientConnection, timeout: time.Second}
	defer client.Close()
	go func() {
		reader := bufio.NewReader(serverConnection)
		for i := 0; i < 16; i++ {
			if _, err := reader.ReadBytes('\n'); err != nil {
				return
			}
			_, _ = serverConnection.Write([]byte(`{"return":"OK","message":` + requiredCommands + `}`))
		}
	}()
	var group sync.WaitGroup
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			commands, err := client.CommandList(context.Background())
			if err != nil || len(commands) != 4 {
				t.Errorf("concurrent command lost response: %v %v", commands, err)
			}
		}()
	}
	group.Wait()
}

func TestClientRejectsUnownedPathsAndNullQueueState(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer serverConnection.Close()
	client := &Client{conn: clientConnection, timeout: time.Second}
	defer client.Close()
	if err := client.Submit(context.Background(), "relative.pcap", t.TempDir()); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("relative path accepted: %v", err)
	}
	go func() {
		reader := bufio.NewReader(serverConnection)
		for i := 0; i < 2; i++ {
			_, _ = reader.ReadBytes('\n')
			_, _ = serverConnection.Write([]byte(`{"return":"OK","message":null}`))
		}
	}()
	if _, err := client.Queued(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown queue list interpreted as empty: %v", err)
	}
	if _, err := client.QueueDepth(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown queue depth interpreted as zero: %v", err)
	}
}
