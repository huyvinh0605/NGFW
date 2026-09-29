package requestworker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection/suricata_socket"
)

func TestSuricataSessionRequiresDrainAndJobLocalEVE(t *testing.T) {
	for name, scenario := range map[string]string{
		"complete":       "complete",
		"missing output": "missing",
		"other flow":     "other",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			socketPath := filepath.Join(root, "suricata.sock")
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				t.Skipf("Unix sockets unavailable locally: %v", err)
			}
			defer listener.Close()
			var currentCalls atomic.Int32
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				defer connection.Close()
				reader := bufio.NewReader(connection)
				pcap := ""
				for {
					line, err := reader.ReadBytes('\n')
					if err != nil {
						return
					}
					var request struct {
						Command   string            `json:"command"`
						Arguments map[string]string `json:"arguments"`
					}
					if json.Unmarshal(line, &request) != nil {
						return
					}
					message := any(nil)
					switch request.Command {
					case "command-list":
						message = []string{"pcap-file", "pcap-current", "pcap-file-list", "pcap-file-number"}
					case "pcap-file":
						pcap = request.Arguments["filename"]
						if scenario == "complete" {
							_ = os.WriteFile(filepath.Join(request.Arguments["output-dir"], "eve.json"), []byte("{\"event_type\":\"flow\"}\n"), 0600)
						}
						message = "added"
					case "pcap-current":
						currentCalls.Add(1)
						if scenario == "other" {
							message = "/wrong-job.pcap"
						} else if currentCalls.Load() == 1 {
							message = pcap
						} else {
							message = ""
						}
					case "pcap-file-list":
						message = map[string]any{"count": 0, "files": []string{}}
					case "pcap-file-number":
						message = 0
					}
					response, _ := json.Marshal(map[string]any{"return": "OK", "message": message})
					_, _ = connection.Write(append(response, '\n'))
				}
			}()
			client, err := suricata_socket.Dial(context.Background(), socketPath, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close(); <-serverDone }()
			session := &suricataSession{client: client, done: make(chan struct{}), poll: time.Millisecond}
			output := filepath.Join(root, "output")
			if err := os.Mkdir(output, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
			defer cancel()
			eve, err := session.Run(ctx, filepath.Join(root, "request.pcap"), output)
			switch scenario {
			case "complete":
				if err != nil || len(eve) == 0 || currentCalls.Load() < 2 {
					t.Fatalf("premature or failed completion: polls=%d EVE=%q err=%v", currentCalls.Load(), eve, err)
				}
			case "missing":
				if !errors.Is(err, context.DeadlineExceeded) || len(eve) != 0 {
					t.Fatalf("missing EVE treated as clean: %q %v", eve, err)
				}
			case "other":
				if !errors.Is(err, ErrUnavailable) || len(eve) != 0 {
					t.Fatalf("other job state treated as own: %q %v", eve, err)
				}
			}
		})
	}
}
