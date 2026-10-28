//go:build linux

// The probe runs production reader/runtime/IPC/API libraries in a disposable
// network namespace. EVE input is explicitly synthetic; conntrack is real.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kltngfw/ngfw/internal/config"
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/conntrack"
	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/engine"
	"github.com/kltngfw/ngfw/internal/engineipc"
	"github.com/kltngfw/ngfw/internal/flow"
	"github.com/kltngfw/ngfw/internal/inspection"
	"github.com/kltngfw/ngfw/internal/inspection/eve"
	"github.com/kltngfw/ngfw/internal/management"
	"github.com/kltngfw/ngfw/internal/session"
)

var evidence string

func save(name string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	check(err)
	check(os.WriteFile(filepath.Join(evidence, name), append(data, '\n'), 0600))
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func command(input string, args ...string) string {
	cmd := exec.Command(args[0], args[1:]...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("%v: %v: %s", args, err, output))
	}
	return string(output)
}
func wait(label string, test func() bool) {
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if test() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	panic(label + " timed out")
}

func run() {
	self, err := os.Readlink("/proc/self/ns/net")
	check(err)
	initial, err := os.Readlink("/proc/1/ns/net")
	check(err)
	require(os.Geteuid() == 0 && self != initial, "run as root in a disposable network namespace, never the appliance namespace")
	check(os.MkdirAll(evidence, 0700))
	save("isolation.json", map[string]any{"current_netns": self, "appliance_netns": initial, "scope": "synthetic EVE test adapter; real Linux conntrack and production runtime/IPC/API libraries; no sensor process"})
	command("", "ip", "link", "set", "lo", "up")
	command("", "sysctl", "-qw", "net.netfilter.nf_conntrack_timestamp=1")
	command("", "sysctl", "-qw", "net.netfilter.nf_conntrack_acct=1")
	command("table inet m3_source_probe {\n chain output {\n type filter hook output priority 0; policy accept;\n ct state new counter\n }\n}\n", "nft", "-f", "-")
	value := config.Defaults()
	value.Inspection = &domain.InspectionConfig{Enabled: true, Limits: domain.DefaultInspectionLimits()}
	value.Inspection.Limits.EVELineBytes = 4096
	value.Inspection.Limits.SecurityEvents = 32
	value.Inspection.Limits.SecurityEventBytes = 65536
	value.Inspection.Limits.RecentSessions = 2
	value.Inspection.Limits.RecentSessionTTLSeconds = 1
	value.Profiles = []domain.SecurityProfile{{ID: "ids", IDSIPSEnabled: true, TLSMode: domain.TLSMetadata, Inspection: &domain.InspectionProfile{Mode: domain.InspectionModeIDS, FailMode: "OPEN", RulesetID: config.BuiltinM3RulesetID}}}
	value.Policies = []domain.SecurityPolicy{{ID: "probe", Priority: 10, SecurityProfileID: "ids", Action: domain.DecisionAllow, Scope: "SESSION", Enabled: true}}
	manager, err := config.NewManager(filepath.Join(evidence, "state"), value)
	check(err)
	program, err := connectivity.CompileM3(value, manager.Version().Version)
	check(err)
	source, err := conntrack.NewLinuxSource(self)
	check(err)
	limits := session.DefaultRuntimeLimits()
	limits.MaxSessions = 128
	runtime := engine.NewRuntime(source, program, manager.Version().Version, limits)
	path := filepath.Join(evidence, "input-eve.jsonl")
	check(os.WriteFile(path, nil, 0600))
	reader := eve.NewReader(path, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "probe-epoch", Mode: domain.InspectionModeIDS}, eve.FileCheckpointStore{Path: filepath.Join(evidence, "checkpoint.json")})
	reader.LineBytes = 4096
	reader.PollInterval = 5 * time.Millisecond
	path2 := filepath.Join(evidence, "input-eve-next-epoch.jsonl")
	check(os.WriteFile(path2, nil, 0600))
	reader2 := eve.NewReader(path2, inspection.SourcePosition{SensorID: "ids", SensorEpoch: "probe-epoch-2", Mode: domain.InspectionModeIDS}, eve.FileCheckpointStore{Path: filepath.Join(evidence, "checkpoint-next-epoch.json")})
	reader2.LineBytes = 4096
	reader2.PollInterval = 5 * time.Millisecond
	coordinator := engine.NewInspectionRuntimeWithScope(runtime, value.Inspection.Limits, []inspection.EventSource{reader, reader2}, flow.Scope{NetworkNamespace: self})
	runtime.SetInspectionRuntime(coordinator)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	check(runtime.Start(ctx))
	defer runtime.Stop()
	check(coordinator.Start(ctx))
	defer coordinator.Stop()
	service := engine.NewRuntimeServiceAdapter(runtime, manager, nil)
	socketPath := filepath.Join(evidence, "engine.sock")
	server := engineipc.NewRuntimeServer(socketPath, service)
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(ctx) }()
	wait("IPC listener", func() bool { _, err := os.Stat(socketPath); return err == nil })
	client := engineipc.NewRuntimeClient(socketPath)
	var secret [32]byte
	_, err = rand.Read(secret[:])
	check(err)
	token := hex.EncodeToString(secret[:])
	api := management.NewRuntimeAPI(client, manager, token, slog.New(slog.NewTextHandler(io.Discard, nil)))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	check(err)
	httpServer := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: time.Second}
	go httpServer.Serve(listener)
	defer httpServer.Close()
	fetch := func(label, path string) {
		request, err := http.NewRequest("GET", "http://"+listener.Addr().String()+path, nil)
		check(err)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
		check(err)
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		check(err)
		require(response.StatusCode == 200, "API status "+response.Status)
		var body any
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		check(decoder.Decode(&body))
		save(label, body)
	}
	appendInput := func(data string) {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		check(err)
		_, err = file.WriteString(data)
		check(err)
		check(file.Close())
	}
	record := func(signature int, tuple *domain.Tuple, observed time.Time, flowID uint64, action string) string {
		body := map[string]any{"timestamp": observed.UTC().Format(time.RFC3339Nano), "event_type": "alert", "flow_id": flowID, "app_proto": "http", "alert": map[string]any{"signature_id": signature, "signature": "isolated lab source probe", "action": action}}
		if tuple != nil {
			body["src_ip"] = tuple.SrcIP.String()
			body["src_port"] = tuple.SrcPort
			body["dest_ip"] = tuple.DstIP.String()
			body["dest_port"] = tuple.DstPort
			body["proto"] = "TCP"
		}
		data, err := json.Marshal(body)
		check(err)
		return string(data) + "\n"
	}
	find := func(signature uint32) (domain.ThreatEvent, bool) {
		page := coordinator.SecurityEvents().Query(domain.SecurityQuery{Limit: 200})
		for _, event := range page.Items {
			if event.SignatureID == signature {
				return event, true
			}
		}
		return domain.ThreatEvent{}, false
	}

	// M3-09: bad lines, an oversized line and partial writes must not stop
	// processing. The missing-tuple blocked IDS record remains unenforced.
	appendInput("{broken\n" + strings.Repeat("x", 5000) + "\n{\"event_type\":\"future-type\"}\n")
	appendInput(record(9900209, nil, time.Now(), 9, "blocked"))
	partial := strings.TrimSuffix(record(9900210, nil, time.Now(), 10, "allowed"), "\n")
	appendInput(partial)
	time.Sleep(40 * time.Millisecond)
	_, exists := find(9900210)
	require(!exists, "partial EVE line emitted before newline")
	appendInput("\n")
	wait("good alert after malformed EVE", func() bool { _, ok := find(9900210); return ok })
	stats := reader.Snapshot().ReaderStats
	require(stats["invalid"] >= 1 && stats["oversize"] >= 1 && stats["ignored"] >= 1, "reader loss/error counters missing")
	bad, ok := find(9900209)
	require(ok && bad.Verdict == domain.VerdictUnknown && bad.CorrelationState == domain.CorrelationUncorrelated && bad.Enforcement.Status == domain.EnforcementNotRequested && bad.Severity == domain.SeverityUnknown, "missing evidence promoted to clean/blocked")
	fetch("M3-09-health.json", "/api/v1/inspection/health")
	fetch("M3-09-events.json", "/api/v1/security/events?limit=200")
	save("M3-09-result.json", map[string]any{"id": "M3-09", "status": "PASS", "reader_stats": stats, "scope": "isolated malformed source -> real reader/reducer -> Unix IPC -> authenticated API, real Linux conntrack source"})
	fmt.Println("PASS M3-09: malformed/oversize/partial EVE stays bounded; runtime and authenticated API continue; missing fields never claim enforcement")

	// M3-18: emit before the real kernel connection exists, then resolve it
	// once conntrack reports its exact identity; later attach to closed history.
	listen, err := net.Listen("tcp4", "127.0.0.1:0")
	check(err)
	defer listen.Close()
	local, err := net.Listen("tcp4", "127.0.0.2:0")
	check(err)
	port := local.Addr().(*net.TCPAddr).Port
	check(local.Close())
	destination := listen.Addr().(*net.TCPAddr)
	tuple := domain.Tuple{Family: domain.FamilyIPv4, Protocol: 6, SrcIP: netipAddr("127.0.0.2"), SrcPort: uint16(port), DstIP: netipAddr("127.0.0.1"), DstPort: uint16(destination.Port)}
	observed := time.Now().UTC()
	appendInput(record(9900218, &tuple, observed, 18, "allowed"))
	wait("pre-CT event retained", func() bool { _, ok := find(9900218); return ok })
	before, _ := find(9900218)
	require(before.SessionID == "", "event correlated before CT exists")
	accepted := make(chan net.Conn, 1)
	go func() { connection, _ := listen.Accept(); accepted <- connection }()
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: port}}
	connection, err := dialer.Dial("tcp4", listen.Addr().String())
	check(err)
	peer := <-accepted
	require(peer != nil, "server accept failed")
	defer connection.Close()
	defer peer.Close()
	_, err = connection.Write([]byte("live-kernel-probe"))
	check(err)
	wait("event-before-CT correlation", func() bool {
		event, ok := find(9900218)
		return ok && event.CorrelationState == domain.CorrelationCorrelated
	})
	correlated, _ := find(9900218)
	require(before.EventID == correlated.EventID, "correlation retry created a second physical event ID")
	active, ok := runtime.Store.Get(correlated.SessionID)
	require(ok && active.Identity.ID != 0 && active.Identity.KernelStart != 0, "correlated without trustworthy real kernel start")
	save("M3-18-live-session.json", active)
	if tcp, ok := connection.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	check(connection.Close())
	check(peer.Close())
	// Delete only this test flow, never flush the conntrack table.
	cmd := exec.Command("conntrack", "-D", "-p", "tcp", "--orig-src", "127.0.0.2", "--orig-dst", "127.0.0.1", "--sport", fmt.Sprint(port), "--dport", fmt.Sprint(destination.Port))
	_, _ = cmd.CombinedOutput()
	wait("closed canonical session", func() bool { _, ok := runtime.Store.Get(active.SessionID); return !ok })
	appendInput(record(9900219, &tuple, observed, 18, "allowed"))
	wait("delayed event on closed session", func() bool {
		event, ok := find(9900219)
		return ok && event.SessionID == active.SessionID && event.CorrelationState == domain.CorrelationCorrelated
	})
	_, reopened := runtime.Store.Get(active.SessionID)
	require(!reopened, "late alert reopened a closed session")
	// Reuse the exact TCP tuple and Suricata flow ID in a new sensor epoch.
	// While the old closed record still overlaps, correlation must be ambiguous.
	newLocal, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: port})
	check(err)
	check(newLocal.Close())
	secondEventAt := time.Now().UTC()
	appendSecond := func(signature int, at time.Time) {
		data := record(signature, &tuple, at, 18, "allowed")
		file, err := os.OpenFile(path2, os.O_APPEND|os.O_WRONLY, 0600)
		check(err)
		_, err = file.WriteString(data)
		check(err)
		check(file.Close())
	}
	accepted2 := make(chan net.Conn, 1)
	go func() { connection, _ := listen.Accept(); accepted2 <- connection }()
	dialer2 := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2"), Port: port}, Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return optionErr
	}}
	connection2, err := dialer2.Dial("tcp4", listen.Addr().String())
	check(err)
	peer2 := <-accepted2
	require(peer2 != nil, "reused-tuple server accept failed")
	_, err = connection2.Write([]byte("new-incarnation"))
	check(err)
	appendSecond(9900220, secondEventAt)
	wait("ambiguous tuple/flow reuse event", func() bool { _, ok := find(9900220); return ok })
	ambiguous, _ := find(9900220)
	newActive, ok := runtime.Store.Get(ambiguous.SessionID)
	require(ambiguous.CorrelationState == domain.CorrelationAmbiguous && (!ok || newActive.SessionID != active.SessionID), "reused flow ID selected the previous incarnation")
	secondID := ""
	secondKernelID := uint32(0)
	for _, item := range runtime.Store.List() {
		if item.OriginalTuple == tuple && item.SessionID != active.SessionID {
			secondID = item.SessionID
			secondKernelID = item.Identity.ID
		}
	}
	require(secondID != "", "new kernel incarnation was not tracked")
	if tcp, ok := connection2.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
	}
	_ = connection2.Close()
	_ = peer2.Close()
	cmd = exec.Command("conntrack", "-D", "-p", "tcp", "--orig-src", "127.0.0.2", "--orig-dst", "127.0.0.1", "--sport", fmt.Sprint(port), "--dport", fmt.Sprint(destination.Port))
	_, _ = cmd.CombinedOutput()
	wait("second incarnation closed", func() bool { _, ok := runtime.Store.Get(secondID); return !ok })
	time.Sleep(2100 * time.Millisecond)
	appendSecond(9900221, secondEventAt)
	wait("expired old event", func() bool { _, ok := find(9900221); return ok })
	lateReuse, _ := find(9900221)
	require(lateReuse.CorrelationState != domain.CorrelationCorrelated || lateReuse.SessionID != active.SessionID && lateReuse.SessionID != secondID, "delayed old flow event rebound to a reused tuple")
	save("M3-19-result.json", map[string]any{"id": "M3-19", "status": "PARTIAL", "old_session_id": active.SessionID, "new_session_id": secondID, "old_conntrack_id": active.Identity.ID, "new_conntrack_id": secondKernelID, "same_original_tuple": true, "same_sensor_flow_id": 18, "new_sensor_epoch": "probe-epoch-2", "overlapping_tuple_state": ambiguous.CorrelationState, "delayed_old_event_state": lateReuse.CorrelationState, "delayed_event_did_not_reopen_session": true, "scope": "real conntrack tuple reuse; conntrack IDs recorded but kernel did not promise ID reuse"})
	fetch("M3-18-events.json", "/api/v1/security/events?limit=200")
	save("M3-18-result.json", map[string]any{"id": "M3-18", "status": "PASS", "kernel_identity": active.Identity, "same_event_id_updated": before.EventID == correlated.EventID, "closed_session_not_reopened": true})
	fmt.Println("PASS M3-18: event-before-real-CT resolves the same event ID; delayed alert attaches to closed history without reopening")
	fmt.Println("PASS M3-19 tuple/flow reuse: old session is not rebound; ambiguous and delayed evidence stays non-correlated")
	time.Sleep(1100 * time.Millisecond)
	runtime.Store.PruneClosed(time.Now())
	recent, _ := runtime.Store.ResolveCandidates(flow.Key{Scope: flow.Scope{NetworkNamespace: self}, Tuple: tuple}, observed, 8)
	save("M3-33-recent-history.json", map[string]any{"configured_ttl_seconds": 1, "remaining": len(recent), "stats": runtime.Stats()})
	require(len(recent) == 0, "configured recent_session_ttl_seconds was not applied to canonical closed history")
	fetch("final-health.json", "/api/v1/inspection/health")
	save("result.json", map[string]any{"status": "PASS", "cases": []string{"M3-09", "M3-18", "M3-19 tuple/flow reuse"}, "scope": "isolated synthetic EVE source integration, real kernel CT and real IPC/API; not a live Suricata sensor test"})
}

func netipAddr(value string) netip.Addr { return netip.MustParseAddr(value) }

func main() {
	flag.StringVar(&evidence, "evidence-dir", "", "absolute output directory inside disposable lab namespace")
	var activationPhase string
	flag.StringVar(&activationPhase, "activation-phase", "", "run isolated activation crash probe")
	flag.Parse()
	if activationPhase != "" {
		defer func() {
			if failure := recover(); failure != nil {
				_ = os.MkdirAll(evidence, 0700)
				writeActivationJSON(filepath.Join(evidence, "result.json"), map[string]any{"status": "FAIL", "error": fmt.Sprint(failure)})
				fmt.Fprintln(os.Stderr, "FAIL:", failure)
				os.Exit(1)
			}
		}()
		runActivationProbe(evidence, activationPhase)
		return
	}
	if !filepath.IsAbs(evidence) || filepath.Dir(evidence) != "/tmp" || !strings.HasPrefix(filepath.Base(evidence), "ngfw-m3-source-") {
		fmt.Fprintln(os.Stderr, "--evidence-dir requires a fresh /tmp/ngfw-m3-source-* directory")
		os.Exit(2)
	}
	if _, err := os.Lstat(evidence); !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "evidence directory must not already exist")
		os.Exit(2)
	}
	defer func() {
		if failure := recover(); failure != nil {
			_ = os.MkdirAll(evidence, 0700)
			save("result.json", map[string]any{"status": "FAIL", "error": fmt.Sprint(failure)})
			fmt.Fprintln(os.Stderr, "FAIL:", failure)
			os.Exit(1)
		}
	}()
	run()
}
