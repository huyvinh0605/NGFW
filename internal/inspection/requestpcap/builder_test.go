package requestpcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/kltngfw/ngfw/internal/inspection"
)

func sampleRequest() inspection.GateHTTPRequest {
	return inspection.GateHTTPRequest{
		Method: "POST", Host: "lab.example", Path: "/submit", RawQuery: "q=%27+OR+1%3D1",
		HTTPVersion: "HTTP/2.0", Headers: http.Header{
			"Content-Type":  {"application/x-www-form-urlencoded"},
			"User-Agent":    {"ngfw-test"},
			"Authorization": {"Bearer private-token"},
			"Cookie":        {"session=private-cookie"},
			"X-Api-Key":     {"private-key"},
			"X-Trace":       {"one"},
		},
		Body: []byte("id=1%27+OR+1%3D1"),
	}
}

func TestBuildGoldenFiniteConversation(t *testing.T) {
	const flowID = uint32(1)
	first, err := Build(sampleRequest(), flowID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(sampleRequest(), flowID)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("non-deterministic capture: %v", err)
	}
	const goldenSHA256 = "b7e93870224fc5c8350c1c651c53fd9c05b774bb5a8f57d6f38844620b0173ff"
	sum := sha256.Sum256(first)
	if got := hex.EncodeToString(sum[:]); got != goldenSHA256 {
		t.Fatalf("golden hash changed: got %s, want %s", got, goldenSHA256)
	}
	packets := parseCapture(t, first, flowID)
	if len(packets) != 11 {
		t.Fatalf("expected finite 11-packet conversation, got %d", len(packets))
	}
	if packets[0].flags != 0x02 || packets[1].flags != 0x12 || packets[2].flags != 0x10 || packets[len(packets)-1].flags != 0x10 {
		t.Fatalf("incorrect handshake/close: %#v", packets)
	}
	var request []byte
	for _, packet := range packets {
		if packet.sourcePort == flowPort(flowID) {
			request = append(request, packet.body...)
		}
	}
	if !bytes.Contains(request, []byte("POST /submit?q=%27+OR+1%3D1 HTTP/1.1\r\n")) || !bytes.Contains(request, []byte("id=1%27+OR+1%3D1")) {
		t.Fatalf("semantic request missing from capture: %q", request)
	}
	for _, secret := range []string{"private-token", "private-cookie", "private-key", "Authorization:", "Cookie:", "X-Api-Key:"} {
		if bytes.Contains(request, []byte(secret)) {
			t.Fatalf("secret header leaked into PCAP: %s", secret)
		}
	}
}

type capturedPacket struct {
	sourcePort uint16
	seq, ack   uint32
	flags      byte
	body       []byte
}

func flowPort(flowID uint32) uint16 { return uint16(1024 + (flowID & 0x7fff)) }

func parseCapture(t *testing.T, capture []byte, flowID uint32) []capturedPacket {
	t.Helper()
	if len(capture) < 24 || binary.LittleEndian.Uint32(capture[:4]) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(capture[20:24]) != 1 {
		t.Fatal("invalid Ethernet PCAP header")
	}
	var packets []capturedPacket
	for offset := 24; offset < len(capture); {
		if len(capture)-offset < 16 {
			t.Fatal("truncated record header")
		}
		length := int(binary.LittleEndian.Uint32(capture[offset+8 : offset+12]))
		if length != int(binary.LittleEndian.Uint32(capture[offset+12:offset+16])) || length < 54 || length > len(capture)-offset-16 {
			t.Fatal("invalid record length")
		}
		packet := capture[offset+16 : offset+16+length]
		if binary.BigEndian.Uint16(packet[12:14]) != 0x0800 {
			t.Fatal("not IPv4")
		}
		ip := packet[14:34]
		if ip[0] != 0x45 || ip[9] != 6 || int(binary.BigEndian.Uint16(ip[2:4])) != len(packet)-14 || checksum(ip) != 0 {
			t.Fatal("invalid IPv4 packet/checksum")
		}
		tcp := packet[34:]
		pseudo := make([]byte, 12+len(tcp))
		copy(pseudo[:4], ip[12:16])
		copy(pseudo[4:8], ip[16:20])
		pseudo[9] = 6
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
		copy(pseudo[12:], tcp)
		if checksum(pseudo) != 0 {
			t.Fatal("invalid TCP checksum")
		}
		packets = append(packets, capturedPacket{sourcePort: binary.BigEndian.Uint16(tcp[:2]), seq: binary.BigEndian.Uint32(tcp[4:8]), ack: binary.BigEndian.Uint32(tcp[8:12]), flags: tcp[13], body: append([]byte(nil), tcp[20:]...)})
		offset += 16 + length
	}
	if len(packets) < 10 {
		t.Fatal("capture lacks a complete TCP conversation")
	}
	clientSeq, serverSeq := clientSequence, serverSequence
	for _, packet := range packets {
		if packet.sourcePort == flowPort(flowID) {
			if packet.seq != clientSeq || packet.ack != serverSeq && packet.flags&0x10 != 0 {
				t.Fatalf("invalid client seq/ack: %#v", packet)
			}
			clientSeq += uint32(len(packet.body))
			if packet.flags&0x03 != 0 {
				clientSeq++
			}
		} else {
			if packet.seq != serverSeq || packet.ack != clientSeq {
				t.Fatalf("invalid server seq/ack: %#v", packet)
			}
			serverSeq += uint32(len(packet.body))
			if packet.flags&0x03 != 0 {
				serverSeq++
			}
		}
	}
	return packets
}

func TestBuildSegmentsAndBounds(t *testing.T) {
	request := sampleRequest()
	request.Body = bytes.Repeat([]byte("Z"), 4<<20)
	capture, err := Build(request, 2)
	if err != nil || len(capture) > maxCaptureBytes {
		t.Fatalf("bounded max body build: len=%d err=%v", len(capture), err)
	}
	packets := parseCapture(t, capture, 2)
	if len(packets) < 1000 {
		t.Fatalf("large body was not segmented: %d", len(packets))
	}
	request.Body = append(request.Body, 'X')
	if _, err := Build(request, 2); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unbounded body accepted: %v", err)
	}
}

func TestBuildRejectsAmbiguousWireValues(t *testing.T) {
	for name, mutate := range map[string]func(*inspection.GateHTTPRequest){
		"method":       func(v *inspection.GateHTTPRequest) { v.Method = "GE T" },
		"host":         func(v *inspection.GateHTTPRequest) { v.Host = "good\r\nBad: yes" },
		"path":         func(v *inspection.GateHTTPRequest) { v.Path = "/ok\r\nInjected: yes" },
		"query":        func(v *inspection.GateHTTPRequest) { v.RawQuery = "a\r\nb" },
		"header name":  func(v *inspection.GateHTTPRequest) { v.Headers["Bad Header"] = []string{"x"} },
		"header value": func(v *inspection.GateHTTPRequest) { v.Headers["X-Trace"] = []string{"ok\r\nBad: yes"} },
	} {
		t.Run(name, func(t *testing.T) {
			request := sampleRequest()
			mutate(&request)
			if _, err := Build(request, 2); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("invalid wire accepted: %v", err)
			}
		})
	}
	request := sampleRequest()
	request.RawQuery = strings.Repeat("a", maxURLBytes)
	if _, err := Build(request, 2); !errors.Is(err, ErrCaptureLimit) {
		t.Fatalf("long URL accepted: %v", err)
	}
	request = sampleRequest()
	request.Headers.Set("X-Large", strings.Repeat("x", maxHeaderBytes))
	if _, err := Build(request, 2); !errors.Is(err, ErrCaptureLimit) {
		t.Fatalf("large header accepted: %v", err)
	}
	request = sampleRequest()
	request.Host = "é.example"
	if _, err := Build(request, 2); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("non-ASCII host accepted without IDNA normalization: %v", err)
	}
}

func TestBuildFlowIDSeparatesWorkerJobs(t *testing.T) {
	first, err := Build(sampleRequest(), 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(sampleRequest(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("distinct jobs reused an identical synthetic flow")
	}
	firstPacket := first[24+16:]
	secondPacket := second[24+16:]
	if bytes.Equal(firstPacket[26:30], secondPacket[26:30]) && bytes.Equal(firstPacket[34:36], secondPacket[34:36]) {
		t.Fatal("synthetic client IP/port tuple was reused")
	}
}
