package m3fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

func TestMarkerPCAPIsDeterministicAndMarkerSpansSegments(t *testing.T) {
	data, err := os.ReadFile("marker-http.pcap")
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	const expected = "a5bfb017103f90d4b3e6f2f18f2815420c31a3e59dab58141edd9e04d4f08df7"
	if digest != expected {
		t.Fatalf("fixture checksum=%s want=%s; regenerate and update the reviewed checksum together", digest, expected)
	}
	if len(data) < 24 || binary.LittleEndian.Uint32(data[:4]) != 0xa1b2c3d4 {
		t.Fatal("invalid PCAP global header")
	}
	offset := 24
	var payloads [][]byte
	for offset < len(data) {
		if offset+16 > len(data) {
			t.Fatal("truncated PCAP record header")
		}
		length := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
		offset += 16
		if length < 54 || offset+length > len(data) {
			t.Fatal("invalid PCAP record length")
		}
		frame := data[offset : offset+length]
		offset += length
		if binary.BigEndian.Uint16(frame[34:36]) == 50000 && len(frame) > 54 {
			payloads = append(payloads, append([]byte(nil), frame[54:]...))
		}
	}
	if len(payloads) != 2 {
		t.Fatalf("client payload segments=%d want=2", len(payloads))
	}
	marker := []byte("NGFW_M3_TEST_fixture")
	if bytes.Contains(payloads[0], marker) || bytes.Contains(payloads[1], marker) {
		t.Fatal("marker no longer exercises TCP stream reassembly")
	}
	if !bytes.Contains(append(append([]byte(nil), payloads[0]...), payloads[1]...), marker) {
		t.Fatal("reassembled client stream does not contain marker")
	}
}
