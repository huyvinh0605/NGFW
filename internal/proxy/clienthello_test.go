package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/kltngfw/ngfw/internal/inspection"
)

func testTLSRecord(payload []byte) []byte {
	record := []byte{22, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	return append(record, payload...)
}

func testClientHello(sni bool) []byte {
	extensions := make([]byte, 0)
	add := func(kind uint16, body []byte) {
		header := []byte{0, 0, 0, 0}
		binary.BigEndian.PutUint16(header[:2], kind)
		binary.BigEndian.PutUint16(header[2:], uint16(len(body)))
		extensions = append(extensions, header...)
		extensions = append(extensions, body...)
	}
	if sni {
		name := []byte("api.example.com")
		entry := append([]byte{0, 0, byte(len(name))}, name...)
		add(0, append([]byte{0, byte(len(entry))}, entry...))
	}
	protocols := []byte{2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	add(16, append([]byte{0, byte(len(protocols))}, protocols...))
	add(43, []byte{4, 3, 4, 3, 3})
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0)                // session ID
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression methods
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	hello := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hello, body...)
}

func TestPeekClientHelloSplitRecordsPreservesBytes(t *testing.T) {
	hello := testClientHello(true)
	first := testTLSRecord(hello[:9])
	second := testTLSRecord(append(append([]byte{}, hello[9:]...), 0, 0))
	wire := append(first, second...)
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	done := make(chan error, 1)
	go func() {
		for position := 0; position < len(wire); position += 3 {
			end := min(position+3, len(wire))
			if _, err := client.Write(wire[position:end]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	metadata, buffered, err := PeekClientHello(context.Background(), proxy, 64<<10, time.Second)
	if err != nil || !metadata.Available || metadata.SNI != "api.example.com" || metadata.ALPN != "h2" || metadata.TLSVersion != "0x0304" || !bytes.Equal(buffered, wire) {
		t.Fatalf("fragmented peek lost metadata or wire bytes: %+v len=%d err=%v", metadata, len(buffered), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	parsed, err := inspection.ParseTLSClientHello(wire)
	if err != nil || parsed.SNI != metadata.SNI {
		t.Fatalf("shared TLS parser rejected fragmented records: %+v, %v", parsed, err)
	}
}

func TestPeekClientHelloNoSNIIsObservableNotInvented(t *testing.T) {
	wire := testTLSRecord(testClientHello(false))
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	go func() { _, _ = client.Write(wire) }()
	metadata, buffered, err := PeekClientHello(context.Background(), proxy, len(wire), time.Second)
	if err != nil || !metadata.Available || metadata.SNI != "" || metadata.ALPN != "h2" || !bytes.Equal(buffered, wire) {
		t.Fatalf("missing SNI was fabricated or rejected: %+v %v", metadata, err)
	}
}

func TestPeekRealGoTLSClientHello(t *testing.T) {
	client, proxy := net.Pipe()
	defer proxy.Close()
	secureClient := tls.Client(client, &tls.Config{ServerName: "api.example.com", NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	defer secureClient.Close()
	done := make(chan error, 1)
	go func() { done <- secureClient.Handshake() }()
	metadata, buffered, err := PeekClientHello(context.Background(), proxy, 64<<10, time.Second)
	if err != nil || !metadata.Available || metadata.SNI != "api.example.com" || metadata.ALPN != "h2" || len(buffered) == 0 {
		t.Fatalf("Go TLS ClientHello parsing failed: %+v len=%d err=%v", metadata, len(buffered), err)
	}
	_ = proxy.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TLS client did not stop")
	}
}

func TestPeekClientHelloMalformedLimitAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		wire []byte
		max  int
		want error
	}{
		{[]byte{23, 3, 3, 0, 1}, 64 << 10, ErrClientHelloInvalid},
		{testTLSRecord(testClientHello(true)), 16, ErrClientHelloLimit},
	} {
		client, proxy := net.Pipe()
		go func() { _, _ = client.Write(tc.wire); _ = client.Close() }()
		_, buffered, err := PeekClientHello(context.Background(), proxy, tc.max, time.Second)
		_ = proxy.Close()
		if !errors.Is(err, tc.want) || len(buffered) < 5 {
			t.Fatalf("malformed/limit result = len %d, %v; want %v", len(buffered), err, tc.want)
		}
	}
	client, proxy := net.Pipe()
	defer client.Close()
	defer proxy.Close()
	_, _, err := PeekClientHello(context.Background(), proxy, 64<<10, 30*time.Millisecond)
	if !errors.Is(err, ErrClientHelloTimeout) {
		t.Fatalf("missing ClientHello did not time out: %v", err)
	}
}

func TestPeekClientHelloMalformedExtensionsAreUnavailable(t *testing.T) {
	hello := testClientHello(true)
	hello[len(hello)-5] = 6 // supported_versions list length no longer matches
	context, err := inspection.ParseTLSClientHello(testTLSRecord(hello))
	if !errors.Is(err, inspection.ErrClientHelloInvalid) || context.Available {
		t.Fatalf("malformed metadata was marked available: %+v %v", context, err)
	}
	truncated := testTLSRecord(testClientHello(true))
	truncated = truncated[:len(truncated)-1]
	context, err = inspection.ParseTLSClientHello(truncated)
	if !errors.Is(err, inspection.ErrClientHelloIncomplete) || context.Available {
		t.Fatalf("truncated record was accepted: %+v %v", context, err)
	}
}
