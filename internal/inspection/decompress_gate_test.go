package inspection

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"testing"
)

func compressedGateFixture(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(&buffer)
	case "deflate":
		writer = zlib.NewWriter(&buffer)
	default:
		t.Fatal("unsupported fixture")
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestDecodeGateBodySupportedAndExplicitErrors(t *testing.T) {
	body := []byte("POST /check HTTP/1.1\nSQL payload 1234567890")
	for _, encoding := range []string{"gzip", "deflate"} {
		raw := compressedGateFixture(t, encoding, body)
		decoded, err := DecodeGateBody(context.Background(), encoding, raw, false, 1024, 20)
		if err != nil || !bytes.Equal(decoded, body) {
			t.Fatalf("%s decode changed request: %q %v", encoding, decoded, err)
		}
		if decoded, err := DecodeGateBody(context.Background(), encoding, raw[:len(raw)-1], false, 1024, 20); decoded != nil || !errors.Is(err, ErrGateDecompressionInvalid) {
			t.Fatalf("truncated %s became clean: %v", encoding, err)
		}
	}
	if decoded, err := DecodeGateBody(context.Background(), "br", body, false, 1024, 20); decoded != nil || !errors.Is(err, ErrGateUnsupportedEncoding) {
		t.Fatalf("unsupported coding became clean: %v", err)
	}
	if decoded, err := DecodeGateBody(context.Background(), "gzip", body, true, 1024, 20); decoded != nil || !errors.Is(err, ErrGateBodyPartial) {
		t.Fatalf("partial compressed body became clean: %v", err)
	}
	if decoded, err := DecodeGateBody(context.Background(), "identity", body, false, 4, 20); decoded != nil || !errors.Is(err, ErrGateDecompressionLimit) {
		t.Fatalf("identity decoded limit ignored: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if decoded, err := DecodeGateBody(cancelled, "gzip", body, false, 1024, 20); decoded != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled decode continued: %v", err)
	}
}

func TestDecodeGateBodyBombHasByteAndRatioCaps(t *testing.T) {
	body := bytes.Repeat([]byte("A"), 200000)
	raw := compressedGateFixture(t, "gzip", body)
	if decoded, err := DecodeGateBody(context.Background(), "gzip", raw, false, 256<<10, 20); decoded != nil || !errors.Is(err, ErrGateDecompressionLimit) {
		t.Fatalf("compression ratio bomb escaped cap: raw=%d err=%v", len(raw), err)
	}
	if decoded, err := DecodeGateBody(context.Background(), "gzip", raw, false, 100, 100); decoded != nil || !errors.Is(err, ErrGateDecompressionLimit) {
		t.Fatalf("decoded byte cap ignored: %v", err)
	}
}

func FuzzDecodeGateBodyNoPanic(f *testing.F) {
	f.Add("gzip", []byte{31, 139, 8, 0, 0, 0, 0, 0})
	f.Add("deflate", []byte{120, 156, 3, 0})
	f.Add("br", []byte("unknown"))
	f.Fuzz(func(t *testing.T, encoding string, raw []byte) {
		if len(raw) > 1024 {
			return
		}
		decoded, err := DecodeGateBody(context.Background(), encoding, raw, false, 4096, 20)
		if err == nil && len(decoded) > 4096 {
			t.Fatal("decoder exceeded cap")
		}
	})
}
