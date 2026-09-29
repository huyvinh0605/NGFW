package inspection

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"strings"
)

var (
	ErrGateUnsupportedEncoding  = errors.New("GATE_UNSUPPORTED_ENCODING")
	ErrGateDecompressionLimit   = errors.New("GATE_DECOMPRESSION_LIMIT")
	ErrGateDecompressionInvalid = errors.New("GATE_REQUEST_MALFORMED")
	ErrGateBodyPartial          = errors.New("GATE_REQUEST_PARTIAL")
)

// DecodeGateBody returns a detached inspection body, not a replacement for
// the raw application body. gzip and zlib-wrapped deflate are supported; any
// other coding is explicit UNAVAILABLE/PARTIAL input to the engine's failure
// policy, never a CLEAN detector result.
func DecodeGateBody(ctx context.Context, encoding string, raw []byte, rawTruncated bool, maxDecodedBytes, maxRatio int) ([]byte, error) {
	if ctx == nil || maxDecodedBytes < 1 || maxDecodedBytes > 4<<20 || maxRatio < 1 || maxRatio > 100 || len(raw) > 1<<20 {
		return nil, ErrGateDecompressionInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rawTruncated {
		return nil, ErrGateBodyPartial
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding == "" || encoding == "identity" {
		if len(raw) > maxDecodedBytes {
			return nil, ErrGateDecompressionLimit
		}
		return append([]byte(nil), raw...), nil
	}
	var decoder io.ReadCloser
	var err error
	switch encoding {
	case "gzip":
		decoder, err = gzip.NewReader(bytes.NewReader(raw))
	case "deflate":
		decoder, err = zlib.NewReader(bytes.NewReader(raw))
	default:
		return nil, ErrGateUnsupportedEncoding
	}
	if err != nil {
		return nil, ErrGateDecompressionInvalid
	}
	defer decoder.Close()
	maximum := maxDecodedBytes
	if ratioMaximum := len(raw) * maxRatio; ratioMaximum < maximum {
		maximum = ratioMaximum
	}
	result := make([]byte, 0, min(maximum, 4096))
	var chunk [4096]byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining := maximum + 1 - len(result)
		if remaining <= 0 {
			return nil, ErrGateDecompressionLimit
		}
		read, readErr := decoder.Read(chunk[:min(len(chunk), remaining)])
		result = append(result, chunk[:read]...)
		if len(result) > maximum {
			return nil, ErrGateDecompressionLimit
		}
		if errors.Is(readErr, io.EOF) {
			return result, nil
		}
		if readErr != nil {
			return nil, ErrGateDecompressionInvalid
		}
	}
}
