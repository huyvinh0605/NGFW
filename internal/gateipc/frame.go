package gateipc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolVersion      uint16 = 1
	DefaultMaxFrameBytes        = 256 << 10
	HardMaxFrameBytes           = 1 << 20
)

const (
	CodeMalformed       = "GATE_IPC_MALFORMED"
	CodeVersionMismatch = "GATE_IPC_VERSION_MISMATCH"
	CodeFrameTooLarge   = "GATE_IPC_FRAME_TOO_LARGE"
	CodeDeadline        = "GATE_IPC_DEADLINE_EXCEEDED"
	CodeEngineDown      = "GATE_ENGINE_UNAVAILABLE"
	CodeCorrelation     = "GATE_IPC_CORRELATION_MISMATCH"
	CodeStaleGeneration = "GATE_IPC_STALE_GENERATION"
	CodeInternal        = "GATE_IPC_INTERNAL"
)

type ProtocolError struct {
	Code string
}

func (e *ProtocolError) Error() string { return e.Code }

func protocolError(code string) error { return &ProtocolError{Code: code} }

func normalizedMaxFrame(value int) int {
	if value <= 0 {
		return DefaultMaxFrameBytes
	}
	if value > HardMaxFrameBytes {
		return HardMaxFrameBytes
	}
	return value
}

// readFrame rejects the length before allocating a payload. Its caller owns
// the connection deadline and closes the connection after one exchange.
func readFrame(reader io.Reader, maxBytes int, out any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return protocolError(CodeMalformed)
	}
	if length > uint32(normalizedMaxFrame(maxBytes)) {
		return protocolError(CodeFrameTooLarge)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return protocolError(CodeMalformed)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return protocolError(CodeMalformed)
	}
	return nil
}

func writeFrame(writer io.Writer, maxBytes int, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal gate IPC frame: %w", err)
	}
	if len(payload) == 0 || len(payload) > normalizedMaxFrame(maxBytes) {
		return protocolError(CodeFrameTooLarge)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
