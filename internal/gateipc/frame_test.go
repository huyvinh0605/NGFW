package gateipc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

type oneByteWriter struct{ writer io.Writer }

func (writer oneByteWriter) Write(value []byte) (int, error) {
	if len(value) > 1 {
		value = value[:1]
	}
	return writer.writer.Write(value)
}

type oneByteReader struct{ reader io.Reader }

func (reader oneByteReader) Read(value []byte) (int, error) {
	if len(value) > 1 {
		value = value[:1]
	}
	return reader.reader.Read(value)
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var coded *ProtocolError
	if !errors.As(err, &coded) || coded.Code != want {
		t.Fatalf("error = %v, want code %s", err, want)
	}
}

func TestFrameHandlesFragmentedReadsAndWrites(t *testing.T) {
	var wire bytes.Buffer
	want := requestFrame{Version: ProtocolVersion, CorrelationID: "f1", Operation: OpenConnection, Payload: []byte(`{"connection_id":"c1"}`)}
	if err := writeFrame(oneByteWriter{&wire}, 256, want); err != nil {
		t.Fatal(err)
	}
	var got requestFrame
	if err := readFrame(oneByteReader{&wire}, 256, &got); err != nil {
		t.Fatal(err)
	}
	if got.CorrelationID != want.CorrelationID || got.Version != ProtocolVersion || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("fragmented frame changed: %+v", got)
	}
}

func TestFrameRejectsMalformedAndOversizedPayloads(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		code string
	}{
		{"zero length", []byte{0, 0, 0, 0}, CodeMalformed},
		{"oversized without allocating body", []byte{0xff, 0xff, 0xff, 0xff}, CodeFrameTooLarge},
		{"invalid JSON", rawFrame([]byte(`{"version":`)), CodeMalformed},
		{"unknown field", rawFrame([]byte(`{"unknown":1}`)), CodeMalformed},
		{"multiple JSON values", rawFrame([]byte(`{} {}`)), CodeMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var result requestFrame
			requireCode(t, readFrame(bytes.NewReader(tc.data), 64, &result), tc.code)
		})
	}
	if err := writeFrame(io.Discard, 16, requestFrame{Version: ProtocolVersion, CorrelationID: "a-long-id"}); err == nil {
		t.Fatal("oversized outgoing request was written")
	} else {
		requireCode(t, err, CodeFrameTooLarge)
	}
}

func rawFrame(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func FuzzReadFrame(f *testing.F) {
	f.Add(rawFrame([]byte(`{"version":1,"correlation_id":"c","operation":"gate_health_ping","payload":{}}`)))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add(rawFrame([]byte(`{} {}`)))
	f.Fuzz(func(t *testing.T, input []byte) {
		var result requestFrame
		_ = readFrame(bytes.NewReader(input), 1024, &result)
	})
}
