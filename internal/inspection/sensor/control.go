package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type ControlClient struct {
	SocketPath    string
	Timeout       time.Duration
	MaxReplyBytes int
}
type ControlProbe struct {
	OK      bool            `json:"ok"`
	Message string          `json:"message,omitempty"`
	Raw     json.RawMessage `json:"raw,omitempty"`
}

func (c ControlClient) Probe(ctx context.Context) (ControlProbe, error) {
	return c.Command(ctx, "uptime")
}

func (c ControlClient) Command(ctx context.Context, command string) (ControlProbe, error) {
	if command != "uptime" && command != "version" && command != "command-list" {
		return ControlProbe{}, errors.New("control command is not allowed")
	}
	if c.Timeout <= 0 {
		c.Timeout = 500 * time.Millisecond
	}
	if c.MaxReplyBytes <= 0 {
		c.MaxReplyBytes = 64 << 10
	}
	dialer := net.Dialer{Timeout: c.Timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return ControlProbe{}, err
	}
	defer connection.Close()
	deadline := time.Now().Add(c.Timeout)
	_ = connection.SetDeadline(deadline)
	if err := writeControlJSON(connection, map[string]string{"version": "0.1"}); err != nil {
		return ControlProbe{}, err
	}
	handshake, err := readControlJSON(connection, c.MaxReplyBytes)
	if err != nil {
		return ControlProbe{}, fmt.Errorf("control handshake: %w", err)
	}
	if value, _ := handshake["return"].(string); !strings.EqualFold(value, "OK") {
		return ControlProbe{}, errors.New("control handshake was rejected")
	}
	request, _ := json.Marshal(map[string]any{"command": command})
	if _, err = connection.Write(append(request, '\n')); err != nil {
		return ControlProbe{}, err
	}
	raw, err := readControlJSON(connection, c.MaxReplyBytes)
	if err != nil {
		return ControlProbe{}, err
	}
	reply, _ := json.Marshal(raw)
	probe := ControlProbe{OK: true, Raw: reply}
	if value, ok := raw["return"].(string); ok {
		if message, exists := raw["message"]; exists {
			probe.Message = fmt.Sprint(message)
		} else {
			probe.Message = value
		}
		if value != "OK" && value != "ok" {
			probe.OK = false
		}
	}
	return probe, nil
}

func writeControlJSON(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = writer.Write(append(encoded, '\n'))
	return err
}

func readControlJSON(reader io.Reader, max int) (map[string]any, error) {
	limited := &io.LimitedReader{R: reader, N: int64(max) + 1}
	var value map[string]any
	if err := json.NewDecoder(limited).Decode(&value); err != nil {
		if limited.N == 0 {
			return nil, errors.New("control response exceeds 64 KiB")
		}
		return nil, err
	}
	if limited.N == 0 {
		return nil, errors.New("control response exceeds 64 KiB")
	}
	return value, nil
}
