package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
	"github.com/kltngfw/ngfw/internal/inspection"
)

var (
	ErrClientHelloTimeout = errors.New("TLS_CLIENTHELLO_TIMEOUT")
	ErrClientHelloInvalid = errors.New("TLS_CLIENTHELLO_INVALID")
	ErrClientHelloLimit   = fmt.Errorf("%w: byte limit", ErrClientHelloInvalid)
)

// PeekClientHello consumes only complete TLS record frames, bounded by bytes
// and time. The returned bytes include every byte consumed even on failure;
// BYPASS/METADATA_ONLY must replay them verbatim before copying the rest of
// the connection. No upstream connection is opened here.
func PeekClientHello(ctx context.Context, connection net.Conn, maxBytes int, timeout time.Duration) (domain.TLSContext, []byte, error) {
	if ctx == nil || connection == nil {
		return domain.TLSContext{}, nil, ErrClientHelloInvalid
	}
	if maxBytes <= 0 {
		maxBytes = 64 << 10
	}
	if maxBytes > 64<<10 {
		return domain.TLSContext{}, nil, ErrClientHelloLimit
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout > 5*time.Second {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return domain.TLSContext{}, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.SetReadDeadline(time.Now()) })
	defer func() {
		stop()
		_ = connection.SetReadDeadline(time.Time{})
	}()

	buffered := make([]byte, 0, min(maxBytes, 4096))
	for {
		if len(buffered)+5 > maxBytes {
			return domain.TLSContext{}, buffered, ErrClientHelloLimit
		}
		header := make([]byte, 5)
		read, err := io.ReadFull(connection, header)
		buffered = append(buffered, header[:read]...)
		if err != nil {
			return domain.TLSContext{}, buffered, clientHelloReadError(ctx, err)
		}
		if header[0] != 22 || header[1] != 3 || header[2] > 4 {
			return domain.TLSContext{}, buffered, ErrClientHelloInvalid
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || length > 18432 {
			return domain.TLSContext{}, buffered, ErrClientHelloInvalid
		}
		if len(buffered)+length > maxBytes {
			return domain.TLSContext{}, buffered, ErrClientHelloLimit
		}
		payload := make([]byte, length)
		read, err = io.ReadFull(connection, payload)
		buffered = append(buffered, payload[:read]...)
		if err != nil {
			return domain.TLSContext{}, buffered, clientHelloReadError(ctx, err)
		}
		metadata, parseErr := inspection.ParseTLSClientHello(buffered)
		if parseErr == nil {
			return metadata, buffered, nil
		}
		if !errors.Is(parseErr, inspection.ErrClientHelloIncomplete) {
			return domain.TLSContext{}, buffered, fmt.Errorf("%w: %v", ErrClientHelloInvalid, parseErr)
		}
	}
}

func clientHelloReadError(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ErrClientHelloTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return ErrClientHelloTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return inspection.ErrClientHelloIncomplete
	}
	return err
}
