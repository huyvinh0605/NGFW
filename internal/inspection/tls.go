package inspection

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kltngfw/ngfw/internal/domain"
)

// ParseTLSClientHello extracts metadata without decrypting application data.
// It intentionally returns Available=false when the input is incomplete or
// encrypted in a form that cannot be safely parsed.
func ParseTLSClientHello(data []byte) (domain.TLSContext, error) {
	result := domain.TLSContext{Available: false}
	if len(data) < 5 {
		return result, errors.New("incomplete TLS record")
	}
	if data[0] != 22 {
		return result, errors.New("not a TLS handshake record")
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen < 4 || 5+recordLen > len(data) {
		return result, errors.New("incomplete TLS record payload")
	}
	payload := data[5 : 5+recordLen]
	if payload[0] != 1 {
		return result, errors.New("first TLS handshake is not ClientHello")
	}
	if len(payload) < 4 {
		return result, errors.New("incomplete ClientHello")
	}
	helloLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if helloLen+4 > len(payload) {
		return result, errors.New("incomplete ClientHello payload")
	}
	hello := payload[4 : 4+helloLen]
	if len(hello) < 34 {
		return result, errors.New("short ClientHello")
	}
	pos := 34
	if pos >= len(hello) {
		return result, errors.New("missing session id")
	}
	sidLen := int(hello[pos])
	pos++
	if pos+sidLen+2 > len(hello) {
		return result, errors.New("invalid session id")
	}
	pos += sidLen
	csLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if csLen%2 != 0 || pos+csLen+1 > len(hello) {
		return result, errors.New("invalid cipher list")
	}
	if csLen >= 2 {
		cipher := binary.BigEndian.Uint16(hello[pos : pos+2])
		result.Cipher = fmt.Sprintf("0x%04x", cipher)
	}
	pos += csLen
	compLen := int(hello[pos])
	pos++
	if pos+compLen > len(hello) {
		return result, errors.New("invalid compression list")
	}
	pos += compLen
	if pos == len(hello) {
		result.TLSVersion = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(hello[0:2]))
		result.Available = true
		return result, nil
	}
	if pos+2 > len(hello) {
		return result, errors.New("missing extensions")
	}
	extLen := int(binary.BigEndian.Uint16(hello[pos : pos+2]))
	pos += 2
	if pos+extLen > len(hello) {
		return result, errors.New("invalid extensions")
	}
	exts := hello[pos : pos+extLen]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[:2])
		l := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if l > len(exts) {
			return result, errors.New("invalid extension length")
		}
		body := exts[:l]
		exts = exts[l:]
		switch typ {
		case 0:
			if len(body) >= 5 {
				listLen := int(binary.BigEndian.Uint16(body[:2]))
				if listLen+2 <= len(body) && body[2] == 0 && len(body) >= 5 {
					n := int(binary.BigEndian.Uint16(body[3:5]))
					if 5+n <= len(body) {
						result.SNI = string(body[5 : 5+n])
					}
				}
			}
		case 16:
			if len(body) >= 3 {
				n := int(body[0])
				if n+1 < len(body) {
					p := body[1:]
					if len(p) > 0 {
						result.ALPN = string(p[1 : 1+min(n, len(p)-1)])
					}
				}
			}
		case 43:
			if len(body) >= 3 {
				n := int(body[0])
				if n > 0 && n+1 <= len(body) {
					result.TLSVersion = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(body[1:3]))
				}
			}
		}
	}
	if result.TLSVersion == "" {
		result.TLSVersion = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(hello[0:2]))
	}
	result.Available = true
	return result, nil
}

// TLSConfig is used by the lab interception proxy. The returned config never
// exposes the CA private key through the API layer.
func TLSConfig(cert tls.Certificate, nextProtos []string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: nextProtos, PreferServerCipherSuites: true}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func IsLikelyTLS(data []byte) bool { return len(data) >= 5 && bytes.Equal(data[:1], []byte{22}) }
