package inspection

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/kltngfw/ngfw/internal/domain"
)

var (
	ErrClientHelloIncomplete = errors.New("incomplete TLS ClientHello")
	ErrClientHelloInvalid    = errors.New("invalid TLS ClientHello")
)

// ParseTLSClientHello extracts observable metadata from one or more TLS
// handshake records. It never treats incomplete or malformed input as clean.
// The bounded proxy peek calls it after each complete record; M3 may call it
// on an incomplete packet and receive ErrClientHelloIncomplete.
func ParseTLSClientHello(data []byte) (domain.TLSContext, error) {
	result := domain.TLSContext{Available: false}
	const maxHello = 64 << 10
	var handshake []byte
	for position := 0; position < len(data); {
		if len(data)-position < 5 {
			return result, ErrClientHelloIncomplete
		}
		header := data[position : position+5]
		if header[0] != 22 || header[1] != 3 || header[2] > 4 {
			return result, fmt.Errorf("%w: not a TLS handshake record", ErrClientHelloInvalid)
		}
		recordLength := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLength == 0 || recordLength > 18432 || len(handshake)+recordLength > maxHello {
			return result, fmt.Errorf("%w: record length", ErrClientHelloInvalid)
		}
		position += 5
		if len(data)-position < recordLength {
			return result, ErrClientHelloIncomplete
		}
		handshake = append(handshake, data[position:position+recordLength]...)
		position += recordLength
		if len(handshake) < 4 {
			continue
		}
		if handshake[0] != 1 {
			return result, fmt.Errorf("%w: first handshake is not ClientHello", ErrClientHelloInvalid)
		}
		helloLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if helloLength < 34 || helloLength+4 > maxHello {
			return result, fmt.Errorf("%w: ClientHello length", ErrClientHelloInvalid)
		}
		if len(handshake) < helloLength+4 {
			continue
		}
		return parseClientHelloBody(handshake[4 : helloLength+4])
	}
	return result, ErrClientHelloIncomplete
}

func parseClientHelloBody(hello []byte) (domain.TLSContext, error) {
	result := domain.TLSContext{Available: false}
	invalid := func(reason string) (domain.TLSContext, error) {
		return domain.TLSContext{Available: false}, fmt.Errorf("%w: %s", ErrClientHelloInvalid, reason)
	}
	if len(hello) < 35 {
		return invalid("short ClientHello")
	}
	legacyVersion := binary.BigEndian.Uint16(hello[:2])
	result.TLSVersion = fmt.Sprintf("0x%04x", legacyVersion)
	position := 34 // two version bytes and 32 random bytes
	sessionLength := int(hello[position])
	position++
	if sessionLength > 32 || len(hello)-position < sessionLength+2 {
		return invalid("session ID length")
	}
	position += sessionLength
	ciphersLength := int(binary.BigEndian.Uint16(hello[position : position+2]))
	position += 2
	if ciphersLength < 2 || ciphersLength%2 != 0 || len(hello)-position < ciphersLength+1 {
		return invalid("cipher list length")
	}
	result.Cipher = fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(hello[position:position+2]))
	position += ciphersLength
	compressionLength := int(hello[position])
	position++
	if compressionLength == 0 || len(hello)-position < compressionLength {
		return invalid("compression list length")
	}
	position += compressionLength
	if position == len(hello) {
		result.Available = true
		return result, nil
	}
	if len(hello)-position < 2 {
		return invalid("extension block length")
	}
	extensionsLength := int(binary.BigEndian.Uint16(hello[position : position+2]))
	position += 2
	if extensionsLength != len(hello)-position {
		return invalid("extension block framing")
	}
	extensions := hello[position:]
	for len(extensions) > 0 {
		if len(extensions) < 4 {
			return invalid("extension header")
		}
		typ := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if length > len(extensions) {
			return invalid("extension length")
		}
		body := extensions[:length]
		extensions = extensions[length:]
		switch typ {
		case 0: // server_name
			if len(body) < 2 || int(binary.BigEndian.Uint16(body[:2])) != len(body)-2 {
				return invalid("SNI list framing")
			}
			for names := body[2:]; len(names) > 0; {
				if len(names) < 3 {
					return invalid("SNI entry header")
				}
				nameType := names[0]
				nameLength := int(binary.BigEndian.Uint16(names[1:3]))
				names = names[3:]
				if nameLength == 0 || nameLength > len(names) {
					return invalid("SNI entry length")
				}
				if nameType == 0 && result.SNI == "" && nameLength <= 253 && !bytes.ContainsRune(names[:nameLength], 0) {
					result.SNI = string(names[:nameLength])
				}
				names = names[nameLength:]
			}
		case 16: // application_layer_protocol_negotiation
			if len(body) < 2 || int(binary.BigEndian.Uint16(body[:2])) != len(body)-2 {
				return invalid("ALPN list framing")
			}
			for protocols := body[2:]; len(protocols) > 0; {
				length := int(protocols[0])
				protocols = protocols[1:]
				if length == 0 || length > len(protocols) {
					return invalid("ALPN entry length")
				}
				if result.ALPN == "" {
					result.ALPN = string(protocols[:length]) // first offered protocol
				}
				protocols = protocols[length:]
			}
		case 43: // supported_versions in ClientHello
			if len(body) < 3 || int(body[0]) != len(body)-1 || body[0]%2 != 0 {
				return invalid("supported versions framing")
			}
			for offered := body[1:]; len(offered) > 0; offered = offered[2:] {
				version := binary.BigEndian.Uint16(offered[:2])
				if version == 0x0304 {
					result.TLSVersion = "0x0304"
				}
			}
		}
	}
	result.Available = true
	return result, nil
}

// TLSConfig is used by the lab interception proxy. The returned config never
// exposes the CA private key through the API layer.
func TLSConfig(cert tls.Certificate, nextProtos []string) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: nextProtos, PreferServerCipherSuites: true}
}

func IsLikelyTLS(data []byte) bool { return len(data) >= 5 && data[0] == 22 }
