// Package requestpcap builds a finite, deterministic HTTP/1.1-equivalent TCP
// conversation for request-signature inspection. It never opens a file or
// derives a path from request data.
package requestpcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/kltngfw/ngfw/internal/inspection"
)

const (
	maxBodyBytes    = 4 << 20
	maxHeaderBytes  = 64 << 10
	maxURLBytes     = 16 << 10
	maxCaptureBytes = 6 << 20
	segmentBytes    = 1200
	clientSequence  = uint32(1000)
	serverSequence  = uint32(5000)
)

var ErrInvalidRequest = errors.New("REQUEST_PCAP_INVALID_REQUEST")
var ErrCaptureLimit = errors.New("REQUEST_PCAP_CAPTURE_LIMIT")

// Build produces linktype Ethernet (DLT_EN10MB), IPv4, TCP and a complete
// three-way handshake, request, empty HTTP response and bidirectional close.
// The caller supplies a distinct flowID for every job handled by one Suricata
// process. All 32 bits are encoded in the synthetic client IP/port tuple, so
// live worker jobs cannot reuse a tuple until the counter wraps. A worker must
// fail closed or restart its Suricata process before that wrap.
func Build(request inspection.GateHTTPRequest, flowID uint32) ([]byte, error) {
	payload, err := semanticRequest(request)
	if err != nil {
		return nil, err
	}
	pcap := new(bytes.Buffer)
	pcap.Grow(min(maxCaptureBytes, len(payload)+1024))
	_ = binary.Write(pcap, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(pcap, binary.LittleEndian, uint16(2))
	_ = binary.Write(pcap, binary.LittleEndian, uint16(4))
	_ = binary.Write(pcap, binary.LittleEndian, uint32(0))
	_ = binary.Write(pcap, binary.LittleEndian, uint32(0))
	_ = binary.Write(pcap, binary.LittleEndian, uint32(65535))
	_ = binary.Write(pcap, binary.LittleEndian, uint32(1)) // Ethernet
	clientSeq, serverSeq := clientSequence, serverSequence
	packetNumber := uint32(0)
	write := func(fromClient bool, flags byte, data []byte) error {
		if len(data) > segmentBytes {
			return ErrCaptureLimit
		}
		seq, ack := serverSeq, clientSeq
		if fromClient {
			seq, ack = clientSeq, serverSeq
		}
		packet := makePacket(fromClient, flowID, uint16(packetNumber+1), seq, ack, flags, data)
		if pcap.Len()+16+len(packet) > maxCaptureBytes {
			return ErrCaptureLimit
		}
		_ = binary.Write(pcap, binary.LittleEndian, uint32(1+packetNumber/1000))
		_ = binary.Write(pcap, binary.LittleEndian, uint32(packetNumber%1000*1000))
		_ = binary.Write(pcap, binary.LittleEndian, uint32(len(packet)))
		_ = binary.Write(pcap, binary.LittleEndian, uint32(len(packet)))
		_, _ = pcap.Write(packet)
		packetNumber++
		advance := uint32(len(data))
		if flags&0x03 != 0 { // SYN and FIN each consume one sequence number.
			advance++
		}
		if fromClient {
			clientSeq += advance
		} else {
			serverSeq += advance
		}
		return nil
	}
	if err := write(true, 0x02, nil); err != nil { // SYN
		return nil, err
	}
	if err := write(false, 0x12, nil); err != nil { // SYN, ACK
		return nil, err
	}
	if err := write(true, 0x10, nil); err != nil { // ACK
		return nil, err
	}
	for len(payload) != 0 {
		length := min(len(payload), segmentBytes)
		if err := write(true, 0x18, payload[:length]); err != nil { // PSH, ACK
			return nil, err
		}
		payload = payload[length:]
	}
	if err := write(false, 0x10, nil); err != nil {
		return nil, err
	}
	response := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	if err := write(false, 0x18, response); err != nil {
		return nil, err
	}
	if err := write(true, 0x10, nil); err != nil {
		return nil, err
	}
	if err := write(true, 0x11, nil); err != nil { // FIN, ACK
		return nil, err
	}
	if err := write(false, 0x10, nil); err != nil {
		return nil, err
	}
	if err := write(false, 0x11, nil); err != nil {
		return nil, err
	}
	if err := write(true, 0x10, nil); err != nil {
		return nil, err
	}
	return pcap.Bytes(), nil
}

func semanticRequest(request inspection.GateHTTPRequest) ([]byte, error) {
	if len(request.Method) > 64 || !token(request.Method) || !validHost(request.Host) || len(request.Body) > maxBodyBytes || len(request.Headers) > 256 {
		return nil, ErrInvalidRequest
	}
	path := request.Path
	if path == "" {
		path = "/"
	}
	if len(path)+len(request.RawQuery)+1 > maxURLBytes {
		return nil, ErrCaptureLimit
	}
	if !strings.HasPrefix(path, "/") || !singleLine(path) || !singleLine(request.RawQuery) {
		return nil, ErrInvalidRequest
	}
	uri := path
	if request.RawQuery != "" {
		uri += "?" + request.RawQuery
	}
	if !ascii(uri) {
		return nil, ErrInvalidRequest
	}
	var wire bytes.Buffer
	wire.Grow(min(maxCaptureBytes, len(request.Body)+1024))
	wire.WriteString(request.Method + " " + uri + " HTTP/1.1\r\n")
	wire.WriteString("Host: " + request.Host + "\r\n")
	keys := make([]string, 0, len(request.Headers))
	for key := range request.Headers {
		if len(key) > 256 || !token(key) {
			return nil, ErrInvalidRequest
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := strings.ToLower(keys[i]), strings.ToLower(keys[j])
		if left == right {
			return keys[i] < keys[j]
		}
		return left < right
	})
	for _, key := range keys {
		if excludedHeader(key) {
			continue
		}
		for _, value := range request.Headers[key] {
			if !singleLine(value) {
				return nil, ErrInvalidRequest
			}
			if len(value) > maxHeaderBytes || wire.Len()+len(key)+len(value)+4 > maxHeaderBytes {
				return nil, ErrCaptureLimit
			}
			wire.WriteString(http.CanonicalHeaderKey(key) + ": " + value + "\r\n")
		}
	}
	wire.WriteString("Content-Length: " + strconv.Itoa(len(request.Body)) + "\r\nConnection: close\r\n\r\n")
	if wire.Len() > maxHeaderBytes {
		return nil, ErrCaptureLimit
	}
	wire.Write(request.Body)
	return wire.Bytes(), nil
}

func excludedHeader(key string) bool {
	key = strings.ToLower(key)
	switch key {
	case "host", "content-length", "content-encoding", "transfer-encoding", "connection", "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key":
		return true
	}
	return strings.Contains(key, "token") || strings.Contains(key, "secret") || strings.Contains(key, "password")
}

func token(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func singleLine(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return false
		}
	}
	return true
}

func ascii(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func validHost(host string) bool {
	return host != "" && len(host) <= 255 && singleLine(host) && ascii(host) && !strings.ContainsAny(host, " /?#@\\")
}

func makePacket(fromClient bool, flowID uint32, identifier uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	var sourceIP, destinationIP [4]byte
	var sourcePort, destinationPort uint16
	var sourceMAC, destinationMAC [6]byte
	clientIP := [4]byte{198, 18 | byte(flowID>>31), byte(flowID >> 23), byte(flowID >> 15)}
	clientPort := uint16(1024 + (flowID & 0x7fff))
	serverIP := [4]byte{192, 168, 0, 10}
	if fromClient {
		sourceIP, destinationIP = clientIP, serverIP
		sourcePort, destinationPort = clientPort, 80
		sourceMAC, destinationMAC = [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	} else {
		sourceIP, destinationIP = serverIP, clientIP
		sourcePort, destinationPort = 80, clientPort
		sourceMAC, destinationMAC = [6]byte{2, 0, 0, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 1}
	}
	packet := make([]byte, 14+20+20+len(payload))
	copy(packet[0:6], destinationMAC[:])
	copy(packet[6:12], sourceMAC[:])
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	binary.BigEndian.PutUint16(ip[4:6], identifier)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], sourceIP[:])
	copy(ip[16:20], destinationIP[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	tcp := packet[34:]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12], tcp[13] = 0x50, flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:], payload)
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], sourceIP[:])
	copy(pseudo[4:8], destinationIP[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return packet
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
