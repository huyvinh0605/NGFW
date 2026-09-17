package inspection

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/kltngfw/ngfw/internal/domain"
)

func ParseDNSMessage(packet []byte, maxAnswers int) (domain.DNSContext, error) {
	if maxAnswers <= 0 {
		maxAnswers = 32
	}
	if len(packet) < 12 {
		return domain.DNSContext{}, errors.New("short DNS header")
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	an := int(binary.BigEndian.Uint16(packet[6:8]))
	if qd < 1 || qd > 16 {
		return domain.DNSContext{}, errors.New("invalid DNS question count")
	}
	pos := 12
	name, next, err := readDNSName(packet, pos)
	if err != nil {
		return domain.DNSContext{}, err
	}
	pos = next
	if pos+4 > len(packet) {
		return domain.DNSContext{}, errors.New("short DNS question")
	}
	qtype := binary.BigEndian.Uint16(packet[pos : pos+2])
	pos += 4
	result := domain.DNSContext{Query: name, RecordType: dnsType(qtype), ResponseCode: int(flags & 0xf)}
	if an > maxAnswers {
		an = maxAnswers
	}
	for i := 0; i < an && pos < len(packet); i++ {
		_, next, err = readDNSName(packet, pos)
		if err != nil {
			return result, err
		}
		pos = next
		if pos+10 > len(packet) {
			return result, errors.New("short DNS answer")
		}
		typ := binary.BigEndian.Uint16(packet[pos : pos+2])
		ttl := binary.BigEndian.Uint32(packet[pos+4 : pos+8])
		rdlen := int(binary.BigEndian.Uint16(packet[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(packet) {
			return result, errors.New("DNS answer exceeds packet")
		}
		if result.TTL == 0 || ttl < result.TTL {
			result.TTL = ttl
		}
		if typ == 1 && rdlen == 4 {
			result.Answers = append(result.Answers, fmt.Sprintf("%d.%d.%d.%d", packet[pos], packet[pos+1], packet[pos+2], packet[pos+3]))
		}
		if typ == 28 && rdlen == 16 {
			result.Answers = append(result.Answers, fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x", binary.BigEndian.Uint16(packet[pos:pos+2]), binary.BigEndian.Uint16(packet[pos+2:pos+4]), binary.BigEndian.Uint16(packet[pos+4:pos+6]), binary.BigEndian.Uint16(packet[pos+6:pos+8]), binary.BigEndian.Uint16(packet[pos+8:pos+10]), binary.BigEndian.Uint16(packet[pos+10:pos+12]), binary.BigEndian.Uint16(packet[pos+12:pos+14]), binary.BigEndian.Uint16(packet[pos+14:pos+16])))
		}
		pos += rdlen
	}
	return result, nil
}
func readDNSName(packet []byte, pos int) (string, int, error) {
	var labels []string
	visited := map[int]bool{}
	return readDNSNameAt(packet, pos, labels, visited, 0)
}
func readDNSNameAt(packet []byte, pos int, labels []string, visited map[int]bool, depth int) (string, int, error) {
	if depth > 8 {
		return "", pos, errors.New("DNS compression depth exceeded")
	}
	for {
		if pos >= len(packet) {
			return "", pos, errors.New("DNS name exceeds packet")
		}
		length := int(packet[pos])
		if length == 0 {
			return strings.Join(labels, "."), pos + 1, nil
		}
		if length&0xc0 == 0xc0 {
			if pos+1 >= len(packet) {
				return "", pos, errors.New("short DNS pointer")
			}
			target := int(packet[pos]&0x3f)<<8 | int(packet[pos+1])
			if visited[target] {
				return "", pos, errors.New("DNS pointer loop")
			}
			visited[target] = true
			name, _, err := readDNSNameAt(packet, target, labels, visited, depth+1)
			return name, pos + 2, err
		}
		if length > 63 || pos+1+length > len(packet) {
			return "", pos, errors.New("invalid DNS label")
		}
		labels = append(labels, string(packet[pos+1:pos+1+length]))
		pos += 1 + length
	}
}
func dnsType(v uint16) string {
	switch v {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	default:
		return fmt.Sprintf("TYPE%d", v)
	}
}
