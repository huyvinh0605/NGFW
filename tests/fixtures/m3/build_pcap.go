//go:build ignore

// Command build_pcap creates the deterministic, harmless HTTP stream used by
// M3 offline Suricata replay. The marker is deliberately split across two TCP
// segments so replay also checks stream reassembly.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
)

type packet struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
	seq, ack         uint32
	flags            byte
	payload          []byte
}

func main() {
	output := "marker-http.pcap"
	if len(os.Args) == 2 {
		output = os.Args[1]
	} else if len(os.Args) > 2 {
		panic("usage: go run build_pcap.go [output.pcap]")
	}
	client := netip.MustParseAddr("192.168.10.10")
	server := netip.MustParseAddr("192.0.2.10")
	first := []byte("GET /NGFW_M3_")
	second := []byte("TEST_fixture HTTP/1.1\r\nHost: m3.local\r\nConnection: keep-alive\r\n\r\n")
	clientEnd := uint32(1001 + len(first) + len(second))
	packets := []packet{
		{client, server, 50000, 8080, 1000, 0, 0x02, nil},
		{server, client, 8080, 50000, 9000, 1001, 0x12, nil},
		{client, server, 50000, 8080, 1001, 9001, 0x10, nil},
		{client, server, 50000, 8080, 1001, 9001, 0x18, first},
		{client, server, 50000, 8080, uint32(1001 + len(first)), 9001, 0x18, second},
		{server, client, 8080, 50000, 9001, clientEnd, 0x18, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")},
	}
	data := pcap(packets)
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil && filepath.Dir(output) != "." {
		panic(err)
	}
	if err := os.WriteFile(output, data, 0644); err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)
	fmt.Printf("%x  %s\n", digest, output)
}

func pcap(packets []packet) []byte {
	result := make([]byte, 24)
	binary.LittleEndian.PutUint32(result[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(result[4:6], 2)
	binary.LittleEndian.PutUint16(result[6:8], 4)
	binary.LittleEndian.PutUint32(result[16:20], 65535)
	binary.LittleEndian.PutUint32(result[20:24], 1)
	for index, value := range packets {
		frame := ethernetIPv4TCP(value, uint16(index+1))
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:4], 1700000000)
		binary.LittleEndian.PutUint32(record[4:8], uint32(index*1000))
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))
		result = append(result, record...)
		result = append(result, frame...)
	}
	return result
}

func ethernetIPv4TCP(value packet, id uint16) []byte {
	ipLength := 20 + 20 + len(value.payload)
	frame := make([]byte, 14+ipLength)
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLength))
	binary.BigEndian.PutUint16(ip[4:6], id)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8], ip[9] = 64, 6
	src, dst := value.src.As4(), value.dst.As4()
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	tcp := frame[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], value.srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], value.dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], value.seq)
	binary.BigEndian.PutUint32(tcp[8:12], value.ack)
	tcp[12], tcp[13] = 5<<4, value.flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(frame[54:], value.payload)
	pseudo := make([]byte, 12+20+len(value.payload))
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(value.payload)))
	copy(pseudo[12:], frame[34:])
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return frame
}

func checksum(value []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(value); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(value[index : index+2]))
	}
	if len(value)%2 != 0 {
		sum += uint32(value[len(value)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
