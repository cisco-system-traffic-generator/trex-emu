package main

import (
	"emu/rpc"
	"encoding/binary"
	"encoding/hex"
	"external/google/gopacket"
	"external/google/gopacket/layers"
	"external/google/gopacket/pcapgo"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

func testpcapWrite() {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17}
	ts := time.Unix(0, 0)
	f, _ := os.Create("/tmp/example.pcap")
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     ts,
		Length:        len(data),
		CaptureLength: len(data),
	}, data)
	f.Close()
}

func testpcapWrite2() {
	//data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 17}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	//ip.SerializeTo(buf, opts)
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{142, 122, 18, 195, 169, 113},
			DstMAC:       net.HardwareAddr{58, 86, 107, 105, 89, 94},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{Version: 4, IHL: 5, TTL: 128, Id: 0xcc, SrcIP: net.IPv4(16, 0, 0, 1), DstIP: net.IPv4(48, 0, 0, 1), Length: 44,
			Protocol: layers.IPProtocolTCP},
		&layers.TCP{SrcPort: 0x1111, DstPort: 0x2222, Seq: 0x11223344, Ack: 0x77889900},
		gopacket.Payload([]byte{1, 2, 3, 4}))

	data := buf.Bytes()
	fmt.Println(buf.Layers())

	ts := time.Unix(0, 0)
	f, _ := os.Create("/tmp/example.pcap")
	w := pcapgo.NewWriterNanos(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	w.WritePacket(gopacket.CaptureInfo{
		Timestamp:     ts,
		Length:        len(data),
		CaptureLength: len(data),
	}, data)
	f.Close()
}

func testSlice() {
	s := []byte{2, 3, 5, 7, 11, 13}
	printSlice(s)

	// Slice the slice to give it zero length.
	s = s[:0]
	printSlice(s)

	// Extend its length.
	s = s[:4]
	printSlice(s)

	// Drop its first two values.
	s = s[2:]
	printSlice(s)
}

//type ipHeader1 []byte

type ipHeader struct {
	pkt []byte
}

func (o *ipHeader) UpdateLength() {
	//printSlice(o.pkt)
	binary.BigEndian.PutUint16(o.pkt[2:4], 0x1122)
}

type ipHeader2 []byte

func (o ipHeader2) UpdateLength() {
	binary.BigEndian.PutUint16(o[2:4], 0x1122)
}

func testPkt1() {
	b := []byte{0x01, 0x02, 0x03, 0x04,
		0x11, 0x12, 0x13, 0x14,
		0x21, 0x22, 0x23, 0x24,
		0x31, 0x32, 0x33, 0x34}
	printSlice(b)
	fmt.Printf("1-%s", hex.Dump(b))
	fmt.Printf("1-%s", hex.Dump(b[2:4]))
	binary.BigEndian.PutUint16(b[2:], 0x0000)
	fmt.Printf("2-%s", hex.Dump(b))
	//p := ipHeader{pkt: b[0:]}
	//p.UpdateLength()
	p1 := ipHeader2(b)
	p1.UpdateLength()
	fmt.Printf("3-%s", hex.Dump(b))

}

func printSlice(s []byte) {
	fmt.Printf("len=%d cap=%d %+v\n", len(s), cap(s), s)
}

func testpcapWrite3() {
	fmt.Printf("hey this is an example \n")
}

func main() {
	testpcapWrite3()
	//testpcapWrite2()
	//testPkt1()
	//testSlice()
	//testMemory1()
	//testMemory2()
	//testpcapWrite()
	//testMpool2()
	//testStats()
	return
	var data *[]byte
	d := make([]byte, 10)
	data = &d
	fmt.Println(*data)
	(*data)[0] = 1
	fmt.Println(*data)

	//b := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	//fmt.Println(b)
	//fmt.Println(b[0:1])

	return
	rand.Seed(time.Now().UnixNano())
	rpc.RcpCtx.Create(4510)
	rpc.RcpCtx.StartRxThread()

	for {
		select {
		case req := <-rpc.RcpCtx.GetC():
			rpc.RcpCtx.HandleReqToChan(req)
		}
	}

	rpc.RcpCtx.Delete()
	return
}
