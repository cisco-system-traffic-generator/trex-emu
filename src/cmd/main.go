package main

import (
	"bytes"
	"emu/rpc"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

func testpcapWrite() {
	fmt.Println("hey")
	data := []byte{1, 2, 3, 4}
	ts := time.Unix(0, 0)
	for _, test := range []gopacket.CaptureInfo{
		gopacket.CaptureInfo{
			Timestamp:     ts,
			Length:        5,
			CaptureLength: 5,
		},
		gopacket.CaptureInfo{
			Timestamp:     ts,
			Length:        3,
			CaptureLength: 4,
		},
	} {
		var buf bytes.Buffer
		w := pcapgo.NewWriter(&buf)
		if err := w.WritePacket(test, data); err == nil {
		}
	}
}

func testMemory7() []byte {
	var b [16]byte
	var c = b[:0]
	c = append(c, []byte("1234")...)
	c = append(c, []byte("1234")...)
	c = append(c, []byte("1234")...)
	c = append(c, []byte("1234")...)
	//c = append(c, []byte{1, 2, 3, 4})
	//c = append(c, []byte{1, 2, 3, 4})
	//	c = append(c, []byte{1, 2, 3, 4})
	return c
}

func testMemory(c []byte) {

	c = append(c, []byte("1234")...)
	c = append(c, []byte("1234")...)
	c = append(c, []byte("1234")...)
	c = append(c, []byte("1234")...)
}

func testMemory1() int {
	var b [16]byte
	testMemory(b[:0])
	var sum int
	for _, g := range b {
		sum += int(g)
	}
	return sum

}

func testMemory2() (int, []byte) {
	var b []byte
	b = make([]byte, 10024)
	testMemory(b[:1000])
	var sum int
	for _, g := range b {
		sum += int(g)
	}
	return sum, b

}

func main() {
	testMemory1()
	testMemory2()
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
