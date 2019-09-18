package main

import (
	"emu/rpc"
	"encoding/hex"
	"fmt"
	"math/rand"
	"time"
)

type pkt []byte

func newPktSize(size uint16) pkt {
	var mbuf pkt
	mbuf = make(pkt, size)
	return mbuf
}

func freePkt() {

}

func test1() {
	size := 1
	for i := 0; i <= size; i++ {
		mbuf := newPktSize(128)
		mbuf[0] = 7
		fmt.Printf("%d-%s", len(mbuf), hex.Dump(mbuf))

	}
}

func main() {
	test1()
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
