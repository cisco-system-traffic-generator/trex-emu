package main

import (
	"emu/rpc"
	"math/rand"
	"time"
)

func main() {
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
