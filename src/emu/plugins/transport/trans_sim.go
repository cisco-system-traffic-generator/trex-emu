// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.

package transport

import (
	"bytes"
	"emu/core"
	"fmt"
	"math/rand"
	"time"
)

type simContext struct {
	ctx    *transportCtx
	socket *TcpSocket
	Client *core.CClient
	Ns     *core.CNSCtx
	Tctx   *core.CThreadCtx
	sim    *transportSim
}

func newSimCtx(app iSockeApp, c *core.CClient, server bool, ioctl *map[string]interface{}) *simContext {
	o := new(simContext)
	o.Client = c
	o.Ns = c.Ns
	o.Tctx = c.Ns.ThreadCtx
	o.ctx = NewCtx(c)
	o.socket = new(TcpSocket)
	o.socket.init(c, o.ctx)
	//o.sim = sim
	s := o.socket
	if server {
		s.setTupleIpv4(core.Ipv4Key{48, 0, 0, 1},
			core.Ipv4Key{16, 0, 0, 1},
			80,
			1025)
	} else {
		s.setTupleIpv4(core.Ipv4Key{16, 0, 0, 1},
			core.Ipv4Key{48, 0, 0, 1},
			1025,
			80)
	}
	s.cb = app.getCb()
	app.setSocket(s)
	s.initphase2()

	if ioctl != nil {
		s.SetIoctl(*ioctl)
	}

	if server {
		copy(s.pktTemplate[0:6], []byte{0, 0, 1, 0, 0, 1})
		s.Listen()
	} else {
		copy(s.pktTemplate[0:6], []byte{0, 0, 1, 0, 0, 2})
		s.Connect()
	}
	o.ctx.cdbv.Dump()
	return o
}

type iSockeApp interface {
	setSocket(socket *TcpSocket)
	start()
	stop()
	onRemove()
	getCb() ISocketCb
}

type SocketAppTx1 struct {
	params  *transportSimParam
	socket  *TcpSocket
	state   int
	doClose int
	cnt     uint32
	timer   core.CHTimerObj
	timerw  *core.TimerCtx
}

func (o *SocketAppTx1) setSocket(socket *TcpSocket) {
	o.socket = socket
}

func (o *SocketAppTx1) getCb() ISocketCb {
	return o
}

func (o *SocketAppTx1) onRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *SocketAppTx1) sendChunk() {

	var csize int
	if o.params.debug {
		fmt.Printf("sendChunk() \n")
	}

	if o.params.sendRandom == false {
		csize = int(o.params.chunkSize)
	} else {
		csize = rand.Intn(int(o.params.chunkSize-1)) + 1
	}

	if o.cnt+uint32(csize) > o.params.totalClientToServerSize {
		csize = int(o.params.totalClientToServerSize - o.cnt)
	}
	if csize == 0 {
		return
	}

	r := o.addBuffer(csize)

	if r {
		// start timer
		o.timerw.Start(&o.timer, time.Duration(o.timerw.MinTickMsec())*time.Millisecond)
		o.state = 2
	} else {
		// waits
		o.state = 1
	}

}

func (o *SocketAppTx1) stop() {
	o.state = 0
	o.onRemove()
}

func (o *SocketAppTx1) OnEvent(a, b interface{}) {
	if o.state == 2 {
		o.sendChunk()
	} else {
		panic(" state should be 2")
	}
}

func (o *SocketAppTx1) start() {
	o.timerw = o.socket.tctx.GetTimerCtx()
	o.timer.SetCB(o, nil, nil)
}

func (o *SocketAppTx1) addBuffer(size int) bool {
	if o.params.debug {
		fmt.Printf(" add buffer %v \n", size)
	}
	var b []byte
	b = make([]byte, size)
	for i := 0; i < size; i++ {
		b[i] = byte(o.cnt + uint32(i))
	}
	r, queued := o.socket.Write(b)
	if r != 0 {
		er := fmt.Sprintf(" Write return non zero %d", r)
		panic(er)
	}
	o.cnt += uint32(len(b))

	if o.cnt == o.params.totalClientToServerSize && o.params.closeByClient {
		if !o.params.CloseByRst {
			o.socket.Close()
		} else {
			o.socket.Shutdown()
		}
	}

	return queued
}

func (o *SocketAppTx1) OnRxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" clientRx %p %x  \n", o, event)
	}
	if (event & SocketEventConnected) > 0 {
		o.sendChunk() // start
	}

	if event&SocketRemoteDisconnect > 0 {
		// remote disconnected
		o.socket.Close()
	}

	if (event & SocketClosed) > 0 {
		err := o.socket.GetLastError()
		if err != SeOK {
			fmt.Printf("==> ERROR   %v \n", err.String())
		}
		o.socket = nil
	}

}

func (o *SocketAppTx1) OnRxData(d []byte) {
	if o.params.debug {
		fmt.Printf(" on data %v  \n", d)
	}

}

func (o *SocketAppTx1) OnTxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" clientTx %p %x  \n", o, event)
	}
	if event&SocketTxMore > 0 {
		if o.state == 1 {
			if o.params.debug {
				fmt.Printf(" eventTxMore ----- \n")
			}
			o.sendChunk() // continue
		}
	}
}

type SocketAppRx1 struct {
	params *transportSimParam
	socket *TcpSocket
	cnt    uint32
}

func (o *SocketAppRx1) setSocket(socket *TcpSocket) {
	o.socket = socket
}

func (o *SocketAppRx1) getCb() ISocketCb {
	return o
}

func (o *SocketAppRx1) start() {
}

func (o *SocketAppRx1) stop() {
}

func (o *SocketAppRx1) onRemove() {
}

func (o *SocketAppRx1) OnRxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" serverEvent-eventRx %p %x  \n", o, event)
	}

	if event&SocketRemoteDisconnect > 0 {
		// remote disconnected
		o.socket.Close()
	}
	if (event & SocketClosed) > 0 {
		o.socket = nil
	}

}

func (o *SocketAppRx1) OnRxData(d []byte) {
	if o.params.debug {
		fmt.Printf(" serverRx-on data %v  \n", d) // check the rx data in the server
	}
	for i := 0; i < len(d); i++ {
		if d[i] != byte(o.cnt+uint32(i)) {
			panic(" b[i] != byte(cnt+i) ")
		}
	}
	o.cnt += uint32(len(d))
	if o.cnt == o.params.totalClientToServerSize && o.params.closeByClient == false {
		o.socket.Close()
	}

}

func (o *SocketAppRx1) OnTxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" serverOnTx data %p %x  \n", o, event)
	}
}

///############################

type SocketAppC1 struct {
	params  *transportSimParam
	socket  *TcpSocket
	state   int
	doClose int
	cnt     uint32
	timer   core.CHTimerObj
	timerw  *core.TimerCtx
}

func (o *SocketAppC1) setSocket(socket *TcpSocket) {
	o.socket = socket
}

func (o *SocketAppC1) getCb() ISocketCb {
	return o
}

func (o *SocketAppC1) onRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *SocketAppC1) stop() {
	o.state = 0
	o.onRemove()
}

func (o *SocketAppC1) start() {
}

func (o *SocketAppC1) OnRxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" clientRx %p %x  \n", o, event)
	}
	if (event & SocketEventConnected) > 0 {
		// nothing to do
	}

	if event&SocketRemoteDisconnect > 0 {
		// remote disconnected
		o.socket.Close()
	}

	if (event & SocketClosed) > 0 {
		err := o.socket.GetLastError()
		if err != SeOK {
			panic(err.String())
		}
		o.socket = nil
	}
}

func (o *SocketAppC1) OnRxData(d []byte) {
	if o.params.debug {
		fmt.Printf(" on data %v  \n", d)
	}
	for i := 0; i < len(d); i++ {
		if d[i] != byte(o.cnt+uint32(i)) {
			panic(" b[i] != byte(cnt+i) ")
		}
	}
	o.cnt += uint32(len(d))
	if o.cnt == o.params.totalClientToServerSize && o.params.closeByClient == false {
		o.socket.Close()
	}
}

func (o *SocketAppC1) OnTxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" clientTx %p %x  \n", o, event)

	}

}

type SocketAppRR1 struct {
	params       *transportSimParam
	socket       *TcpSocket
	state        int
	waitResponse bool
	isClient     bool
	doClose      int
	cnt          uint32
	timer        core.CHTimerObj
	timerw       *core.TimerCtx
	request      []byte
	response     []byte
}

func (o *SocketAppRR1) setSocket(socket *TcpSocket) {
	o.socket = socket
}

func (o *SocketAppRR1) getCb() ISocketCb {
	return o
}

func (o *SocketAppRR1) onRemove() {
	if o.timer.IsRunning() {
		o.timerw.Stop(&o.timer)
	}
}

func (o *SocketAppRR1) stop() {
	o.state = 0
	o.onRemove()
}

func (o *SocketAppRR1) start() {
	o.request = []byte(`{"method" :"request"}`)
	o.response = []byte(`{"method" :"response"}`)
}

func (o *SocketAppRR1) SendRequest() {
	r, queued := o.socket.Write(o.request)
	if r != 0 {
		er := fmt.Sprintf(" Write return non zero %d", r)
		panic(er)
	}
	if queued {
		o.waitResponse = true
	} else {
		o.state = 1
	}
}

func (o *SocketAppRR1) SendResponse() {
	r, queued := o.socket.Write(o.response)
	if r != 0 {
		er := fmt.Sprintf(" Write return non zero %d", r)
		panic(er)
	}
	if queued == false {
		panic(" send response with queued ==false ")
	}
}

func (o *SocketAppRR1) OnRxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" clientRx %p %x  \n", o, event)
	}
	if (event & SocketEventConnected) > 0 {
		// nothing to do
		if o.isClient {
			o.SendRequest()
		}
	}

	if event&SocketRemoteDisconnect > 0 {
		// remote disconnected
		o.socket.Close()
	}

	if (event & SocketClosed) > 0 {
		o.socket = nil
	}

}

func (o *SocketAppRR1) OnRxData(d []byte) {
	if o.params.debug {
		fmt.Printf(" on data %v  \n", d)
	}
	if o.isClient {
		if len(d) > 0 {
			if o.waitResponse == false {
				panic(" got bytes before request ")
			} else {
				if bytes.Compare(d, o.response) != 0 {
					panic(" got wrong response ")
				}
			}
		}

	} else {
		// server
		if len(d) > 0 {
			if o.waitResponse == false {
				if bytes.Compare(o.request, d) != 0 {
					panic(" got wrong request ")
				} else {
					o.SendResponse()
					o.socket.Close()
				}
			} else {
				panic(" wrong server state ")
			}
		}
	}
}

func (o *SocketAppRR1) OnTxEvent(event SocketEventType) {
	if o.params.debug {
		fmt.Printf(" clientTx %p %x  \n", o, event)
	}
	if event&SocketTxMore > 0 {
		if o.isClient {
			if o.state == 1 {
				o.waitResponse = true
			}
		}
	}
}

//#############################

func newAppRx1(params *transportSimParam) iSockeApp {
	switch params.name {
	case "a":
		var s SocketAppRx1
		s.params = params
		return &s
	case "s_c":
		var s SocketAppTx1
		s.params = params
		return &s
	case "r_r":
		var s SocketAppRR1
		s.params = params
		return &s
	}
	return nil
}

func newAppTx1(params *transportSimParam) iSockeApp {
	switch params.name {
	case "a":
		var s SocketAppTx1
		s.params = params
		return &s
	case "s_c":
		var s SocketAppC1
		s.params = params
		return &s
	case "r_r":
		var s SocketAppRR1
		s.params = params
		s.isClient = true
		return &s
	}
	return nil
}

type transportSimParam struct {
	name                    string
	totalClientToServerSize uint32
	chunkSize               uint32
	sendRandom              bool
	closeByClient           bool
	closeForce              bool // force to close without flush the Tx queue
	CloseByRst              bool // the server will send the first request
	drop                    float32
	debug                   bool
	ioctlc                  *map[string]interface{}
	ioctls                  *map[string]interface{}
}

type transportSim struct {
	cnt       uint32
	param     *transportSimParam
	client    *simContext
	server    *simContext
	tctx      *core.CThreadCtx
	timer     core.CHTimerObj
	test      uint32
	clientApp iSockeApp
	serverApp iSockeApp
}

func newTransportSim(params *transportSimParam) *transportSim {
	o := new(transportSim)
	o.param = params
	var simrx core.VethIFSim
	simrx = o
	o.tctx = core.NewThreadCtx(0, 4510, true, &simrx)
	var key core.CTunnelKey
	key.Set(&core.CTunnelData{Vport: 1, Vlans: [2]uint32{0x81000001, 0x81000002}})
	ns := core.NewNSCtx(o.tctx, &key)
	o.tctx.AddNs(&key, ns)

	client := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 1},
		core.Ipv4Key{16, 0, 0, 1},
		core.Ipv6Key{},
		core.Ipv4Key{16, 0, 0, 2})
	client.ForceDGW = true
	client.Ipv4ForcedgMac = core.MACKey{0, 0, 1, 0, 0, 2}

	server := core.NewClient(ns, core.MACKey{0, 0, 1, 0, 0, 2},
		core.Ipv4Key{48, 0, 0, 1},
		core.Ipv6Key{},
		core.Ipv4Key{48, 0, 0, 2})
	server.ForceDGW = true
	server.Ipv4ForcedgMac = core.MACKey{0, 0, 1, 0, 0, 1}

	ns.AddClient(client)
	ns.AddClient(server)

	o.clientApp = newAppTx1(params)
	o.serverApp = newAppRx1(params)

	o.server = newSimCtx(o.serverApp, server, true, params.ioctls)
	o.client = newSimCtx(o.clientApp, client, false, params.ioctlc)

	o.timer.SetCB(o, nil, nil)

	o.clientApp.start()
	o.serverApp.start()
	return o
}

func (o *transportSim) OnEvent(a, b interface{}) {
}

// move packet from c->s and s->c
type pktEventTxRx struct {
	cnt          uint32
	sim          *transportSim
	m            *core.Mbuf
	timer        core.CHTimerObj
	sendToServer bool
}

func (o *pktEventTxRx) OnEvent(a, b interface{}) {

	var ps core.ParserPacketState
	ps.Tctx = o.sim.tctx
	ps.Tun = &o.sim.client.Ns.Key
	ps.M = o.m
	ps.L3 = 14 + 8
	ps.L4 = ps.L3 + 20
	do := o.m.GetData()[ps.L4+12]
	tcplen := (do >> 4) << 2
	ps.L7 = ps.L4 + uint16(tcplen)
	ps.L7Len = ps.M.DataLen() - ps.L7

	if (o.sim.param.drop > 0.0) && (rand.Float32() < o.sim.param.drop) {
		fmt.Printf(" drop pkt : %d, to_server: %v\n", o.cnt, o.sendToServer)
		o.m.FreeMbuf()
		return
	}

	if o.sendToServer {
		if o.sim.server.socket != nil {
			o.sim.server.socket.input(&ps)

		}
	} else {
		if o.sim.client.socket != nil {
			o.sim.client.socket.input(&ps)
		}
	}
}

func (o *transportSim) ProcessTxToRx(m *core.Mbuf) *core.Mbuf {
	o.cnt++
	if o.cnt == 2 {
		//fmt.Printf(" this is it ! \n")
	}
	e := new(pktEventTxRx)
	e.sim = o
	e.m = m
	e.cnt = o.cnt
	e.sendToServer = false
	if m.GetData()[5] == 2 { // dst MAC is 2
		e.sendToServer = true
	}
	e.timer.SetCB(e, nil, nil)
	o.tctx.GetTimerCtx().Start(&e.timer, time.Duration(500)*time.Millisecond) // delay in 5 msec
	return nil
}
