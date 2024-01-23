// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.
package main

import (
	"emu/core"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"github.com/songgao/water"
)

// better to use readv/writev for batch of packets. this will accelerate the write and read to/from tap

const MAX_PKT_SIZE = 10 * 1024
const PKT_RING = 3

// create 3 channel to get the packet
// save MAC->IP map
// filter the packet back

const (
	PROXY_VERSION = "0.1"
)

type MainArgs struct {
	port       *int
	vethPort   *int
	verbose    *bool
	monitor    *bool
	version    *bool
	emuTCPoZMQ *bool   // use TCP over ZMQ instead of the classic IPC
	tap        *string // ethernet
}

func parseMainArgs() *MainArgs {
	var args MainArgs
	parser := argparse.NewParser("EMU Proxy Server", "Emu Proxy server proxy zmq to linux raw socket")

	args.vethPort = parser.Int("l", "veth zmq port", &argparse.Options{Default: 4511, Help: "Veth Port for server"})
	args.verbose = parser.Flag("v", "verbose", &argparse.Options{Default: false, Help: "Run server in verbose mode"})
	args.monitor = parser.Flag("m", "monitor", &argparse.Options{Default: false, Help: "Run server in K12 monitor mode"})
	args.version = parser.Flag("V", "version", &argparse.Options{Default: false, Help: "Show TRex-EMU proxy version"})
	args.emuTCPoZMQ = parser.Flag("", "emu-zmq-tcp", &argparse.Options{Default: false, Help: "Run TCP over ZMQ. Default is IPC"})
	args.tap = parser.String("i", "tap", &argparse.Options{Default: "tap0", Help: "Tap interface name e.g. tap0"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	return &args
}

type SocketIF interface {
	// start a thread and waits for raw packet, send them to GetC()
	StartRxThread()
	GetC() chan []byte
	Send(m *core.Mbuf)
}

type Ipv4ToMACTbl map[core.Ipv4Key]core.MACKey

type CZmqProxy struct {
	tctx      *core.CThreadCtx
	zmqVeth   core.VethIFZmq
	rawSocket SocketIF
}

type SocketRawIF struct {
	proxy *CZmqProxy
	tctx  *core.CThreadCtx
	tapif *water.Interface

	data [PKT_RING][]byte
	cn   chan []byte
	ring uint32
}

func (o *SocketRawIF) Create(tctx *core.CThreadCtx, tapname string) {
	var err error
	o.tctx = tctx
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Persist = true
	config.Name = tapname

	o.tapif, err = water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < PKT_RING; i++ {
		o.data[i] = make([]byte, MAX_PKT_SIZE)
	}
	o.ring = 0

	o.cn = make(chan []byte)
}

// thread
func (o *SocketRawIF) rxThread() {

	ring := 0
	for {
		cnt, err := o.tapif.Read(o.data[ring])
		if err != nil {
			fmt.Printf(" ERROR %s \n", err)
			time.Sleep(10 * time.Millisecond)
		} else {
			o.cn <- o.data[ring][:cnt]
			ring++
			if ring == PKT_RING {
				ring = 0
			}
		}
	}
}

func (o *SocketRawIF) StartRxThread() {
	go o.rxThread()
}

func (o *SocketRawIF) GetC() chan []byte {
	return o.cn
}

func (o *SocketRawIF) Send(m *core.Mbuf) {

	p := m.GetData()

	if len(p) > (14) {
		n, err := o.tapif.Write(p)
		if err != nil {
			fmt.Printf("tap Write error %v : %v\n", err, n)
		}
	}
	m.FreeMbuf()
}

func (o *CZmqProxy) Create() {
}

// rx from zmq -> send to raw socket
func (o *CZmqProxy) HandleRxPacket(m *core.Mbuf) {
	o.rawSocket.Send(m)
}

// raw_socket packet -> zmq send
func (o *CZmqProxy) OnRxPkt(b []byte) {
	if len(b) < 20 {
		return
	}

	m := o.tctx.MPool.Alloc(uint16(len(b)))
	m.SetVPort(0)
	m.Append(b)

	o.zmqVeth.Send(m)
}

func (o *CZmqProxy) MainLoop() {

	for {
		select {
		case pkt := <-o.rawSocket.GetC(): // raw socket rx -> send to veth
			o.OnRxPkt(pkt)
		case <-o.tctx.GetTimerCtx().GetC(): // timer flush
			o.tctx.HandleMainTimerTicks()
		case msg := <-o.tctx.Veth.GetC(): // zmq -> raw_socket
			o.tctx.Veth.OnRxStream(msg) // call  HandleRxPacket
		}
		o.tctx.Veth.FlushTx()
	}
	o.tctx.Veth.SimulatorCleanup()
	o.tctx.MPool.ClearCache()
}

func RunCoreZmq(args *MainArgs) {
	var proxy CZmqProxy
	var socket SocketRawIF
	fmt.Printf("EMU proxy version is %s running on tap:%v \n", PROXY_VERSION, *args.tap)
	if *args.version {
		os.Exit(0)
	}

	if *args.emuTCPoZMQ {
		fmt.Printf("Run ZMQ server on [RX: TCP:%d, TX: TCP:%d]\n", *args.vethPort+1, *args.vethPort)
	} else {
		fmt.Printf("Run ZMQ server on [RPC:%d, RX: IPC, TX:IPC]\n", 0)
	}

	rand.Seed(time.Now().UnixNano())

	tctx := core.NewThreadCtxProxy()
	proxy.Create()
	proxy.tctx = tctx

	// mode is proxy, server
	// proxy rx <-> emu tx (port+1)
	// proxy tx <-> emu rx (port)
	proxy.zmqVeth.Create(tctx, uint16(*args.vethPort), "*", *args.emuTCPoZMQ, true)
	proxy.zmqVeth.StartRxThread()
	proxy.zmqVeth.SetCb(&proxy) // set callback

	socket.Create(tctx, *args.tap)
	socket.proxy = &proxy
	proxy.rawSocket = &socket
	proxy.rawSocket.StartRxThread()

	tctx.SetZmqVeth(&proxy.zmqVeth)
	tctx.Veth.SetDebug(*args.monitor, os.Stdout, false)

	proxy.MainLoop()
}

func main() {
	RunCoreZmq(parseMainArgs())
}
