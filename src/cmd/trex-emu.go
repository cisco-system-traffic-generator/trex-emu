// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.
package main

import (
	"emu/core"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/akamensky/argparse"

	"emu/plugins/arp"
	dhcp "emu/plugins/dhcpv4"
	"emu/plugins/dhcpv6"
	"emu/plugins/dot1x"
	"emu/plugins/icmp"
	"emu/plugins/igmp"
	"emu/plugins/ipfix"
	"emu/plugins/ipv6"
)

const (
	VERSION = "0.1"
)

func RegisterPlugins(tctx *core.CThreadCtx) {
	arp.Register(tctx)
	icmp.Register(tctx)
	igmp.Register(tctx)
	ipv6.Register(tctx)
	dhcp.Register(tctx)
	dhcpv6.Register(tctx)
	dot1x.Register(tctx)
	ipfix.Register(tctx)
}

type MainArgs struct {
	port       *int
	verbose    *bool
	sim        *bool
	capture    *bool
	monitor    *bool
	time       *int
	file       *string
	dummyVeth  *bool
	vethPort   *int
	zmqServer  *string
	version    *bool
	duration   time.Duration
	emuTCPoZMQ *bool // use TCP over ZMQ instead of the classic IPC
}

func parseMainArgs() *MainArgs {
	var args MainArgs
	parser := argparse.NewParser("Emu Server", "Emu server emulates clients and namespaces")

	args.port = parser.Int("p", "rpc port", &argparse.Options{Default: 4510, Help: "RPC Port for server"})
	args.vethPort = parser.Int("l", "veth zmq port", &argparse.Options{Default: 4511, Help: "Veth Port for server"})
	args.verbose = parser.Flag("v", "verbose", &argparse.Options{Default: false, Help: "Run server in verbose mode"})
	args.sim = parser.Flag("s", "simulator", &argparse.Options{Default: false, Help: "Run server in simulator mode"})
	args.zmqServer = parser.String("S", "zmq-server", &argparse.Options{Default: "127.0.0.1", Help: "zmq server ip"})
	args.capture = parser.Flag("c", "capture", &argparse.Options{Default: false, Help: "Run server in capture mode"})
	args.monitor = parser.Flag("m", "monitor", &argparse.Options{Default: false, Help: "Run server in K12 monitor mode"})
	args.time = parser.Int("t", "time", &argparse.Options{Default: 10, Help: "Time of the simulation in sec"})
	args.file = parser.String("f", "file", &argparse.Options{Default: "emu_file", Help: "Path to save the pcap file"})
	args.dummyVeth = parser.Flag("d", "dummy-veth", &argparse.Options{Default: false, Help: "Run server with a dummy veth, all packets to rx will be dropped"})
	args.version = parser.Flag("V", "version", &argparse.Options{Default: false, Help: "show trex-emu version"})
	args.emuTCPoZMQ = parser.Flag("", "emu-zmq-tcp", &argparse.Options{Default: false, Help: "Run TCP over ZMQ. Default is IPC"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}
	args.duration = time.Duration(*args.time) * time.Second

	return &args
}

func RunCoreZmq(args *MainArgs) {

	var zmqVeth core.VethIFZmq

	if *args.version {
		fmt.Printf("tre-emu version is %s \n", VERSION)
		os.Exit(0)
	}

	port := uint16(*args.port)
	if *args.emuTCPoZMQ {
		fmt.Printf("Run ZMQ server on [RPC:%d, RX: TCP:%d, TX: TCP:%d]\n", port, *args.vethPort, *args.vethPort+1)
	} else {
		fmt.Printf("Run ZMQ server on [RPC:%d, RX: IPC, TX:IPC]\n", port)
	}

	rand.Seed(time.Now().UnixNano())

	var simrx core.VethIFSim
	if *args.dummyVeth {
		var simVeth core.VethSink
		simrx = &simVeth
	}

	tctx := core.NewThreadCtx(0, port, *args.sim, &simrx)

	if !*args.sim {
		zmqVeth.Create(tctx, uint16(*args.vethPort), *args.zmqServer, *args.emuTCPoZMQ)
		zmqVeth.StartRxThread()
		tctx.SetZmqVeth(&zmqVeth)
	}

	RegisterPlugins(tctx)

	tctx.SetVerbose(*args.verbose)
	tctx.Veth.SetDebug(*args.monitor, *args.capture)
	tctx.StartRxThread()
	defer tctx.Delete()

	if !*args.sim {
		tctx.MainLoop()
	} else {
		tctx.MainLoopSim(args.duration)
	}
	if *args.capture {
		tctx.SimRecordExport(*args.file)
	}
}

func main() {
	RunCoreZmq(parseMainArgs())
}
