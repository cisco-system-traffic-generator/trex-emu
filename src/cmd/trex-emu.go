// Copyright (c) 2020 Cisco Systems and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// that can be found in the LICENSE file in the root of the source
// tree.
// August 2021 Eolo S.p.A. and Altran Italia S.p.A.
// - added Point to Point reference to lines 26 and 44
package main

import (
	"emu/core"
	"emu/version"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/akamensky/argparse"

	"emu/plugins/appsim"
	"emu/plugins/arp"
	"emu/plugins/cdp"
	dhcp "emu/plugins/dhcpv4"
	dhcpsrv "emu/plugins/dhcpv4srv"
	"emu/plugins/dhcpv6"
	"emu/plugins/dns"
	"emu/plugins/dot1x"
	"emu/plugins/icmp"
	"emu/plugins/igmp"
	"emu/plugins/ipfix"
	"emu/plugins/ipv6"
	"emu/plugins/lldp"
	"emu/plugins/mdns"
	ppp "emu/plugins/point2point"
	"emu/plugins/tdl"
	"emu/plugins/transport"
	"emu/plugins/transport_example"
)

const (
	VERSION = "2.92"
)

func RegisterPlugins(tctx *core.CThreadCtx) {
	// These are ordered alphabetically, just like in the imports.
	appsim.Register(tctx)
	arp.Register(tctx)
	cdp.Register(tctx)
	dhcp.Register(tctx)
	dhcpsrv.Register(tctx)
	dhcpv6.Register(tctx)
	dns.Register(tctx)
	dot1x.Register(tctx)
	icmp.Register(tctx)
	igmp.Register(tctx)
	ipfix.Register(tctx)
	ipv6.Register(tctx)
	lldp.Register(tctx)
	mdns.Register(tctx)
	tdl.Register(tctx)
	ppp.Register(tctx)
	transport.Register(tctx)
	transport_example.Register(tctx)
}

type MainArgs struct {
	rpcPort     *int    // RPC port. Port to which the client connects to
	vethPort    *int    // Veth Port for EMU. Port to which TRex Server connects to.
	dummyVeth   *bool   // Run Emu on dummy veth mode.
	zmqServer   *string // IPv4 for the zmqServer. Defaults to local.
	capture     *bool   // capture traffic, rpc, counters and dump them in a json file
	captureJson *string // filename for the capture
	monitor     *bool   // monitor traffic in K12 mode and dump in pcapFile
	monitorFile *string // filename for the monitored traffic to be dumped
	verbose     *bool   // verbose mode, will print details
	version     *bool   // print version of EMU and exit
	emuTCPoZMQ  *bool   // use TCP over ZMQ instead of the classic IPC to connect with TRex.
	kernelMode  *bool   // Run Emu in kernel mode
}

func printVersion() {
	fmt.Println()
	fmt.Println("Copyright (c) 2020 Cisco Systems, Inc. and/or its affiliates.")
	fmt.Println()
	fmt.Println("Licensed under the Apache License, Version 2.0 (the 'License').")
	fmt.Println("You may not use this file except in compliance with the License.")
	fmt.Println()
	fmt.Println("The license can be found in the LICENSE file in the root of the source.")
	fmt.Println()
	fmt.Println("Unless required by applicable law or agreed to in writing, software")
	fmt.Println("distributed under the License is distributed on an \"AS IS\" BASIS,")
	fmt.Println("WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.")
	fmt.Println("See the License for the specific language governing permissions and")
	fmt.Println("limitations under the License.")
	fmt.Println()
	fmt.Printf("TRex-EMU Version : %s \n", VERSION)
	fmt.Printf("User             : %s \n", version.User)
	fmt.Printf("Date             : %s \n", version.Date)
	fmt.Printf("Git SHA          : %s \n", version.GitSha)
	fmt.Println()
}

func parseMainArgs() *MainArgs {
	var args MainArgs
	parser := argparse.NewParser("Emu Server", "Emu server emulates clients and namespaces")

	args.rpcPort = parser.Int("p", "rpc port", &argparse.Options{Default: 4510, Help: "RPC Port for server"})
	args.vethPort = parser.Int("l", "veth zmq port", &argparse.Options{Default: 4511, Help: "Veth Port for server"})
	args.dummyVeth = parser.Flag("d", "dummy-veth", &argparse.Options{Default: false, Help: "Run server with a dummy veth, all packets to rx will be dropped"})
	args.zmqServer = parser.String("S", "zmq-server", &argparse.Options{Default: "127.0.0.1", Help: "ZMQ server IP"})
	args.capture = parser.Flag("c", "capture", &argparse.Options{Default: false, Help: "Run server in capture mode"})
	args.captureJson = parser.String("C", "capture-json", &argparse.Options{Default: "capture.json", Help: "Path to save the JSON with capture details"})
	args.monitor = parser.Flag("m", "monitor", &argparse.Options{Default: false, Help: "Run server in K12 monitor mode"})
	args.monitorFile = parser.String("M", "monitor-pcap", &argparse.Options{Default: "stdout", Help: "Path to save monitored traffic (PCAP)"})
	args.verbose = parser.Flag("v", "verbose", &argparse.Options{Default: false, Help: "Run server in verbose mode"})
	args.version = parser.Flag("V", "version", &argparse.Options{Default: false, Help: "Show TRex-Emu version"})
	args.emuTCPoZMQ = parser.Flag("", "emu-zmq-tcp", &argparse.Options{Default: false, Help: "Run TCP over ZMQ. Default is IPC"})
	args.kernelMode = parser.Flag("k", "kernel-mode", &argparse.Options{Default: false, Help: "Run server in kernel mode"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	return &args
}

func RunCoreZmq(args *MainArgs) {

	var zmqVeth core.VethIFZmq
	var dummyVeth bool
	var simrx core.VethIFSim

	if *args.version {
		printVersion()
		os.Exit(0)
	}

	rpcPort := uint16(*args.rpcPort)
	if *args.emuTCPoZMQ {
		fmt.Printf("Run ZMQ server on [RPC:%d, RX: TCP:%d, TX: TCP:%d]\n", rpcPort, *args.vethPort, *args.vethPort+1)
	} else {
		fmt.Printf("Run ZMQ server on [RPC:%d, RX: IPC, TX:IPC]\n", rpcPort)
	}

	rand.Seed(time.Now().UnixNano())

	dummyVeth = *args.dummyVeth || *args.kernelMode

	if dummyVeth {
		var simVeth core.VethSink
		simrx = &simVeth
	}

	tctx := core.NewThreadCtx(0, rpcPort, dummyVeth, &simrx)
	tctx.SetVerbose(*args.verbose)
	tctx.SetKernelMode(*args.kernelMode)

	if !dummyVeth {
		zmqVeth.Create(tctx, uint16(*args.vethPort), *args.zmqServer, *args.emuTCPoZMQ, false)
		zmqVeth.StartRxThread()
		tctx.SetZmqVeth(&zmqVeth)
	}

	RegisterPlugins(tctx)

	tctx.SetRpcParams(*args.verbose, *args.capture)
	var monitorFile *os.File
	var err error
	if *args.monitorFile == "stdout" {
		monitorFile = os.Stdout
	} else {
		monitorFile, err = os.Create(*args.monitorFile)
		if err != nil {
			log.Fatal(err)
		}
		defer monitorFile.Close()
	}
	tctx.Veth.SetDebug(*args.monitor, monitorFile, *args.capture)
	tctx.StartRxThread()
	defer tctx.Delete()

	tctx.MainLoop()

	if *args.capture {
		tctx.SimRecordExport(*args.captureJson)
	}
}

func main() {
	RunCoreZmq(parseMainArgs())
}
