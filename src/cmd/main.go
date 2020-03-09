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
	"emu/plugins/icmp"
	"emu/plugins/igmp"
	"emu/plugins/ipv6"
)

func RegisterPlugins(tctx *core.CThreadCtx) {
	arp.Register(tctx)
	icmp.Register(tctx)
	igmp.Register(tctx)
	ipv6.Register(tctx)
	dhcp.Register(tctx)
	dhcpv6.Register(tctx)
}

type MainArgs struct {
	port      int
	verbose   bool
	sim       bool
	capture   bool
	monitor   bool
	time      time.Duration
	file      string
	dummyVeth bool
	vethPort  int
}

func parseMainArgs() *MainArgs {
	parser := argparse.NewParser("Emu Server", "Emu server emulates clients and namespaces")

	portArg := parser.Int("p", "rpc port", &argparse.Options{Default: 4510, Help: "RPC Port for server"})
	vethPortArg := parser.Int("l", "veth zmq port", &argparse.Options{Default: 4511, Help: "Veth Port for server"})
	verboseArg := parser.Flag("v", "verbose", &argparse.Options{Default: false, Help: "Run server in verbose mode"})
	simArg := parser.Flag("s", "simulator", &argparse.Options{Default: false, Help: "Run server in simulator mode"})
	captureArg := parser.Flag("c", "capture", &argparse.Options{Default: false, Help: "Run server in capture mode"})
	monitorArg := parser.Flag("m", "monitor", &argparse.Options{Default: false, Help: "Run server in K12 monitor mode"})
	timeArg := parser.Int("t", "time", &argparse.Options{Default: 10, Help: "Time of the simulation in sec"})
	fileArg := parser.String("f", "file", &argparse.Options{Default: "emu_file", Help: "Path to save the pcap file"})
	dummyVethArg := parser.Flag("d", "dummy-veth", &argparse.Options{Default: false, Help: "Run server with a dummy veth, all packets to rx will be dropped"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	durInSec := time.Duration(*timeArg) * time.Second
	return &MainArgs{port: *portArg, verbose: *verboseArg, sim: *simArg, capture: *captureArg,
		monitor: *monitorArg, time: durInSec, file: *fileArg, dummyVeth: *dummyVethArg, vethPort: *vethPortArg}
}

func RunCoreZmq(args *MainArgs) {

	var zmqVeth core.VethIFZmq

	port := uint16(args.port)
	fmt.Printf("run zmq server on [%d:rx:%d:tx:%d] \n", port, args.vethPort, args.vethPort+1)
	rand.Seed(time.Now().UnixNano())

	var simrx core.VethIFSim
	if args.dummyVeth {
		var simVeth core.VethSink
		simrx = &simVeth
	}

	tctx := core.NewThreadCtx(0, port, args.sim, &simrx)

	if !args.sim {
		zmqVeth.Create(tctx, uint16(args.vethPort))
		zmqVeth.StartRxThread()
		tctx.SetZmqVeth(&zmqVeth)
	}

	RegisterPlugins(tctx)

	tctx.SetVerbose(args.verbose)
	tctx.Veth.SetDebug(args.monitor, args.capture)
	tctx.StartRxThread()
	defer tctx.Delete()

	if !args.sim {
		tctx.MainLoop()
	} else {
		tctx.MainLoopSim(args.time)
	}
	if args.capture {
		tctx.SimRecordExport(args.file)
	}
}

func main() {
	RunCoreZmq(parseMainArgs())
}
